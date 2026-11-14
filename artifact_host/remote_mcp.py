"""Authenticated, stateless Streamable HTTP MCP gateway to the private API."""
import functools
import ipaddress
import logging
import os
import re
from urllib.parse import urlsplit

import anyio
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from artifact_host.client import REQUEST_TOKEN, endpoint_url
from artifact_host.mcp_server import upload_artifact, list_artifacts, revoke_artifact
from artifact_host.rate_limit import RateLimit, client_address


def threaded(function):
    """Keep slow HTTP API calls off the event loop; copy request context safely."""
    @functools.wraps(function)
    async def invoke(*args, **kwargs):
        return await anyio.to_thread.run_sync(functools.partial(function, *args, **kwargs))
    return invoke


class GatewayBoundary:
    def __init__(self, app, origin, backend, body_limit, active_limit):
        self.app = app
        self.origin = origin
        self.host = urlsplit(origin).netloc
        self.backend = backend
        self.body_limit = body_limit
        self.slots = anyio.Semaphore(active_limit)
        burst = int(os.environ.get('MCP_AUTH_BURST', 30))
        if not 1 <= burst <= 1000:
            raise ValueError('Invalid MCP authentication burst')
        self.attempts = RateLimit(burst, 1)  # Per source, 60/minute with a burst of 30.
        self.total_attempts = RateLimit(120, 5)
        self.trust_proxy = os.environ.get('ARTIFACT_TRUST_PROXY_IP') == '1'

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        async def reject(status, message, retry=None):
            headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
            if status == 405:
                headers['Allow'] = 'POST'
            if status == 401:
                headers['WWW-Authenticate'] = 'Bearer realm="artifact-host"'
            if status == 429:
                headers['Retry-After'] = str(retry or 1)
            await JSONResponse({'error': message}, status_code=status, headers=headers)(scope, receive, send)

        headers = Headers(scope=scope)
        try:
            peer = scope.get('client') or ('', 0)
            private_peer = ipaddress.ip_address(peer[0]).is_loopback
        except ValueError:
            private_peer = False
        if not private_peer:
            return await reject(403, 'Private proxy required')
        if headers.getlist('host') != [self.host]:
            return await reject(421, 'Untrusted Host')
        origins = headers.getlist('origin')
        if origins and origins != [self.origin]:
            return await reject(403, 'Untrusted Origin')
        if scope.get('query_string'):
            return await reject(400, 'Query credentials are not accepted')
        if scope['path'] == '/health' and scope['method'] == 'GET':
            return await JSONResponse({'ok': True}, headers={'Cache-Control': 'no-store'})(scope, receive, send)
        if scope['path'] != '/mcp':
            return await reject(404, 'Not found')
        source = client_address(peer[0], headers, self.trust_proxy)
        retry = max(self.total_attempts.check('all'), self.attempts.check(source))
        if retry:
            return await reject(429, 'Too many authentication attempts', retry)
        authorization = headers.getlist('authorization')
        if len(authorization) != 1 or not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}', authorization[0]):
            return await reject(401, 'Active bearer token required')
        secret = authorization[0][7:]
        try:
            self.slots.acquire_nowait()
        except anyio.WouldBlock:
            return await reject(429, 'Gateway busy')
        context = REQUEST_TOKEN.set(secret)
        started = False

        async def safe_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
                message['headers'] = [(name, value) for name, value in message.get('headers', [])
                                      if name.lower() not in (b'cache-control', b'x-content-type-options')] + [
                    (b'cache-control', b'no-store, no-transform'), (b'x-content-type-options', b'nosniff')]
            await send(message)

        try:
            with anyio.fail_after(120):
                try:
                    # No cache: token revocation applies to the very next request,
                    # including initialization and tool discovery.
                    async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
                        identity = await client.get(self.backend + '/api/identity',
                            headers={'Authorization': 'Bearer ' + secret}, follow_redirects=False)
                except httpx.HTTPError:
                    return await reject(503, 'Private API unavailable')
                if identity.status_code == 401:
                    return await reject(401, 'Active bearer token required')
                if identity.status_code != 200:
                    return await reject(503, 'Private API unavailable')
                if scope['method'] != 'POST':
                    return await reject(405, 'Stateless MCP uses POST responses; no standalone event stream')
                length = headers.get('content-length')
                if length is not None:
                    try:
                        if int(length) < 0 or int(length) > self.body_limit:
                            return await reject(413, 'MCP request exceeds limit')
                    except ValueError:
                        return await reject(400, 'Invalid content length')
                body = bytearray()
                if scope['method'] == 'POST':
                    while True:
                        message = await receive()
                        if message['type'] == 'http.disconnect':
                            return
                        block = message.get('body', b'')
                        if len(body) + len(block) > self.body_limit:
                            raise BodyTooLarge
                        body.extend(block)
                        if not message.get('more_body', False):
                            break
                delivered = False

                async def buffered_receive():
                    nonlocal delivered
                    if not delivered and scope['method'] == 'POST':
                        delivered = True
                        return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                    return await receive()

                await self.app(scope, buffered_receive, safe_send)
        except BodyTooLarge:
            if not started:
                await reject(413, 'MCP request exceeds limit')
        except TimeoutError:
            if not started:
                await reject(504, 'MCP request timed out')
        finally:
            REQUEST_TOKEN.reset(context)
            self.slots.release()


class BodyTooLarge(Exception):
    pass


class SafeFormatter(logging.Formatter):
    def format(self, record):
        # Never log request URLs, bodies, headers or exception text.
        return f'{record.levelname} {record.name}'


def create_app():
    origin = endpoint_url(os.environ.get('MCP_ORIGIN', 'http://127.0.0.1:8793'))
    backend = endpoint_url(os.environ.get('ARTIFACT_API', 'http://127.0.0.1:8791'))
    os.environ['ARTIFACT_REQUIRE_REQUEST_TOKEN'] = '1'
    body_limit = int(os.environ.get('MCP_BODY_LIMIT', 8 * 1024**2))
    active_limit = int(os.environ.get('MCP_ACTIVE_LIMIT', 4))
    if not 1024 <= body_limit <= 72 * 1024**2 or not 1 <= active_limit <= 8:
        raise ValueError('Invalid MCP gateway limits')
    server = FastMCP('Artifact host', stateless_http=True, json_response=False,
        max_request_body_size=body_limit, log_level='ERROR',
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[urlsplit(origin).netloc], allowed_origins=[origin]))
    for function in (upload_artifact, list_artifacts, revoke_artifact):
        server.add_tool(threaded(function))
    return GatewayBoundary(server.streamable_http_app(), origin, backend, body_limit, active_limit)


def main():
    import uvicorn
    log_config = {
        'version': 1, 'disable_existing_loggers': False,
        'formatters': {'safe': {'()': SafeFormatter}},
        'handlers': {'safe': {'class': 'logging.StreamHandler', 'formatter': 'safe'}},
        'root': {'handlers': ['safe'], 'level': 'ERROR'},
        'loggers': {'uvicorn': {'handlers': ['safe'], 'level': 'INFO', 'propagate': False},
                    'uvicorn.error': {'level': 'INFO'}, 'uvicorn.access': {'level': 'CRITICAL'}},
    }
    uvicorn.run(create_app(), host='127.0.0.1', port=int(os.environ.get('MCP_PORT', 8793)),
                access_log=False, proxy_headers=False, timeout_keep_alive=5,
                limit_concurrency=16, log_config=log_config)


if __name__ == '__main__':
    main()
