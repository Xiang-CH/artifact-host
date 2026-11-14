"""Authenticated HTTP client for CLI and MCP. Never follow redirects with secrets."""
import io
import base64
from contextvars import ContextVar
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

REQUEST_TOKEN = ContextVar('artifact_request_token', default=None)

MAX_UPLOAD = 50 * 1024 * 1024

class ClientError(ValueError):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def endpoint_url(endpoint):
    parts = urllib.parse.urlsplit(endpoint)
    if (parts.scheme not in ('https', 'http') or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment or parts.path not in ('', '/')
            or (parts.scheme == 'http' and parts.hostname not in ('localhost', '127.0.0.1', '::1'))):
        raise ClientError('API must be an HTTPS origin or loopback HTTP origin')
    return endpoint.rstrip('/')

def api(method, path, data=None, endpoint=None, extra_headers=None):
    endpoint = endpoint_url(endpoint or os.environ.get('ARTIFACT_API', 'http://127.0.0.1:8791'))
    secret = REQUEST_TOKEN.get()
    if secret is None:
        secret = '' if os.environ.get('ARTIFACT_REQUIRE_REQUEST_TOKEN') == '1' else os.environ.get('ARTIFACT_TOKEN', '')
    if not secret or any(c.isspace() for c in secret):
        raise ClientError('ARTIFACT_TOKEN is required')
    request = urllib.request.Request(endpoint + path, data=data, method=method,
        headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/octet-stream', **(extra_headers or {})})
    # Explicitly disable ambient proxies, which could otherwise see loopback credentials.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=120) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise ClientError('API response too large; use pagination')
            return json.loads(body) if body else {'ok': True}
    except urllib.error.HTTPError as error:
        raise ClientError(f'Artifact API returned HTTP {error.code}') from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise ClientError('Artifact API request failed') from None

def upload(name, content, slug='', bundle=False, expires=None, endpoint=None, read_password=''):
    if len(content) > MAX_UPLOAD:
        raise ClientError('Upload exceeds client limit')
    query = {'name': name, 'slug': slug}
    if bundle:
        query['bundle'] = '1'
    if expires is not None:
        query['expires'] = str(expires)
    headers = {'X-Artifact-Read-Password': base64.b64encode(read_password.encode()).decode()} if read_password else None
    return api('POST', '/api/artifacts?' + urllib.parse.urlencode(query), content, endpoint, extra_headers=headers)

def read_upload(path):
    path = Path(path)
    if path.is_symlink():
        raise ClientError('Symlinks are not supported')
    if path.is_file():
        with path.open('rb') as source:
            content = source.read(MAX_UPLOAD + 1)
        if len(content) > MAX_UPLOAD:
            raise ClientError('Upload exceeds client limit')
        return content, False
    if not path.is_dir():
        raise ClientError('Upload path must be a file or directory')
    output = io.BytesIO()
    count = size = 0
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for file in path.rglob('*'):
            if file.is_symlink():
                raise ClientError('Symlinks are not supported')
            if file.is_dir():
                continue
            if not file.is_file():
                raise ClientError('Special files are not supported')
            count += 1
            size += file.stat().st_size
            if count > 2000 or size > MAX_UPLOAD:
                raise ClientError('Bundle exceeds client limit')
            archive.write(file, file.relative_to(path))
            if output.tell() > MAX_UPLOAD:
                raise ClientError('Bundle exceeds client limit')
    if output.tell() > MAX_UPLOAD:
        raise ClientError('Bundle exceeds client limit')
    return output.getvalue(), True
