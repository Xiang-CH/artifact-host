import asyncio
import os
import unittest
from unittest.mock import patch
import httpx
from artifact_host.rate_limit import RateLimit, client_address
from artifact_host.remote_mcp import GatewayBoundary


class RateLimits(unittest.TestCase):
    def test_refill_bound_and_untrusted_forwarding(self):
        now = [0]
        limit = RateLimit(2, 1, maximum=2, clock=lambda: now[0])
        self.assertEqual([limit.check('a') for _ in range(3)], [0, 0, 1])
        now[0] = 1
        self.assertEqual(limit.check('a'), 0)
        limit.check('b');limit.check('c')
        self.assertEqual(len(limit.entries), 2)
        self.assertEqual(client_address('127.0.0.1', {'x-real-ip':'192.0.2.1'}), '127.0.0.1')
        self.assertEqual(client_address('127.0.0.1', {'x-real-ip':'192.0.2.1'}, True), '192.0.2.1')
        self.assertEqual(client_address('198.51.100.2', {'x-real-ip':'192.0.2.1'}, True), '198.51.100.2')

    def test_missing_and_rotating_tokens_throttled_before_backend(self):
        async def check():
            async def unreachable(*args):
                self.fail('Unauthenticated request reached MCP')
            with patch.dict(os.environ, {'MCP_AUTH_BURST':'2', 'ARTIFACT_TRUST_PROXY_IP':'0'}):
                gateway = GatewayBoundary(unreachable, 'http://localhost', 'http://127.0.0.1:1', 8192, 4)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway, client=('127.0.0.1',1)), base_url='http://localhost') as client:
                for _ in range(2):
                    self.assertEqual((await client.post('/mcp')).status_code, 401)
                for token in ('x'*43, 'y'*43):
                    result = await client.post('/mcp', headers={'Authorization':'Bearer '+token, 'X-Real-IP':'192.0.2.22'})
                    self.assertEqual(result.status_code, 429)
                    self.assertIn('Retry-After', result.headers)
                self.assertEqual((await client.get('/health')).status_code, 200)
        asyncio.run(check())
