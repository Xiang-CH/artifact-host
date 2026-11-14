"""Exercise the real HTTP, CLI and MCP flows with a fixed public mount."""
import http.client
import json
import os
from unittest.mock import patch
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import test_e2e


class SubpathEndToEnd(test_e2e.EndToEnd):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {'PUBLIC_PATH': '/a'}):
            super().setUpClass()

    def test_password_redirect_cookie_and_resource_scope_under_mount(self):
        code, body, _ = self.request('POST', '/api/artifacts?name=report.md', b'# Mounted report', self.owner)
        self.assertEqual(code, 201)
        item = json.loads(body)
        path = urlsplit(item['url']).path
        self.assertTrue(path.startswith('/a/'), path)
        self.assertEqual(self.request('GET', path.removeprefix('/a'), base=self.public)[0], 404)
        with urlopen(Request(self.api+'/api/artifacts/'+item['id']+'/access',
                             json.dumps({'password': 'synthetic-mount-password'}).encode(),
                             {'Authorization': 'Bearer '+self.owner, 'Content-Type': 'application/json'})) as response:
            self.assertEqual(response.status, 200)
        connection = http.client.HTTPConnection('127.0.0.1', self.public_port)
        try:
            connection.request('POST', path, 'password=synthetic-mount-password',
                               {'Origin': self.public, 'Content-Type': 'application/x-www-form-urlencoded'})
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 303)
            self.assertEqual(response.getheader('Location'), path)
            cookies = [value for key, value in response.getheaders() if key.lower() == 'set-cookie']
            self.assertTrue(any('Path=/a/' in value for value in cookies))
            self.assertTrue(any('Path=/a/s/' in value for value in cookies))
            cookie = next(value.split(';')[0] for value in cookies if 'Max-Age=0' not in value)
            connection.request('GET', path, headers={'Cookie': cookie, 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate'})
            response = connection.getresponse()
            document = response.read().decode()
            self.assertEqual(response.status, 200)
            self.assertIn(self.public+'/a/_r/', document)
            self.assertIn(self.public+'/a/_r/', response.getheader('Content-Security-Policy'))
        finally:
            connection.close()
