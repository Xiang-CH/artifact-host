import base64
import time
import unittest
from unittest.mock import patch
import test_service
from artifact_host import storage
from artifact_host.app import public_app, private_app, PUBLIC
from artifact_host.rate_limit import RateLimit


class ReadAccess(unittest.TestCase):
    setUp = test_service.Service.setUp
    headers = test_service.Service.headers
    upload = test_service.Service.upload

    def protected(self):
        headers = self.headers()
        headers['X-Artifact-Read-Password'] = base64.b64encode('测试密码 long password'.encode()).decode()
        response = self.private.post('/api/artifacts?name=secret.txt', data=b'PRIVATE CONTENT', headers=headers)
        self.assertEqual(response.status_code, 201)
        item = response.json
        return item, '/s/' + item['id'] + '/' + item['slug'] + '/'

    def unlock(self, path, password='测试密码 long password', origin=PUBLIC):
        return self.public.post(path, data={'password': password}, headers={'Origin': origin})

    def change(self, item, password, secret=None):
        return self.private.post('/api/artifacts/' + item['id'] + '/access', json={'password': password}, headers=self.headers(secret))

    def test_default_public_and_password_bounds(self):
        item = self.upload('hello.txt', b'public').json
        self.assertEqual(self.public.get('/s/' + item['id'] + '/').data, b'public')
        for password in ('short', 'x' * 129, None):
            self.assertEqual(self.change(item, password).status_code, 400)
        self.assertEqual(self.change(item, 'valid password', self.other).status_code, 403)
        self.assertEqual(self.public.post('/s/' + item['id'] + '/', data={'password': 'x'}).status_code, 405)

    def test_unlock_rotation_public_and_no_secret_leaks(self):
        item, path = self.protected()
        response = self.public.get(path)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(b'PRIVATE CONTENT', response.data)
        self.assertIn("form-action 'self'", response.headers['Content-Security-Policy'])
        self.assertEqual(self.unlock(path, origin='https://evil.example').status_code, 403)
        self.assertEqual(self.unlock(path, 'wrong').status_code, 401)
        response = self.unlock(path)
        self.assertEqual(response.status_code, 303)
        self.assertIn('HttpOnly', response.headers['Set-Cookie'])
        self.assertIn('SameSite=None', response.headers['Set-Cookie'])
        self.assertIn('Secure', response.headers['Set-Cookie'])
        self.assertEqual(self.public.get(path).data, b'PRIVATE CONTENT')
        listing = self.private.get('/api/artifacts', headers=self.headers())
        self.assertTrue(listing.json[0]['password_protected'])
        self.assertNotIn(b'read_cookie_key', listing.data)
        self.assertNotIn(b'read_password_hash', listing.data)
        self.assertNotIn(b'long password', listing.data)
        self.assertEqual(self.change(item, 'changed password').status_code, 200)
        self.assertEqual(self.public.get(path).status_code, 401)
        self.assertEqual(self.unlock(path, 'changed password').status_code, 303)
        self.assertEqual(self.public.get(path).data, b'PRIVATE CONTENT')
        with patch('artifact_host.read_access.time.time', return_value=time.time() + 40 * 86400):
            self.assertEqual(self.public.get(path).status_code, 401)
        self.assertEqual(self.change(item, '').status_code, 200)
        self.assertEqual(self.public.get(path).data, b'PRIVATE CONTENT')

    def test_assets_legacy_cookie_tampering_revocation(self):
        item, path = self.protected()
        self.assertEqual(self.public.get(path + 'secret.txt').status_code, 401)
        self.assertEqual(self.unlock(path).status_code, 303)
        name = 'artifact_read_' + item['id']
        self.public.set_cookie(name, '999999999999.forged', domain='127.0.0.1')
        self.assertEqual(self.public.get(path).status_code, 401)
        self.assertEqual(self.unlock(path).status_code, 303)
        self.assertEqual(self.public.get(path + 'secret.txt').data, b'PRIVATE CONTENT')
        self.private.delete('/api/artifacts/' + item['id'], headers=self.headers())
        self.assertEqual(self.public.get(path).status_code, 404)

    def test_password_attempts_throttle_before_expensive_hash(self):
        _, path = self.protected()
        # Fresh client source to avoid dependence on other password tests.
        with patch('artifact_host.app.client_address', return_value='192.0.2.11'):
            for _ in range(5):
                self.assertEqual(self.unlock(path, 'wrong').status_code, 401)
            with patch('artifact_host.read_access.check_password', side_effect=AssertionError('must not hash')):
                response = self.unlock(path, 'wrong')
                self.assertEqual(response.status_code, 429)
                self.assertGreater(int(response.headers['Retry-After']), 0)
