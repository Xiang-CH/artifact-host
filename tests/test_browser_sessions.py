import time
import unittest
import test_service
from artifact_host import storage
class BrowserSessions(unittest.TestCase):
    setUp=test_service.Service.setUp
    headers=test_service.Service.headers
    upload=test_service.Service.upload
    def test_remember_logout_and_csrf(self):
        ui={'X-Artifact-UI':'1','Origin':'http://localhost'}
        self.assertEqual(self.private.post('/api/session',headers=dict(ui,**self.headers(self.agent))).status_code,403)
        response=self.private.post('/api/session',headers=dict(ui,**self.headers(self.owner)))
        self.assertEqual(response.status_code,200)
        self.assertIn('HttpOnly',response.headers['Set-Cookie']);self.assertIn('SameSite=Strict',response.headers['Set-Cookie']);self.assertIn('Path=/api',response.headers['Set-Cookie'])
        self.assertEqual(self.private.get('/api/tokens',headers={'X-Artifact-UI':'1'}).status_code,200)
        self.assertEqual(self.private.get('/api/tokens').status_code,401)
        self.assertEqual(self.private.post('/api/tokens',headers={'X-Artifact-UI':'1'}).status_code,403)
        self.assertEqual(self.private.post('/api/tokens',headers=dict(ui,Origin='https://evil.example')).status_code,403)
        cookie=self.private.get_cookie('artifact_session',path='/api').value
        self.assertEqual(self.private.delete('/api/session',headers=ui).status_code,200)
        self.private.set_cookie('artifact_session',cookie,path='/api')
        self.assertEqual(self.private.get('/api/tokens',headers={'X-Artifact-UI':'1'}).status_code,401)
    def test_archive_filter_applied_before_pagination(self):
        active=self.upload('x',b'x').json
        expired=self.upload('y',b'y').json
        revoked=self.upload('z',b'z').json
        with storage.database() as c:c.execute('UPDATE artifacts SET expires=1 WHERE id=?',(expired['id'],))
        self.private.delete('/api/artifacts/'+revoked['id'],headers=self.headers())
        rows=self.private.get('/api/artifacts?category=active',headers=self.headers()).json
        self.assertEqual([r['id'] for r in rows],[active['id']])
        rows=self.private.get('/api/artifacts?category=archive',headers=self.headers()).json
        self.assertEqual({r['id'] for r in rows},{expired['id'],revoked['id']})
    def test_secure_cookie_expiry_and_owner_invalidation(self):
        import os
        from unittest.mock import patch
        from artifact_host.app import create_app
        with patch.dict(os.environ,{'PRIVATE_ORIGIN':'https://admin.example'}):client=create_app(True).test_client()
        ui={'X-Artifact-UI':'1','Origin':'https://admin.example'}
        response=client.post('/api/session',base_url='https://admin.example',headers=dict(ui,**self.headers(self.owner)))
        self.assertEqual(response.status_code,200);self.assertIn('Secure',response.headers['Set-Cookie'])
        self.assertEqual(client.get('/api/identity',base_url='https://admin.example',headers=ui).status_code,200)
        with storage.database() as c:c.execute('UPDATE browser_sessions SET expires=1')
        self.assertEqual(client.get('/api/identity',base_url='https://admin.example',headers=ui).status_code,401)
        self.assertEqual(client.post('/api/session',base_url='https://admin.example',headers=dict(ui,**self.headers(self.owner))).status_code,200)
        with storage.database() as c:c.execute('DELETE FROM tokens WHERE id=?',(self.owner_id,))
        self.assertEqual(client.get('/api/identity',base_url='https://admin.example',headers=ui).status_code,401)
