import os
import time
import unittest
from unittest.mock import patch
import test_service
from artifact_host import storage
from artifact_host.app import create_app

class ShortSlugs(unittest.TestCase):
    headers=test_service.Service.headers
    upload=test_service.Service.upload
    bundle=test_service.Service.bundle
    def setUp(self):
        test_service.Service.setUp(self)
        with patch.dict(os.environ,{'READABLE_URLS':'1'}):
            self.private=create_app(True).test_client()
            app=create_app(False);app.config['SERVER_NAME']='127.0.0.1'
            self.public=app.test_client()
    def get(self,path):
        response=self.public.get(path);response.get_data();response.close();return response
    def test_upload_and_relative_assets(self):
        archive=self.bundle([('index.html',b'<script src="app.js"></script>'),('app.js',b'window.ok=1')])
        result=self.upload(data=archive,extra='&bundle=1&slug=Architecture')
        self.assertEqual(result.status_code,201)
        item=result.json
        self.assertEqual(item['url'],'http://127.0.0.1:8792/architecture/')
        self.assertEqual(item['short_slug'],'architecture')
        for suffix in ('','app.js'):
            response=self.get('/architecture/'+suffix);self.assertEqual(response.status_code,200)
            self.assertIn('no-store',response.headers['Cache-Control'])
        self.assertEqual(self.get('/architecture').status_code,308)
        self.assertEqual(self.get('/s/'+item['id']+'/'+item['slug']+'/').status_code,200)
        self.assertEqual(self.get('/architecture/../state.db').status_code,404)
        listing=self.private.get('/api/artifacts',headers=self.headers()).json
        self.assertEqual(listing[0]['url'],item['url'])
        self.assertEqual(self.private.delete('/api/artifacts/'+item['id'],headers=self.headers()).status_code,204)
        self.assertEqual(self.get('/architecture/').status_code,404)
        self.assertEqual(self.get('/architecture/app.js').status_code,404)
        # Names stay reserved after deletion; links cannot later point at someone else's content.
        self.assertEqual(self.upload(extra='&slug=architecture',secret=self.other).status_code,409)
    def test_collision_defaults_and_atomic_cleanup(self):
        self.assertEqual(self.upload(extra='&slug=report').status_code,201)
        with storage.database() as c:before=c.execute('SELECT count(*) FROM artifacts').fetchone()[0]
        self.assertEqual(self.upload(extra='&slug=report',secret=self.other).status_code,409)
        with storage.database() as c:self.assertEqual(c.execute('SELECT count(*) FROM artifacts').fetchone()[0],before)
        self.assertFalse((storage.ROOT/'.staging').exists())
        self.assertEqual(self.upload('报告.txt',b'hello').json['short_slug'],'artifact')
        first=self.upload('notes.txt',b'a').json;second=self.upload('notes.txt',b'b').json
        self.assertEqual(first['short_slug'],'notes');self.assertEqual(second['short_slug'],'notes-2')
        for invalid in ('health','api','s','static','%2F%2F%2F'):
            self.assertEqual(self.upload(extra='&slug='+invalid).status_code,400)
    def test_alias_auth_ownership_idempotency_and_expiry(self):
        # Simulate an artifact created before the short-link migration.
        with patch.dict(os.environ,{'READABLE_URLS':'0'}):legacy=create_app(True).test_client()
        item=legacy.post('/api/artifacts?name=README.md',data=b'# Legacy',headers=self.headers()).json
        endpoint='/api/artifacts/'+item['id']+'/alias?slug=legacy-report'
        self.assertEqual(self.private.post(endpoint).status_code,401)
        self.assertEqual(self.private.post(endpoint,headers=self.headers(self.other)).status_code,403)
        result=self.private.post(endpoint,headers=self.headers());self.assertEqual(result.status_code,200)
        self.assertEqual(self.private.post(endpoint,headers=self.headers()).json,result.json)
        self.assertEqual(self.private.post(endpoint.replace('legacy-report','new-name'),headers=self.headers()).status_code,409)
        self.assertEqual(self.get('/legacy-report/').status_code,200)
        with storage.database() as c:c.execute('UPDATE artifacts SET expires=1 WHERE id=?',(item['id'],))
        self.assertEqual(self.get('/legacy-report/').status_code,404)
        self.assertEqual(self.private.post(endpoint,headers=self.headers()).status_code,404)
    def test_revoked_token_and_disabled_mode(self):
        item=self.upload(extra='&slug=token-test').json
        self.private.delete('/api/tokens/'+self.agent_id,headers=self.headers(self.owner))
        self.assertEqual(self.private.post('/api/artifacts/'+item['id']+'/alias?slug=token-test',headers=self.headers()).status_code,401)
        with patch.dict(os.environ,{'READABLE_URLS':'0'}):
            public=create_app(False);public.config['SERVER_NAME']='127.0.0.1'
            private=create_app(True)
        self.assertEqual(public.test_client().get('/token-test/').status_code,404)
        self.assertEqual(private.test_client().post('/api/artifacts/'+item['id']+'/alias?slug=token-test',headers=self.headers(self.owner)).status_code,404)
        listing=private.test_client().get('/api/artifacts',headers=self.headers(self.owner)).json
        self.assertIn('/s/',listing[0]['url'])
    def test_alias_admission_respects_budget(self):
        with patch.dict(os.environ,{'READABLE_URLS':'0'}):legacy=create_app(True).test_client()
        item=legacy.post('/api/artifacts?name=x',data=b'x',headers=self.headers()).json
        with patch.object(storage,'BUDGET',0):
            self.assertEqual(self.private.post('/api/artifacts/'+item['id']+'/alias?slug=quota-test',headers=self.headers()).status_code,413)
        self.assertEqual(self.get('/quota-test/').status_code,404)
    def test_short_alias_backup_restore(self):
        import tempfile
        from pathlib import Path
        from artifact_host.maintenance import backup, restore
        item=self.upload('backup.txt',b'Alias backup',extra='&slug=backup-report').json
        with tempfile.TemporaryDirectory() as temporary:
            snapshot=Path(temporary)/'snapshot';restored=Path(temporary)/'restored'
            backup(snapshot)
            self.private.delete('/api/artifacts/'+item['id'],headers=self.headers())
            self.assertEqual(self.get('/backup-report/').status_code,404)
            restore(snapshot,restored)
            with patch.object(storage,'ROOT',restored):
                response=self.get('/backup-report/')
                self.assertEqual(response.status_code,200);self.assertEqual(response.data,b'Alias backup')
