import concurrent.futures
import fcntl
import io
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

os.environ['ARTIFACT_DATA'] = tempfile.mkdtemp(prefix='artifact-tests-')
from artifact_host import storage
from artifact_host.app import private_app, public_app, token, create_app
from artifact_host.rendering import MAX_MARKDOWN
public_app.config['SERVER_NAME'] = '127.0.0.1'

class Service(unittest.TestCase):
    def setUp(self):
        for p in storage.ROOT.iterdir():
            if p.is_dir(): shutil.rmtree(p)
        with storage.database() as c:
            c.execute('DELETE FROM artifacts'); c.execute('DELETE FROM tokens')
        self.owner_id, self.owner = token(True)
        self.agent_id, self.agent = token()
        self.other_id, self.other = token()
        self.private = private_app.test_client()
        self.public = public_app.test_client()

    def headers(self, secret=None):
        return {'Authorization': 'Bearer '+(secret or self.agent)}

    def upload(self, name='README.md', data=b'# Report', extra='', secret=None):
        return self.private.post('/api/artifacts?name='+name+extra, data=data, headers=self.headers(secret))

    def get(self, value, asset=''):
        response = self.public.get('/s/'+value['id']+'/'+value['slug']+'/'+asset)
        response.get_data(); response.close()
        return response

    def bundle(self, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries: archive.writestr(name, content)
        return buffer.getvalue()

    def test_auth_ownership_and_token_revocation(self):
        for header in ('', self.agent, 'Basic '+self.agent, 'Bearer '+self.agent+' extra'):
            self.assertEqual(self.private.post('/api/artifacts', data=b'x', headers={'Authorization':header}).status_code,401)
        value = self.upload().json
        for secret, expected in ((self.other,403),(self.owner,204)):
            self.assertEqual(self.private.delete('/api/artifacts/'+value['id'], headers=self.headers(secret)).status_code,expected)
        self.assertEqual(self.get(value).status_code,404)
        self.assertEqual(self.private.post('/api/tokens',headers=self.headers()).status_code,403)
        issued=self.private.post('/api/tokens',headers=self.headers(self.owner))
        self.assertEqual(issued.status_code,201)
        self.assertEqual(self.upload(secret=issued.json['token']).status_code,201)
        self.assertEqual(self.private.delete('/api/tokens/'+self.agent_id,headers=self.headers(self.owner)).status_code,204)
        self.assertEqual(self.upload().status_code,401)
        self.assertEqual(self.private.delete('/api/artifacts/'+value['id'],headers=self.headers()).status_code,401)
        self.assertEqual(self.private.delete('/api/tokens/'+self.owner_id,headers=self.headers(self.owner)).status_code,404)

    def test_lists_are_scoped(self):
        own=self.upload().json; other=self.upload(secret=self.other).json
        rows=self.private.get('/api/artifacts',headers=self.headers()).json
        self.assertEqual([r['id'] for r in rows],[own['id']])
        self.assertEqual(rows[0]['url'],own['url'])
        self.assertEqual(len(self.private.get('/api/artifacts',headers=self.headers(self.owner)).json),2)
        self.assertEqual(self.private.get('/api/tokens',headers=self.headers()).status_code,403)

    def test_expiry_slug_and_cache(self):
        for invalid in ('nan','inf','-inf','abc','1'):
            self.assertEqual(self.upload(extra='&expires='+invalid).status_code,400)
        value=self.upload(extra='&slug=Quarterly+Report&expires='+str(time.time()+10)).json
        self.assertRegex(value['slug'],r'^quarterly-report-[a-f0-9]{12}$')
        self.assertNotEqual(value['slug'],self.upload(extra='&slug=Quarterly+Report').json['slug'])
        response=self.get(value);self.assertEqual(response.status_code,200)
        self.assertIn('no-store',response.headers['Cache-Control']);self.assertNotIn('ETag',response.headers)
        with self.public.get('/s/'+value['id']+'/') as legacy:
            self.assertEqual(legacy.status_code,200)
        with storage.database() as c:c.execute('UPDATE artifacts SET expires=1 WHERE id=?',(value['id'],))
        self.assertEqual(self.get(value).status_code,404)

    def test_markdown_is_precomputed_and_sanitized(self):
        value=self.upload(data=b'# Title\n\n|A|B|\n|-|-|\n|1|2|\n\n```python\nprint(1)\n```\n\n<script>alert(1)</script><img src=x onerror=alert(1)>[bad](javascript:alert(1))').json
        response=self.get(value)
        self.assertEqual(response.status_code,200)
        for expected in (b'<h1>',b'<table>',b'codehilite'):self.assertIn(expected,response.data)
        for forbidden in (b'<script>',b'onerror=',b'href="javascript:'):self.assertNotIn(forbidden,response.data)
        self.assertIn('sandbox allow-scripts',response.headers['Content-Security-Policy'])
        self.assertEqual(self.get(value,'.artifact-render/README.md').status_code,404)
        value=self.upload(data=b'x'*(MAX_MARKDOWN+1)).json
        response=self.get(value)
        self.assertIn('attachment',response.headers['Content-Disposition'])
        self.assertEqual(self.upload(data=b'\xff').status_code,400)

    def test_bundle_relative_assets_and_mime(self):
        value=self.upload(data=self.bundle([('index.html',b'<script src="app.js"></script>'),('app.js',b'window.test=1'),('nested/image.svg',b'<svg onload="alert(1)"/>')]),extra='&bundle=1').json
        self.assertEqual(self.get(value).mimetype,'text/html')
        self.assertEqual(self.get(value,'app.js').mimetype,'text/javascript')
        svg=self.get(value,'nested/image.svg');self.assertEqual(svg.mimetype,'application/octet-stream')
        self.assertIn('attachment',svg.headers['Content-Disposition'])
        for name, mime in [('x.pdf','application/pdf'),('x.png','image/png'),('x.unknown','application/octet-stream')]:
            item=self.upload(name,data=b'test').json
            self.assertEqual(self.get(item).mimetype,mime)

    def test_zip_and_path_rejections(self):
        for name in ('../escape','/absolute','a/../b','a//b','a\\b','.artifact-render/README.md'):
            with self.subTest(name=name):
                result=self.upload(data=self.bundle([(name,b'x')]),extra='&bundle=1')
                self.assertEqual(result.status_code,400)
        link=zipfile.ZipInfo('link');link.create_system=3;link.external_attr=(stat.S_IFLNK|0o777)<<16
        special=zipfile.ZipInfo('device');special.create_system=3;special.external_attr=(stat.S_IFIFO|0o600)<<16
        for entries in ([(link,b'/etc/passwd')],[(special,b'x')],[('index.html',b'a'),('index.html',b'b')]):
            self.assertEqual(self.upload(data=self.bundle(entries),extra='&bundle=1').status_code,400)
        self.assertEqual(self.upload(data=b'invalid zip',extra='&bundle=1').status_code,400)
        with patch.object(storage,'MAX_FILES',1):
            self.assertEqual(self.upload(data=self.bundle([('index.html',b'a'),('a',b'b')]),extra='&bundle=1').status_code,413)
        with patch.object(storage,'LIMIT',100):
            self.assertEqual(self.upload(data=self.bundle([('index.html',b'a'*1000)]),extra='&bundle=1').status_code,413)
        self.assertFalse((storage.ROOT/'.staging').exists())

    def test_symlink_escape_on_reads(self):
        item=self.upload('index.html',b'hello').json
        directory=storage.ROOT/item['id']
        (directory/'link').symlink_to('/etc/passwd')
        (directory/'folder').symlink_to('/etc',target_is_directory=True)
        self.assertEqual(self.get(item,'link').status_code,404)
        self.assertEqual(self.get(item,'folder/passwd').status_code,404)
        shutil.rmtree(directory);directory.symlink_to('/etc',target_is_directory=True)
        self.assertEqual(self.get(item,'passwd').status_code,404)
        directory.unlink()

    def test_physical_quota_and_failed_delete(self):
        (storage.ROOT/'orphan').mkdir();(storage.ROOT/'orphan/file').write_bytes(b'x'*100)
        with patch.object(storage,'BUDGET',storage.disk_usage()+16384):
            self.assertEqual(self.upload('x',b'x'*10).status_code,413)
        item=self.upload('x',b'hello').json
        original=shutil.rmtree
        def fail_target(path,*a,**kw):
            if Path(path)==storage.ROOT/item['id']:raise OSError('private path should not be logged')
            return original(path,*a,**kw)
        with patch('artifact_host.app.shutil.rmtree',side_effect=fail_target):
            result=self.private.delete('/api/artifacts/'+item['id'],headers=self.headers())
        self.assertEqual(result.status_code,500);self.assertNotIn(b'private path',result.data)
        self.assertEqual(self.get(item).status_code,404)
        self.assertTrue((storage.ROOT/item['id']).exists())
        self.assertEqual(self.private.delete('/api/artifacts/'+item['id'],headers=self.headers()).status_code,204)

    def test_ingestion_limit_and_concurrency(self):
        stream=io.BytesIO(b'x'*101)
        with self.assertRaises(storage.QuotaExceeded):storage.copy_limited(stream,io.BytesIO(),100)
        with (storage.ROOT/'.upload.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            self.assertEqual(self.upload('x',b'x').status_code,429)
            self.assertEqual(self.private.delete('/api/tokens/'+self.agent_id,headers=self.headers(self.owner)).status_code,204)
        # Token revoked while its body is being streamed cannot commit.
        self.agent_id,self.agent=token()
        original=storage.copy_limited
        def revoke_midstream(source,dest,maximum):
            value=original(source,dest,maximum)
            with storage.database() as c:c.execute('DELETE FROM tokens WHERE id=?',(self.agent_id,))
            return value
        with patch('artifact_host.app.storage.copy_limited',side_effect=revoke_midstream):
            self.assertEqual(self.upload('x',b'x').status_code,401)
        with storage.database() as c:self.assertEqual(c.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)

    def test_atomic_parallel_budget(self):
        with patch.object(storage,'BUDGET',storage.disk_usage()+100000):
            def upload_one(_):
                with private_app.test_client() as client:
                    return client.post('/api/artifacts?name=x',data=b'x'*60000,headers=self.headers()).status_code
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results=list(pool.map(upload_one,range(2)))
            self.assertLessEqual(storage.disk_usage(),storage.BUDGET)
        self.assertEqual(results.count(201),1)
        self.assertTrue(set(results)<={201,413,429})

    def test_empty_files_cannot_bypass_quota(self):
        with patch.object(storage,'BUDGET',0):
            self.assertEqual(self.upload('empty',b'').status_code,413)
        budget=storage.disk_usage()+100000
        results=[]
        with patch.object(storage,'BUDGET',budget):
            for _ in range(10):results.append(self.upload('empty',b'').status_code)
        self.assertIn(413,results)
        self.assertGreater(storage.disk_usage(),0)
        with storage.database() as c:
            self.assertLess(c.execute('SELECT count(*) FROM artifacts').fetchone()[0],10)

    def test_zip64_metadata_is_rejected_before_parsing(self):
        blob=self.bundle([('index.html',b'x')])
        position=blob.rfind(b'PK\x05\x06')
        record=struct.unpack_from('<4s4H2LH',blob,position)
        zip64=struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,record[4],record[4],record[5],record[6])
        locator=struct.pack('<4sLQL',b'PK\x06\x07',0,position,1)
        false=struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,1,1,20,position+len(zip64),0)
        with patch('artifact_host.storage.zipfile.ZipFile',side_effect=AssertionError('Must reject before ZipInfo allocation')):
            result=self.upload(data=blob[:position]+zip64+locator+false,extra='&bundle=1')
        self.assertEqual(result.status_code,400)

    def test_zip64_locator_outside_tail_buffer(self):
        blob=self.bundle([('index.html',b'x'),('other',b'x')])
        position=blob.rfind(b'PK\x05\x06')
        record=struct.unpack_from('<4s4H2LH',blob,position)
        start=record[6]
        lengths=struct.unpack_from('<3H',blob,start+28)
        fake=bytearray(blob[start:start+46+sum(lengths)])
        struct.pack_into('<H',fake,32,76)  # Hide ZIP64 records in a member comment.
        zip64=struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,3,3,record[5]+len(fake),start)
        locator=struct.pack('<4sLQL',b'PK\x06\x07',0,position+len(fake),1)
        false=struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,1,1,len(fake)+76,position,65535)
        forged=blob[:position]+fake+zip64+locator+false+b'x'*65535
        with patch.object(storage,'MAX_FILES',1),patch('artifact_host.storage.zipfile.ZipFile',side_effect=AssertionError('Must reject before allocation')):
            self.assertEqual(self.upload(data=forged,extra='&bundle=1').status_code,400)

    def test_explicit_https_private_origin(self):
        with patch.dict(os.environ,{'PRIVATE_ORIGIN':'https://private.example:8443'}):
            app=create_app(True)
        client=app.test_client()
        headers=dict(self.headers(),Host='private.example:8443',Origin='https://private.example:8443')
        self.assertEqual(client.post('/api/artifacts?name=x',data=b'x',headers=headers).status_code,201)
        self.assertEqual(client.post('/api/artifacts?name=x',data=b'x',headers={'Host':'private.example:8443','Origin':'https://private.example:8443'}).status_code,401)
        headers['Origin']='https://evil.example'
        headers['X-Forwarded-Proto']='https'
        self.assertEqual(client.post('/api/artifacts?name=x',data=b'x',headers=headers).status_code,403)
        with patch.dict(os.environ,{'PRIVATE_ORIGIN':'http://private.example'}),self.assertRaises(RuntimeError):
            create_app(True)

    def test_private_and_public_boundaries(self):
        self.assertEqual(self.private.get('/health',environ_overrides={'REMOTE_ADDR':'100.64.0.1'}).status_code,403)
        self.assertEqual(self.private.get('/health',headers={'Host':'evil.example'}).status_code,400)
        self.assertEqual(self.private.post('/api/artifacts',data=b'x',headers=dict(self.headers(),Origin='https://evil.example')).status_code,403)
        self.assertEqual(self.public.post('/api/artifacts',data=b'x',headers=self.headers()).status_code,404)
        self.assertEqual(self.public.get('/health',headers={'Host':'evil.example'}).status_code,400)
        response=self.private.get('/')
        self.assertNotIn('sandbox',response.headers['Content-Security-Policy'])
        self.assertIn("connect-src 'self'",response.headers['Content-Security-Policy'])
        self.assertEqual(self.private.get('/api/artifacts').status_code,401)
        with self.private.get('/dashboard.js') as script:
            self.assertEqual(script.status_code,200)

if __name__=='__main__':unittest.main()
