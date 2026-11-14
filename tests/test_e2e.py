"""Real HTTP/CLI/MCP flow through a reverse proxy, no mocked authentication."""
import asyncio
import http.client
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from urllib.request import Request,urlopen
from urllib.error import HTTPError

REPO=Path(__file__).resolve().parents[1]
def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.directory=Path(cls.temp.name)
        cls.private_port=free_port();cls.public_port=free_port()
        cls.api=f'http://127.0.0.1:{cls.private_port}'
        cls.public=f'http://127.0.0.1:{cls.public_port}'
        cls.env=dict(os.environ,ARTIFACT_DATA=str(cls.directory/'data'),PUBLIC_URL=cls.public,READABLE_URLS='1')
        result=subprocess.run([sys.executable,'-m','artifact_host.app','init'],cwd=REPO,env=cls.env,capture_output=True,check=True)
        cls.owner=json.loads(result.stdout)['token'];cls.processes=[]
        cls.log=(cls.directory/'server.log').open('w+')
        for kind,port in [('private',cls.private_port),('public',cls.public_port)]:
            cls.processes.append(subprocess.Popen([sys.executable,'-m','gunicorn','--config','deployment/gunicorn.conf.py','--bind',f'127.0.0.1:{port}',f'artifact_host.app:{kind}_app'],cwd=REPO,env=cls.env,stdout=cls.log,stderr=cls.log))
        for base in (cls.api,cls.public):
            for attempt in range(100):
                try:
                    with urlopen(base+'/health',timeout=1) as response:
                        if response.status==200:break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('Test server did not start')

    @classmethod
    def tearDownClass(cls):
        for process in cls.processes:process.terminate()
        for process in cls.processes:process.wait(timeout=15)
        cls.log.close();cls.temp.cleanup()

    def request(self,method,path,data=None,secret=None,base=None):
        headers={'Authorization':'Bearer '+secret} if secret else {}
        try:
            with urlopen(Request((base or self.api)+path,data=data,method=method,headers=headers),timeout=10) as response:
                return response.status,response.read(),response.headers
        except HTTPError as error:
            return error.code,error.read(),error.headers

    def agent(self):
        code,body,_=self.request('POST','/api/tokens',secret=self.owner)
        self.assertEqual(code,201);return json.loads(body)

    def test_cli_and_http_auth_and_revoke(self):
        agent=self.agent();file=self.directory/'report.md';file.write_text('# CLI report')
        env=dict(self.env,ARTIFACT_API=self.api,ARTIFACT_TOKEN=agent['token'])
        result=subprocess.run([sys.executable,'artifact',str(file),'--slug','CLI Report'],cwd=REPO,env=env,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        path=urlsplit(result.stdout.decode().strip()).path
        code,body,_=self.request('GET',path,base=self.public)
        self.assertEqual(code,200);self.assertIn(b'<h1>CLI report</h1>',body)
        items=json.loads(self.request('GET','/api/artifacts',secret=agent['token'])[1])
        identifier=next(item['id'] for item in items if urlsplit(item['url']).path==path)
        short_alias=subprocess.run([sys.executable,'artifact','--alias',identifier,'--slug','cli-report'],cwd=REPO,env=env,capture_output=True)
        self.assertEqual(short_alias.returncode,0)
        no_auth=dict(env,ARTIFACT_TOKEN='')
        for args in ([str(file)],['--revoke',identifier]):
            result=subprocess.run([sys.executable,'artifact',*args],cwd=REPO,env=no_auth,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(agent['token'].encode(),result.stdout+result.stderr)
        self.assertEqual(self.request('DELETE','/api/artifacts/'+identifier)[0],401)
        result=subprocess.run([sys.executable,'artifact','--revoke',identifier],cwd=REPO,env=env,capture_output=True)
        self.assertEqual(result.returncode,0)
        self.assertEqual(self.request('GET',path,base=self.public)[0],404)
        self.request('DELETE','/api/tokens/'+agent['id'],secret=self.owner)
        result=subprocess.run([sys.executable,'artifact',str(file)],cwd=REPO,env=env,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.log.flush();self.assertNotIn(agent['token'],(self.directory/'server.log').read_text())
        self.assertNotIn(identifier,(self.directory/'server.log').read_text())

    def test_mcp_auth_and_revoke(self):
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        agent=self.agent()
        async def flow(secret):
            params=StdioServerParameters(command=sys.executable,args=['-m','artifact_host.mcp_server'],env=dict(self.env,ARTIFACT_API=self.api,ARTIFACT_TOKEN=secret),cwd=str(REPO))
            with (self.directory/'mcp.log').open('w') as log:
                async with stdio_client(params,errlog=log) as (read,write):
                    async with ClientSession(read,write) as session:
                        await session.initialize()
                        self.assertEqual({t.name for t in (await session.list_tools()).tools},{'upload_artifact','list_artifacts','revoke_artifact'})
                        result=await session.call_tool('upload_artifact',{'name':'index.html','content':'<h1>MCP report</h1>','slug':'MCP report'})
                        if not secret or secret=='invalid':
                            self.assertTrue(result.isError)
                            result=await session.call_tool('revoke_artifact',{'artifact_id':'x'*43});self.assertTrue(result.isError)
                            return
                        self.assertFalse(result.isError)
                        value=json.loads(result.content[0].text)
                        path=urlsplit(value['url']).path
                        self.assertEqual(self.request('GET',path,base=self.public)[0],200)
                        result=await session.call_tool('revoke_artifact',{'artifact_id':value['id']})
                        self.assertFalse(result.isError)
                        self.assertEqual(self.request('GET',path,base=self.public)[0],404)
        asyncio.run(flow(agent['token']))
        asyncio.run(flow(''))
        asyncio.run(flow('invalid'))
        self.request('DELETE','/api/tokens/'+agent['id'],secret=self.owner)
        # The same once-valid token is now rejected through MCP too.
        async def revoked():
            params=StdioServerParameters(command=sys.executable,args=['-m','artifact_host.mcp_server'],env=dict(self.env,ARTIFACT_API=self.api,ARTIFACT_TOKEN=agent['token']),cwd=str(REPO))
            with (self.directory/'mcp.log').open('w') as log:
                async with stdio_client(params,errlog=log) as (read,write):
                    async with ClientSession(read,write) as session:
                        await session.initialize()
                        for name,args in [('upload_artifact',{'name':'x','content':'x'}),('revoke_artifact',{'artifact_id':'x'*43})]:
                            self.assertTrue((await session.call_tool(name,args)).isError)
        asyncio.run(revoked())

    def test_slow_upload_does_not_block_revocation(self):
        agent=self.agent()
        with socket.create_connection(('127.0.0.1',self.private_port),timeout=5) as sock:
            headers=(f'POST /api/artifacts?name=x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {agent["token"]}\r\nContent-Length: 10\r\nConnection: close\r\n\r\n')
            sock.sendall(headers.encode()+b'x')
            time.sleep(.1)
            start=time.monotonic()
            code,_,_=self.request('DELETE','/api/tokens/'+agent['id'],secret=self.owner)
            self.assertEqual(code,204);self.assertLess(time.monotonic()-start,3)
            sock.sendall(b'x'*9)
            self.assertIn(b'401',sock.recv(4096).split(b'\r\n')[0])

    def test_slow_access_change_does_not_block_revocation(self):
        agent=self.agent()
        code,body,_=self.request('POST','/api/artifacts?name=slow-access.txt',b'unchanged',agent['token'])
        self.assertEqual(code,201);artifact=json.loads(body)
        payload=json.dumps({'password':'slow-access-password'}).encode()
        with socket.create_connection(('127.0.0.1',self.private_port),timeout=5) as sock:
            headers=(f'POST /api/artifacts/{artifact["id"]}/access HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {agent["token"]}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n')
            sock.sendall(headers.encode()+payload[:1])
            time.sleep(.1)
            start=time.monotonic()
            code,_,_=self.request('DELETE','/api/tokens/'+agent['id'],secret=self.owner)
            self.assertEqual(code,204);self.assertLess(time.monotonic()-start,3)
            sock.sendall(payload[1:])
            self.assertIn(b'401',sock.recv(4096).split(b'\r\n')[0])
        code,body,_=self.request('GET','/api/artifacts',secret=self.owner)
        self.assertEqual(code,200)
        item=next(item for item in json.loads(body) if item['id']==artifact['id'])
        self.assertFalse(item['password_protected'])

    def test_reverse_proxy_revocation_expiry_and_assets(self):
        public_port=self.public_port
        class Proxy(BaseHTTPRequestHandler):
            def do_GET(self):
                connection=http.client.HTTPConnection('127.0.0.1',public_port)
                connection.request('GET',self.path,headers={'Host':'127.0.0.1','X-Forwarded-Host':'evil.example'})
                response=connection.getresponse();body=response.read()
                self.send_response(response.status)
                for name,value in response.getheaders():
                    if name.lower() not in ('connection','transfer-encoding','server','date'):self.send_header(name,value)
                self.end_headers();self.wfile.write(body);connection.close()
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Proxy)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        import zipfile
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive:
            archive.writestr('index.html','<script src="app.js"></script>');archive.writestr('app.js','window.ok=1')
        try:
            code,body,_=self.request('POST','/api/artifacts?bundle=1&expires='+str(time.time()+2),buffer.getvalue(),self.owner)
            self.assertEqual(code,201);value=json.loads(body);path=urlsplit(value['url']).path
            proxy=f'http://127.0.0.1:{server.server_port}'
            for suffix in ('','app.js'):
                code,body,headers=self.request('GET',path+suffix,base=proxy)
                self.assertEqual(code,200);self.assertIn('no-store',headers['Cache-Control'])
            # No stale/conditional response can resurrect a revoked link.
            self.assertEqual(self.request('DELETE','/api/artifacts/'+value['id'],secret=self.owner)[0],204)
            self.assertEqual(self.request('GET',path,base=proxy)[0],404)
            self.assertEqual(self.request('GET',path,base=self.public)[0],404)
            code,body,_=self.request('POST','/api/artifacts?name=x&expires='+str(time.time()+.3),b'x',self.owner)
            self.assertEqual(code,201);path=urlsplit(json.loads(body)['url']).path
            time.sleep(.35)
            self.assertEqual(self.request('GET',path,base=proxy)[0],404)
        finally:server.shutdown();server.server_close()
