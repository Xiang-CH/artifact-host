"""Verify the ingress template on disposable loopback listeners, never reload nginx."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def main():
    nginx=shutil.which('nginx')
    if not nginx:raise RuntimeError('nginx is required for this separate integration check')
    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            if self.path=='/cookie-migration/':
                for index in range(60):self.send_header('Set-Cookie','fixture_'+str(index)+'='+('x'*180)+'; Path=/fixture/; Secure; HttpOnly')
            self.end_headers();self.wfile.write(b'upstream')
        do_POST=do_GET
        def log_message(self,*args):pass
    upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
    threading.Thread(target=upstream.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='artifact-nginx-check-') as temporary:
            root=Path(temporary);ports=[free_port(),free_port()]
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-days','1','-subj','/CN=artifact-test.invalid'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            config=(Path(__file__).resolve().parents[1]/'deployment/nginx.conf.template').read_text()
            for key,value in {'@READ_HOST@':'read.artifact-test.invalid','@MCP_HOST@':'mcp.artifact-test.invalid','@CERTIFICATE@':str(root/'cert'),'@CERTIFICATE_KEY@':str(root/'key')}.items():config=config.replace(key,value)
            for port in ports:config=config.replace('listen 443 ssl;',f'listen 127.0.0.1:{port} ssl;',1)
            for port in (8792,8793):config=config.replace(f'http://127.0.0.1:{port}',f'http://127.0.0.1:{upstream.server_port}')
            (root/'nginx.conf').write_text('daemon off; pid '+str(root/'pid')+'; error_log stderr; events {} http { client_body_temp_path '+str(root/'body')+'; proxy_temp_path '+str(root/'proxy')+'; '+config+' }')
            command=[nginx,'-p',str(root),'-c',str(root/'nginx.conf')]
            subprocess.run(command+['-t'],check=True,capture_output=True)
            process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            def request(index,method,path=None):
                conn=http.client.HTTPSConnection('127.0.0.1',ports[index],context=ssl._create_unverified_context(),timeout=3)
                try:
                    conn.request(method,path or ('/mcp' if index else '/file/'),body=b'' if method=='POST' else None,headers={'Host':('mcp' if index else 'read')+'.artifact-test.invalid'})
                    response=conn.getresponse()
                    return response.status,dict(response.getheaders()),response.read()
                finally:conn.close()
            try:
                for _ in range(100):
                    try:
                        if request(0,'GET')[0]==200:break
                    except OSError:time.sleep(.02)
                else:raise RuntimeError('Disposable nginx did not start')
                assert request(0,'GET','/cookie-migration/')[0]==200,'Migration response headers exceeded proxy buffer'
                for index,count,delay in ((0,12,'12'),(1,40,'1')):
                    limited=[]
                    for _ in range(count):
                        status,headers,body=request(index,'POST')
                        if status==429:
                            assert headers.get('Retry-After')==delay,(status,headers)
                            assert headers.get('Cache-Control')=='no-store'
                            assert headers.get('X-Content-Type-Options')=='nosniff'
                            assert b'Too many ' in body
                            limited.append(status)
                        else:assert status==200,status
                    assert limited,'Ingress limiter did not trigger'
                print('Nginx template syntax, migration headers and read/MCP ingress 429 Retry-After checks passed')
            finally:
                process.terminate();process.wait(timeout=10)
    finally:
        upstream.shutdown();upstream.server_close()


if __name__=='__main__':main()
