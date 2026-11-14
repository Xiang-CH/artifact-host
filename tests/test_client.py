import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from artifact_host.client import ClientError,api,endpoint_url

class Client(unittest.TestCase):
    def test_transport_validation(self):
        for value in ('http://example.com','https://a:b@example.com','https://example.com/path','file:///tmp/a','https://example.com?x=1','https://example.com#fragment'):
            with self.subTest(endpoint=value),self.assertRaises(ClientError):endpoint_url(value)
        self.assertEqual(endpoint_url('http://127.0.0.1:8791'),'http://127.0.0.1:8791')
        with patch.dict(os.environ,{'ARTIFACT_TOKEN':''}):
            with self.assertRaises(ClientError):api('DELETE','/api/artifacts/x')

    def test_redirect_never_forwards_credentials(self):
        seen=[]
        class Receiver(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get('Authorization'));self.send_response(200);self.end_headers();self.wfile.write(b'{}')
            do_POST=do_DELETE=do_GET
            def log_message(self,*args):pass
        receiver=ThreadingHTTPServer(('127.0.0.1',0),Receiver)
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        for code in (301,302,303,307,308):
            class Redirect(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(code);self.send_header('Location',f'http://127.0.0.1:{receiver.server_port}/capture');self.end_headers()
                do_POST=do_DELETE=do_GET
                def log_message(self,*args):pass
            redirect=ThreadingHTTPServer(('127.0.0.1',0),Redirect)
            threading.Thread(target=redirect.serve_forever,daemon=True).start()
            try:
                with patch.dict(os.environ,{'ARTIFACT_TOKEN':'synthetic-test-token'}):
                    for method in ('GET','POST','DELETE'):
                        with self.assertRaises(ClientError):api(method,'/test',b'x' if method=='POST' else None,endpoint=f'http://127.0.0.1:{redirect.server_port}')
            finally:redirect.shutdown();redirect.server_close()
        receiver.shutdown();receiver.server_close()
        self.assertEqual(seen,[])

    def test_cli_accepts_dash_leading_artifact_ids(self):
        seen=[]
        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.command,self.path,self.headers.get('Authorization')))
                self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
                self.wfile.write(b'{"url":"https://read.example/report/"}')
            do_DELETE=do_POST
            def log_message(self,*args):pass
        receiver=ThreadingHTTPServer(('127.0.0.1',0),Receiver)
        threading.Thread(target=receiver.serve_forever,daemon=True).start()
        repo=Path(__file__).resolve().parents[1]
        secret='synthetic-test-token'
        env=dict(os.environ,ARTIFACT_API=f'http://127.0.0.1:{receiver.server_port}',ARTIFACT_TOKEN=secret)
        try:
            for identifier in ('-'+'a'*41+'A','--'+'b'*40+'A'):
                for option in ('--alias','--revoke'):
                    for args in ([option,identifier],[option+'='+identifier]):
                        if option=='--alias':args+=['--slug','report']
                        result=subprocess.run([sys.executable,'artifact',*args],cwd=repo,env=env,capture_output=True,text=True,timeout=10)
                        self.assertEqual(result.returncode,0,result.stderr)
                        method,path,authorization=seen[-1]
                        self.assertEqual(method,'POST' if option=='--alias' else 'DELETE')
                        self.assertEqual(path,'/api/artifacts/'+identifier+('/alias?slug=report' if option=='--alias' else ''))
                        self.assertEqual(authorization,'Bearer '+secret)
        finally:
            receiver.shutdown();receiver.server_close()
