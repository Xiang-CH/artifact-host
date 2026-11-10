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
