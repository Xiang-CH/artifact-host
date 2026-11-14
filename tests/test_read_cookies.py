"""Remembered credentials stay small per request and migrate without renewing."""
from email.message import Message
import http.cookiejar
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.request import Request
from flask import Response
import test_service
from artifact_host import storage, read_access
from artifact_host.app import create_app


class ReadCookies(unittest.TestCase):
    setUp=test_service.Service.setUp

    def test_forty_remembered_files_do_not_fill_any_request_header(self):
        jar=http.cookiejar.CookieJar()
        for index in range(40):
            identifier=str(index).zfill(43)
            row={'id':identifier,'read_cookie_key':'synthetic-signing-key'}
            paths=['/doc-'+str(index)+'/', '/s/'+identifier+'/']
            response=Response()
            read_access.unlock_cookie(response,row,paths)
            message=Message()
            for header in response.headers.getlist('Set-Cookie'):
                message.add_header('Set-Cookie',header)
            jar.extract_cookies(SimpleNamespace(info=lambda:message),Request('https://read.example'+paths[0]))
        self.assertEqual(len(jar),80)
        for index in range(40):
            for path in ('/doc-'+str(index)+'/', '/s/'+str(index).zfill(43)+'/'):
                request=Request('https://read.example'+path);jar.add_cookie_header(request)
                header=request.get_header('Cookie')
                self.assertIn('artifact_read_'+str(index).zfill(43),header)
                self.assertLess(len(header),512)
                self.assertEqual(header.count('artifact_read_'),1)
        for path in ('/health','/api/identity','/unrelated/'):
            request=Request('https://read.example'+path);jar.add_cookie_header(request)
            self.assertIsNone(request.get_header('Cookie'))

    def test_old_root_cookies_migrate_in_bounded_batches_without_new_expiry(self):
        with patch.dict('os.environ',{'READABLE_URLS':'1'}):app=create_app(False)
        app.config['SERVER_NAME']='127.0.0.1';client=app.test_client()
        expiry=str(int(time.time())+5*86400)
        values={}
        with storage.database() as connection:
            for index in range(25):
                identifier=str(index).zfill(43)
                row={'id':identifier,'read_cookie_key':'synthetic-signing-key'}
                connection.execute('INSERT INTO artifacts(id,owner,entry,size,slug,read_password_hash,read_cookie_key) VALUES(?,?,?,?,?,?,?)',(identifier,self.agent_id,'file.txt',0,'cookie-'+str(index),'fixture-hash',row['read_cookie_key']))
                connection.execute('INSERT INTO aliases VALUES(?,?)',('doc-'+str(index),identifier))
                value=expiry+'.'+read_access.signature(row,expiry)
                values[identifier]=value
                client.set_cookie(read_access.cookie_name(row),value,domain='127.0.0.1',path='/')
        response=client.get('/health')
        self.assertEqual(response.status_code,200)
        self.assertLessEqual(len(response.headers.getlist('Set-Cookie')),60)
        self.assertLess(sum(len(h) for h in response.headers.getlist('Set-Cookie')),30*1024)
        self.assertEqual(sum(client.get_cookie('artifact_read_'+i,domain='127.0.0.1',path='/') is not None for i in values),5)
        self.assertEqual(client.get('/health').status_code,200)
        for index,(identifier,value) in enumerate(values.items()):
            name='artifact_read_'+identifier
            self.assertIsNone(client.get_cookie(name,domain='127.0.0.1',path='/'))
            for path in ('/doc-'+str(index)+'/', '/s/'+identifier+'/'):
                cookie=client.get_cookie(name,domain='127.0.0.1',path=path)
                self.assertEqual(cookie.value,value)
                self.assertEqual(int(cookie.expires.timestamp()),int(expiry))
        self.assertNotIn('artifact_read_',client.get('/health').request.headers.get('Cookie',''))
