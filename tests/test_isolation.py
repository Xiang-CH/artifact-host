import unittest
from unittest.mock import patch
from flask import redirect
from artifact_host.app import PUBLIC, create_app
from artifact_host.isolation import content_policy, remembered_read_context, resource_paths
import test_service


class Isolation(unittest.TestCase):
    setUp = test_service.Service.setUp
    headers = test_service.Service.headers
    upload = test_service.Service.upload

    def test_policy_is_scoped_to_one_artifact(self):
        item = self.upload('index.html', b'<h1>Document</h1>').json
        response = self.public.get('/s/' + item['id'] + '/' + item['slug'] + '/')
        policy = response.headers['Content-Security-Policy']
        self.assertNotIn("'self'", policy)
        self.assertIn(PUBLIC + '/s/' + item['id'] + '/', policy)
        self.assertNotIn('allow-same-origin', policy)
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("default-src 'none'", self.public.get('/missing/').headers['Content-Security-Policy'])
        response.close()

    def test_remembered_cookie_requires_top_level_navigation(self):
        self.assertTrue(remembered_read_context({'Sec-Fetch-Dest':'document','Sec-Fetch-Mode':'navigate'}))
        for headers in ({}, {'Referer':PUBLIC+'/report/'}, {'Sec-Fetch-Dest':'document'}, {'Sec-Fetch-Dest':'iframe','Sec-Fetch-Mode':'navigate'}, {'Sec-Fetch-Dest':'script','Sec-Fetch-Mode':'no-cors'}):
            self.assertFalse(remembered_read_context(headers))

    def test_server_rejects_cross_bundle_even_with_valid_cookie(self):
        item = self.upload('private.js', b'window.privateMarker=true').json
        endpoint='/api/artifacts/'+item['id']+'/access'
        self.assertEqual(self.private.post(endpoint, json={'password':'synthetic-password'}, headers=self.headers()).status_code, 200)
        path='/s/'+item['id']+'/'+item['slug']+'/'
        self.assertEqual(self.public.post(path, data={'password':'synthetic-password'}, headers={'Origin':PUBLIC}).status_code,303)
        for headers in ({}, {'Referer':PUBLIC+'/unrelated/','Sec-Fetch-Dest':'script'}, {'Referer':'https://external.example/','Sec-Fetch-Dest':'script'}, {'Sec-Fetch-Dest':'image'}):
            response=self.public.get(path, headers=headers)
            self.assertEqual(response.status_code,403)
            self.assertNotIn(b'privateMarker',response.data)
        for headers in ({'Sec-Fetch-Dest':'document','Sec-Fetch-Mode':'navigate'},):
            with self.public.get(path, headers=headers) as response:
                self.assertEqual(response.status_code,200)

    def test_browser_resource_redirects_are_never_trampolines(self):
        with patch.dict('os.environ', {'READABLE_URLS':'1'}):
            app=create_app(False)
        app.config['SERVER_NAME']='127.0.0.1'
        app.add_url_rule('/redirect-test/', view_func=lambda:redirect(PUBLIC+'/elsewhere/'))
        client=app.test_client()
        for path in ('/redirect-test/', '/redirect-test'):
            response=client.get(path,headers={'Sec-Fetch-Dest':'script','Sec-Fetch-Mode':'no-cors'})
            self.assertEqual(response.status_code,403)
            self.assertNotIn('Location',response.headers)
        self.assertEqual(client.get('/redirect-test').status_code,308)

    def test_scoped_grants_need_no_cookies_and_recheck_lifecycle(self):
        import re
        import time
        from urllib.parse import urlsplit
        from artifact_host import read_access
        bundle=test_service.Service.bundle(self, [('index.html',b'<script src="private.js"></script>'),('private.js',b'window.ownMarker=true;')])
        item=self.upload('bundle.zip',bundle,extra='&bundle=1').json
        endpoint='/api/artifacts/'+item['id']+'/access'
        self.private.post(endpoint,json={'password':'synthetic-password'},headers=self.headers())
        path='/s/'+item['id']+'/'+item['slug']+'/'
        self.public.post(path,data={'password':'synthetic-password'},headers={'Origin':PUBLIC})
        with self.public.get(path,headers={'Sec-Fetch-Dest':'document','Sec-Fetch-Mode':'navigate'}) as response:
            base=re.match(rb'<!doctype html><base href="([^"]+)">', response.data).group(1).decode()
            policy=response.headers['Content-Security-Policy']
            self.assertIn(base,policy)
            self.assertNotIn("'self'",policy)
        resource=urlsplit(base).path+'private.js'
        anonymous=self.public.application.test_client()
        with anonymous.get(resource) as response:
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.data,b'window.ownMarker=true;')
        with patch('artifact_host.read_access.time.time',return_value=time.time()+read_access.RESOURCE_LIFETIME+1):
            self.assertEqual(anonymous.get(resource).status_code,403)
        other=self.upload('other.js',b'other').json
        self.assertEqual(anonymous.get(resource.replace(item['id'],other['id'])).status_code,403)
        self.assertEqual(anonymous.get(resource.replace('/private.js','x/private.js')).status_code,403)
        self.private.post(endpoint,json={'password':'changed-password'},headers=self.headers())
        self.assertEqual(anonymous.get(resource).status_code,403)
        self.private.delete('/api/artifacts/'+item['id'],headers=self.headers())
        self.assertEqual(anonymous.get(resource).status_code,404)
