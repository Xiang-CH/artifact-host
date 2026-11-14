"""Real Streamable HTTP sessions, independent bearer identities, no shared owner key."""
import asyncio
import concurrent.futures
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request,urlopen

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
import test_e2e

class RemoteMCP(unittest.TestCase):
    request=test_e2e.EndToEnd.request
    agent=test_e2e.EndToEnd.agent

    @classmethod
    def setUpClass(cls):
        test_e2e.EndToEnd.setUpClass.__func__(cls)
        cls.remote_port=test_e2e.free_port()
        cls.origin=f'http://127.0.0.1:{cls.remote_port}'
        cls.remote_url=cls.origin+'/mcp'
        env=dict(cls.env,MCP_PORT=str(cls.remote_port),MCP_ORIGIN=cls.origin,ARTIFACT_API=cls.api,MCP_BODY_LIMIT='8192',MCP_AUTH_BURST='300',ARTIFACT_TOKEN=cls.owner)
        cls.processes.append(subprocess.Popen([sys.executable,'-m','artifact_host.remote_mcp'],cwd=test_e2e.REPO,env=env,stdout=cls.log,stderr=cls.log))
        for _ in range(100):
            try:
                with urlopen(cls.origin+'/health',timeout=1) as response:
                    if response.status==200:break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('Remote MCP did not start')

    @classmethod
    def tearDownClass(cls):
        test_e2e.EndToEnd.tearDownClass.__func__(cls)

    def post(self,secret=None,headers=None,body=None,method='POST'):
        values={'Accept':'application/json, text/event-stream','Content-Type':'application/json'}
        if secret:values['Authorization']='Bearer '+secret
        values.update(headers or {})
        if body is None:body=json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'test','version':'1'}}}).encode()
        try:
            with urlopen(Request(self.remote_url,data=body if method=='POST' else None,headers=values,method=method),timeout=10) as response:
                return response.status,response.read(),response.headers
        except HTTPError as error:return error.code,error.read(),error.headers

    async def session_flow(self,secret,action):
        async with httpx.AsyncClient(headers={'Authorization':'Bearer '+secret},trust_env=False,timeout=15) as http:
            async with streamable_http_client(self.remote_url,http_client=http) as (read,write,get_id):
                async with ClientSession(read,write) as session:
                    await session.initialize()
                    self.assertIsNone(get_id())
                    return await action(session)

    def test_auth_host_origin_limits_and_sse(self):
        agent=self.agent()
        for secret in (None,'invalid','z'*43):self.assertEqual(self.post(secret)[0],401)
        self.assertEqual(self.post(agent['token'],{'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.post(agent['token'],{'Host':'evil.example'})[0],421)
        self.assertEqual(self.post(agent['token'],body=b'x'*9000)[0],413)
        code,body,headers=self.post(agent['token'])
        self.assertEqual(code,200);self.assertIn('text/event-stream',headers['Content-Type'])
        self.assertIn('no-store',headers['Cache-Control']);self.assertIn(b'event: message',body)
        self.assertEqual(self.post(agent['token'],method='GET')[0],405)
        self.request('DELETE','/api/tokens/'+agent['id'],secret=self.owner)
        self.assertEqual(self.post(agent['token'])[0],401)
        self.log.flush();self.assertNotIn(agent['token'],(self.directory/'server.log').read_text())

    def test_chunked_size_limit(self):
        agent=self.agent()
        async def check():
            async def body():
                for _ in range(10):yield b'x'*1024
            async with httpx.AsyncClient(trust_env=False) as client:
                response=await client.post(self.remote_url,content=body(),headers={'Authorization':'Bearer '+agent['token'],'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
                self.assertEqual(response.status_code,413)
        asyncio.run(check())

    def test_per_request_ownership_upload_slug_and_revoke(self):
        first=self.agent();second=self.agent()
        async def create(session):
            tools=await session.list_tools()
            self.assertEqual({t.name for t in tools.tools},{'upload_artifact','list_artifacts','revoke_artifact'})
            upload_tool=next(tool for tool in tools.tools if tool.name=='upload_artifact')
            self.assertIn('slug',upload_tool.inputSchema['properties'])
            result=await session.call_tool('upload_artifact',{'name':'report.md','slug':'remote-mcp-owner-check','content':'# Remote MCP','read_password':'remote-test-password'})
            self.assertFalse(result.isError)
            return json.loads(result.content[0].text)
        artifact=asyncio.run(self.session_flow(first['token'],create))
        self.assertEqual(artifact['short_slug'],'remote-mcp-owner-check')
        self.assertEqual(self.request('GET','/'+artifact['short_slug']+'/',base=self.public)[0],401)
        async def intruder(session):
            listing=await session.call_tool('list_artifacts',{})
            self.assertNotIn(artifact['id'],''.join(c.text for c in listing.content))
            for name,args in [('revoke_artifact',{'artifact_id':artifact['id']})]:
                self.assertTrue((await session.call_tool(name,args)).isError)
        asyncio.run(self.session_flow(second['token'],intruder))
        async def owner(session):
            self.assertFalse((await session.call_tool('revoke_artifact',{'artifact_id':artifact['id']})).isError)
        asyncio.run(self.session_flow(first['token'],owner))
        self.assertEqual(self.request('GET','/'+artifact['short_slug']+'/',base=self.public)[0],404)

    def test_concurrent_callers_do_not_share_identity(self):
        agents=[self.agent() for _ in range(3)]
        for index,agent in enumerate(agents):
            code,body,_=self.request('POST','/api/artifacts?name=x&slug=caller-'+str(index),b'x',agent['token'])
            self.assertEqual(code,201);agent['artifact']=json.loads(body)['id']
        async def one(agent):
            async def check(session):
                result=await session.call_tool('list_artifacts',{})
                text=''.join(c.text for c in result.content)
                self.assertIn(agent['artifact'],text)
                for other in agents:
                    if other is not agent:self.assertNotIn(other['artifact'],text)
            await self.session_flow(agent['token'],check)
        async def all_callers():
            await asyncio.gather(*(one(agent) for agent in agents))
        asyncio.run(all_callers())

    def test_revocation_during_existing_client_connection(self):
        agent=self.agent()
        async def flow(session):
            self.assertEqual(self.request('DELETE','/api/tokens/'+agent['id'],secret=self.owner)[0],204)
            try:
                await session.list_tools()
            except Exception:
                return
            self.fail('Revoked token remained usable on existing connection')
        asyncio.run(self.session_flow(agent['token'],flow))
