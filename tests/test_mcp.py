import unittest
from unittest.mock import patch
from artifact_host.mcp_server import upload_artifact,list_artifacts,revoke_artifact,mcp
class MCP(unittest.IsolatedAsyncioTestCase):
    async def test_tools(self):
        self.assertEqual({t.name for t in await mcp.list_tools()},{'upload_artifact','list_artifacts','revoke_artifact'})
        with patch('artifact_host.mcp_server.upload',return_value={'ok':True}) as call:
            upload_artifact('a.txt','aGVsbG8=',slug='Report',base64_encoded=True)
            self.assertEqual(call.call_args.args,('a.txt',b'hello','Report',False,None))
        with patch('artifact_host.mcp_server.api',return_value={'ok':True}) as call:
            list_artifacts();self.assertEqual(call.call_args.args,('GET','/api/artifacts'))
            revoke_artifact('abc');self.assertEqual(call.call_args.args,('DELETE','/api/artifacts/abc'))
