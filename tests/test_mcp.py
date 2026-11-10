import unittest
from unittest.mock import patch
from artifact_host.mcp_server import upload_artifact, list_artifacts, revoke_artifact, mcp
class MCP(unittest.IsolatedAsyncioTestCase):
 async def test_tools(self):
  tools=await mcp.list_tools()
  self.assertEqual({t.name for t in tools},{'upload_artifact','list_artifacts','revoke_artifact'})
  with patch('artifact_host.mcp_server.api',return_value={'ok':True}) as call:
   upload_artifact('a.txt','aGVsbG8=',slug='Report',base64_encoded=True)
   self.assertEqual(call.call_args.args[2],b'hello')
   self.assertIn('slug=Report',call.call_args.args[1])
   list_artifacts(); self.assertEqual(call.call_args.args,('GET','/api/artifacts'))
   revoke_artifact('abc'); self.assertEqual(call.call_args.args,('DELETE','/api/artifacts/abc'))
