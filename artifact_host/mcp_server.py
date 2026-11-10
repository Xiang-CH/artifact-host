"""Local stdio MCP bridge. Credentials stay in the process environment."""
import os
import json
import base64
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote
from urllib.error import HTTPError
from mcp.server.fastmcp import FastMCP

mcp = FastMCP('Artifact host')

def api(method, path, data=None):
    endpoint = os.environ.get('ARTIFACT_API', 'http://127.0.0.1:8791').rstrip('/')
    token = os.environ.get('ARTIFACT_TOKEN')
    if not token:
        raise ValueError('ARTIFACT_TOKEN is required')
    req = Request(endpoint+path, data=data, method=method,
                  headers={'Authorization': 'Bearer '+token, 'Content-Type': 'application/octet-stream'})
    try:
        with urlopen(req, timeout=120) as response:
            body = response.read()
            return json.loads(body) if body else {'ok': True}
    except HTTPError as error:
        raise ValueError(f'Artifact API returned HTTP {error.code}') from None

@mcp.tool()
def upload_artifact(name: str, content: str, slug: str = '', base64_encoded: bool = False,
                    bundle: bool = False, expires: float | None = None) -> dict:
    """Upload text or base64 binary/ZIP. Bundle ZIPs need index.html or README.md.

    Slug is a readable title; a unique suffix is appended. Links can be forwarded.
    Expiry is an optional Unix timestamp. No local filesystem access is exposed.
    """
    query = {'name': name, 'slug': slug}
    if bundle: query['bundle'] = '1'
    if expires is not None: query['expires'] = str(expires)
    if len(content) > 70*1024*1024: raise ValueError('Content exceeds bridge limit')
    data = base64.b64decode(content, validate=True) if base64_encoded else content.encode()
    return api('POST', '/api/artifacts?'+urlencode(query), data)

@mcp.tool()
def list_artifacts() -> list:
    """List artifacts accessible to this agent, including unique slugs and URLs."""
    return api('GET', '/api/artifacts')

@mcp.tool()
def revoke_artifact(artifact_id: str) -> dict:
    """Permanently revoke and delete an owned artifact. Downloads cannot be recalled."""
    return api('DELETE', '/api/artifacts/'+quote(artifact_id, safe=''))

if __name__ == '__main__':
    mcp.run(transport='stdio')
