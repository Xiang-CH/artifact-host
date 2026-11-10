"""Local stdio MCP bridge. Credentials stay in the process environment."""
import base64
from urllib.parse import quote
from mcp.server.fastmcp import FastMCP
from artifact_host.client import api, upload

mcp = FastMCP('Artifact host')

@mcp.tool()
def upload_artifact(name: str, content: str, slug: str = '', base64_encoded: bool = False,
                    bundle: bool = False, expires: float | None = None) -> dict:
    """Upload text or base64 binary/ZIP. Bundle ZIPs need index.html or README.md.

    Slug is a readable title; a unique suffix is appended. Links can be forwarded.
    Expiry is an optional Unix timestamp. No local filesystem access is exposed.
    """
    if len(content) > 70*1024*1024: raise ValueError('Content exceeds bridge limit')
    data = base64.b64decode(content, validate=True) if base64_encoded else content.encode()
    return upload(name, data, slug, bundle, expires)

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
