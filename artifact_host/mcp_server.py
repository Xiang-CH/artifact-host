"""Local stdio MCP bridge. Credentials stay in the process environment."""
import base64
from urllib.parse import quote, urlencode
from mcp.server.fastmcp import FastMCP
from artifact_host.client import api, upload

mcp = FastMCP('Artifact host')

@mcp.tool()
def upload_artifact(name: str, content: str, slug: str = '', base64_encoded: bool = False,
                    bundle: bool = False, expires: float | None = None) -> dict:
    """Upload text or base64 binary/ZIP. Bundle ZIPs need index.html or README.md.

    Slug selects a readable URL when enabled on the server. Exact names conflict with HTTP 409 if already taken. Links can be forwarded.
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
def set_artifact_slug(artifact_id: str, slug: str) -> dict:
    """Give an owned artifact a simple readable URL. Requires server opt-in.

    Names are guessable, not secret capabilities. Existing links stay valid.
    Slugs are immutable/reserved; a conflicting name returns HTTP 409.
    """
    return api('POST', '/api/artifacts/'+quote(artifact_id, safe='')+'/alias?'+urlencode({'slug': slug}))

@mcp.tool()
def revoke_artifact(artifact_id: str) -> dict:
    """Permanently revoke and delete an owned artifact. Downloads cannot be recalled."""
    return api('DELETE', '/api/artifacts/'+quote(artifact_id, safe=''))

if __name__ == '__main__':
    mcp.run(transport='stdio')
