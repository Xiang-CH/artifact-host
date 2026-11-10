# Artifact host

Run `python3 -m venv .venv` and install requirements.txt. Set ARTIFACT_DATA to a private directory, PUBLIC_URL to the dedicated read hostname, then run `python -m artifact_host.app init` once and save the owner token securely. Tokens are returned once and stored hashed. Use the authenticated token API to create agent tokens. Set ARTIFACT_TOKEN and ARTIFACT_API, then run `./artifact file-or-folder`.

Run two Gunicorn services with access logs disabled: `artifact_host.app:private_app` on 127.0.0.1:8791 and `artifact_host.app:public_app` on 127.0.0.1:8792. Expose only the latter through a dedicated Cloudflare hostname. Access management through SSH forwarding or a strongly authenticated private proxy. Never route the private listener publicly. No proxy headers are trusted. PUBLIC_URL must be configured before sharing.

All responses forbid caching. Share links are bearer capabilities; recipients can forward them and downloaded content cannot be recalled. DELETE revokes an artifact and deletes files. Optional `expires` is a Unix timestamp. Agent tokens can only delete their own artifacts; owner tokens list/delete all and create/revoke agents. Dashboard currently supports listing only; use authenticated HTTP DELETE and token endpoints for management.

HTML uses a CSP sandbox without same-origin privileges. Inline scripts work; external network, forms, frames outside the origin, modules requiring CORS, fetch, storage and service workers are restricted. Bundle relative static assets work subject to browser sandbox behavior. SVG and unknown files download as octet-stream. Markdown HTML is sanitized. No uploaded code runs on the server. ZIP uploads reject symlinks/traversal and enforce expanded size and file-count limits. Admission holds a SQLite write lock across upload/extraction. Request buffering is bounded by the upload limit; use one worker and two threads on small hosts.

For coherent backups stop BOTH services, copy the entire data directory including state.db, then restart both. Restore with both stopped to an empty directory, preserve ownership and permissions, and restart. This procedure has not yet had a restore drill. Never copy only SQLite while uploads are running. Retain backups privately because they contain share capabilities. For upgrades stop both, back up, install a new release, change WorkingDirectory in both units, reload and restart. Roll back by restoring the matching data backup and release together.

Limitations: no public hostname has been configured, CDN is not enabled, browser-level compatibility and hostile-content testing remain incomplete. The current automated integration test covers upload authentication, ownership, Markdown sanitization, HTML sandbox headers, revocation, expiry and ZIP traversal. Backup restoration, concurrency saturation, proxy routing and browser rendering need additional verification before production use.

## MCP and unique slugs

Install `requirements-mcp.txt` in addition to the service requirements, using Python 3.11 or later. Launch `.venv/bin/python -m artifact_host.mcp_server` from the repository directory. This uses the official MCP Python SDK's stdio transport, so it opens no additional network listener. Configure the MCP client to supply ARTIFACT_API and a dedicated agent ARTIFACT_TOKEN through its secure environment configuration. For a remote service, first forward the private API with `ssh -N -L 8791:127.0.0.1:8791 cxiang@aliyun1`.

Example client configuration, with the token supplied separately through the client's secret mechanism:

```json
{"mcpServers":{"artifacts":{"command":"/absolute/path/to/.venv/bin/python","args":["-m","artifact_host.mcp_server"],"cwd":"/absolute/path/to/artifact-host","env":{"ARTIFACT_API":"http://127.0.0.1:8791"}}}}
```

Tools are `upload_artifact`, `list_artifacts`, and `revoke_artifact`. Upload takes UTF-8 text or base64 binary data; ZIP bundles use `bundle=true`. It intentionally exposes no local file-reading tool. Large files should use the CLI to avoid sending base64 through model context. Agent ownership and token revocation are enforced by the same HTTP API.

New URLs have the form `/s/<random-capability>/<readable-title>-<unique-suffix>/`. Set the title with the API's `slug` query argument, the CLI's `--slug`, or the MCP upload's `slug` argument. Titles are normalized and receive a random suffix; SQLite enforces uniqueness. The capability retains 256 bits of randomness. Listing includes the slug and full URL. Existing links remain valid; no uploaded files are renamed. Slugs may disclose the title to recipients, so avoid sensitive names. Public HTTPS still requires configuring PUBLIC_URL and the dedicated read-only hostname.
