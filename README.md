# Artifact host

A small artifact service with a private upload/management API, a separate public read listener, a CLI, and a local stdio MCP bridge. Every upload and revoke requires an active agent bearer token; an owner token can manage all artifacts and agent tokens. Share links need no login. Recipients can forward them, and downloads cannot be recalled.

## Setup

Use Python 3.11+ on Linux. Create a virtual environment and install `requirements.txt`; add `requirements-mcp.txt` for MCP. Set `ARTIFACT_DATA` to a private directory and `PUBLIC_URL` to a dedicated read-only HTTPS origin. For loopback development, the default read origin is `http://127.0.0.1:8792`. Run `python -m artifact_host.app init` once and save the resulting owner token in a secret manager or a mode-0600 file. Do not paste real tokens into logs or commit them.

Start two services from the repository directory:

```sh
gunicorn --config deployment/gunicorn.conf.py --bind 127.0.0.1:8791 artifact_host.app:private_app
gunicorn --config deployment/gunicorn.conf.py --bind 127.0.0.1:8792 artifact_host.app:public_app
```

The supplied config uses two synchronous workers and a 30-second worker deadline. A stalled upload can occupy one worker; another can still revoke its token. One upload is admitted across processes; concurrent attempts receive HTTP 429 and may retry. Request/access logs are disabled and parser/error logs redact request details. Keep proxy, tunnel and CDN request logs disabled or redact share paths, query strings, Authorization and cookies too.

Both listeners bind to loopback. Forward private access with `ssh -N -L 8791:127.0.0.1:8791 cxiang@aliyun1`. The private app also rejects non-loopback peers, cross-origin browser requests and untrusted Host headers. `PRIVATE_HOSTS` can list exact approved proxy hosts; forwarded headers do not grant trust. A dedicated Cloudflare Tunnel hostname may route only to the read listener. Set `PUBLIC_URL` to that HTTPS origin before enabling routing; public Host validation requires it. Never expose the private listener publicly. `/health` checks SQLite connectivity and reveals no artifact metadata.

## CLI and HTTP API

Set `ARTIFACT_TOKEN` through your secret manager and `ARTIFACT_API` to the API origin. Clients accept HTTPS or loopback HTTP, disable ambient proxies, and refuse redirects so credentials cannot follow them to another origin.

```sh
./artifact report.md --slug quarterly-report
./artifact ./bundle --slug interactive-report
./artifact --revoke ARTIFACT_ID
```

Folder bundles require root `index.html` or `README.md`. The CLI rejects symlinks and special files and limits upload size. The API accepts an octet-stream POST to `/api/artifacts?name=report.md&slug=report`; ZIP bundles add `bundle=1`. Optional `expires` is a finite future Unix timestamp. All private API calls require `Authorization: Bearer <token>`.

- `GET /api/artifacts?offset=0` lists up to 100 owned artifacts. Owner tokens see all. Responses include ID, unique slug, URL, expiry and revocation state.
- `DELETE /api/artifacts/<id>` commits revocation, then deletes files. It is retryable if disk cleanup fails. Failed cleanup does not make a link available again or free its quota.
- Owner-only `GET/POST /api/tokens` lists token IDs or creates an agent token shown once. `DELETE /api/tokens/<id>` revokes an agent token. Agent tokens cannot create/revoke tokens or modify another agent's artifacts. Revoking a token does not revoke its existing share links; revoke those separately.

The private management page supports listing, viewing, deleting/revoking artifacts, creating tokens and revoking agent tokens. It exchanges the owner token for a random 30-day browser session, clears the raw token input, and restores login on reload. The cookie is HttpOnly, SameSite=Strict, Secure on the configured HTTPS origin, host-only and scoped to /api. Only a hash is stored server-side, linked to the active owner token. Session requests require a custom UI header; mutations also require the exact admin Origin. Logout revokes the session. No raw owner token is stored in browser storage. The read service never accepts admin browser sessions or owner/agent tokens; optional per-file read cookies are separate credentials; its reserved /api paths are not artifact routes. Theme preference alone is stored in localStorage.

New share URLs are `/s/<256-bit-random-capability>/<readable-title>-<unique-suffix>/`. Titles are normalized and SQLite enforces slug uniqueness. Avoid sensitive titles. Existing capability links remain valid; artifacts without a slug retain their original path.

## MCP

The bridge uses the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) and stdio. It opens no network listener. Configure your MCP client to launch the repository's Python with the repository as its working directory, supplying `ARTIFACT_API` and a dedicated agent `ARTIFACT_TOKEN` through its secure environment configuration:

```json
{"mcpServers":{"artifacts":{"command":"/absolute/path/to/.venv/bin/python","args":["-m","artifact_host.mcp_server"],"cwd":"/absolute/path/to/artifact-host","env":{"ARTIFACT_API":"http://127.0.0.1:8791"}}}}
```

Tools are `upload_artifact`, `list_artifacts`, and `revoke_artifact`. Upload accepts UTF-8 text or base64 binary; ZIPs use `bundle=true`. No filesystem-reading tool is exposed. Use the CLI for large files to avoid passing base64 through model context. Missing, invalid or revoked tokens fail upload and revoke through the same authenticated API. Listing is paginated through the HTTP API; the MCP listing currently returns its first 100 entries.

## Isolation and limits

Uploaded code never executes on the server. HTML uses an opaque-origin CSP sandbox allowing scripts but excluding same-origin privileges. Inline and relative classic scripts and images work. Cookies, local storage, service workers, forms, frames, fetch/WebSocket requests and external subresources are restricted. ES modules and applications requiring storage or network APIs are unsupported. A sandboxed script can still navigate its own tab to another site; this is not a complete network firewall. Do not enter secrets into untrusted artifacts. Use a separate public hostname without dashboard cookies or credentials.

Markdown up to 256 KiB is rendered at upload time with tables and highlighting, then sanitized with nh3. Larger Markdown downloads. Rendering runs in subprocesses with a three-second CPU limit, five-second per-file wall deadline, ten-second aggregate scheduling budget and 2 MiB output limit. Linux also enforces a 256 MiB address-space limit; macOS development does not enforce that memory limit. A bundle may contain at most 20 Markdown files. Safe relative images remain in the artifact path. SVG and unknown types download as octet-stream with attachment disposition. Responses use `no-store`; conditional 304 responses are disabled so revoked or expired links cannot be resurrected through the service cache.

Defaults are 50 MiB upload/expanded bundle limit and a conservative 3 GiB storage budget, configurable with `UPLOAD_LIMIT` and `STORAGE_BUDGET`. Admission includes SQLite, retained crash files, allocation rounding and minimum inode/directory charges, so empty artifacts consume quota. ZIP metadata is bounded before parsing; ZIP64, multi-disk, encrypted archives, symlinks, special files, duplicate/traversing paths and unsupported compression are rejected. There are at most 2,000 ZIP entries, 10,000 retained artifact records and 1,000 active tokens. These limits protect small hosts; exhausted record capacity requires owner maintenance rather than silently dropping history.

Uploads stream to disk before taking the SQLite mutation lock. Authentication is rechecked inside the transaction, so a revoked token cannot commit an upload that was still being received or waiting for admission. Each upload gets a unique staging path. Abandoned staging is removed by the next admitted upload; other retained files remain charged. Raw staging, directory overhead and temporary rendering can make an upload fail before its nominal file limit when space is tight. The budget is conservative admission accounting, not a filesystem hard quota against unrelated local processes. Responses already in flight and files already downloaded cannot be recalled after revocation.

## Backup, restore and upgrade

For a coherent live backup, run `ARTIFACT_DATA=/private/data python -m artifact_host.maintenance backup /private/backups/unique-name`. It excludes concurrent uploads, takes a SQLite write barrier, copies a SQLite snapshot and matching files, and writes SHA-256 checksums. Backups contain tokens' hashes and share capabilities; keep them private and encrypted off-host.

Restore with `python -m artifact_host.maintenance restore /private/backups/name /private/new-data`. The destination must not exist. Checksums, symlinks and SQLite integrity are checked. Stop both services before switching `ARTIFACT_DATA` to the restored directory, then restart and check both health endpoints and an owned test artifact. Restoration into a separate directory is covered by the regression suite; it preserves owner/agent tokens and artifact links.

For upgrades, install dependencies in a **new release-specific virtual environment** before stopping services. Back up data, stop only the two artifact services, run `ARTIFACT_DATA=/private/data python -m artifact_host.maintenance backfill` from the new release to prepare legacy Markdown caches, point both units at that release/venv, reload user systemd and restart. Keep old code, dependencies, units and the coherent data backup together. Roll back with both artifact services stopped, restore that backup into a fresh directory, restore both old units to the old release/venv and recovered directory, then reload/restart. Never restart Docker or unrelated workloads for an artifact upgrade.

## Verification and public delivery

Run `python -m unittest discover -s tests -v`. Tests cover strict auth, owner/agent isolation, API/CLI/real stdio MCP upload and revoke, redirects, expiry, ZIP and symlink handling, physical/empty-file/concurrent quotas, slow uploads versus token revocation, reverse-proxy reads, cache headers, legacy Markdown backfill and coherent backup/restore with tamper detection. See `SECURITY_REVIEW.md` for the security review and browser evidence.

Public sharing remains pending a dedicated hostname and tunnel routing. No Alibaba CDN resources are enabled. CDN is optional: verify origin Host/SNI, DNS loop prevention, direct-origin behavior and expiry/revocation with caching disabled before enabling it. Do not cache share responses unless per-request edge authorization or an explicitly accepted invalidation delay is implemented. No paid cloud resources are provisioned by this repository.

## Tailnet test deployment

Tailscale Serve can expose two separate HTTPS origins while both Gunicorn listeners stay on loopback. For example, use HTTPS port 8443 for management/API and 8444 for artifact reads. Configure `PRIVATE_ORIGIN=https://your-node.your-tailnet.ts.net:8443` and `PUBLIC_URL=https://your-node.your-tailnet.ts.net:8444` in the artifact units, then restart only those units. `PRIVATE_ORIGIN` adds its exact hostname to the private Host allowlist and accepts that exact browser Origin; arbitrary forwarded headers remain untrusted. CLI and MCP still require their bearer tokens at the HTTPS API origin. Artifact links work only for devices allowed to reach the node on the tailnet.

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:8791
tailscale serve --bg --https=8444 http://127.0.0.1:8792
```

Inspect `tailscale serve status --json` first and preserve existing routes. These are Serve routes, not public Funnel routes. Disable only these routes with `tailscale serve --https=8443 off` and `tailscale serve --https=8444 off`. Tailnet ACLs/grants still control network reachability; application tokens control upload/revoke and ownership.

## Simple short slugs

Set `READABLE_URLS=1` in **both** artifact services to return simple URLs such as `https://host/architecture/`. It is enabled for the Tailnet test deployment. This opts into guessable names rather than secret-capability privacy. Anyone who can reach the read service can try those names; retain Tailnet access controls, or use this mode only for content you intend to expose. The feature is off by default. Turning it off disables short routes and makes listing return the original capability URLs.

When enabled, upload `slug=architecture` requests that exact normalized name. No random suffix is added. If the name is already reserved by another artifact, the upload fails with HTTP 409 and does not overwrite it. Without an explicit slug, the service derives a name from the filename and uses `-2`, `-3`, etc. only on collisions. The response's `url` is the short canonical URL, `short_slug` is the simple name, and `slug` retains the older capability-path label for compatibility. Keep the trailing slash so relative bundle assets resolve correctly.

Existing owned artifacts can receive a short URL using authenticated `POST /api/artifacts/<id>/alias?slug=architecture`, CLI `./artifact --alias ARTIFACT_ID --slug architecture`. MCP chooses the slug through the `upload_artifact.slug` parameter; it has no separate slug-setting tool. The HTTP/CLI alias operation checks agent ownership or owner privileges inside its transaction. Each artifact gets at most one immutable short name. Names remain reserved after revoke, so an old link cannot later be reassigned to someone else's content. Expiry, revoke, no-store and sandbox policy apply equally to both URL forms, and all original links remain valid. Backup/restore includes the alias table in the same database snapshot.

## Remote Streamable HTTP MCP

The optional `artifact_host.remote_mcp` service exposes the same three tools at `/mcp`. It is a separate server process, not a local stdio bridge. It forwards each caller's own bearer token to the private artifact API and never uses a shared owner token. `GET /api/identity` on the private API provides the authenticated, non-secret agent identity used for validation. Revoked tokens fail on the next MCP request, including existing clients' discovery requests; mutation authorization is also rechecked by the underlying API.

```sh
ARTIFACT_API=http://127.0.0.1:8791 \
MCP_ORIGIN=https://your-node.your-tailnet.ts.net:8445 \
python -m artifact_host.remote_mcp

tailscale serve --bg --https=8445 http://127.0.0.1:8793
```

Use `deployment/artifact-mcp.service.template` for a user systemd unit. The process binds only `127.0.0.1:8793`; Tailscale Serve supplies tailnet HTTPS. Keep existing Serve routes and never enable Funnel for this test configuration. Every `/mcp` request needs `Authorization: Bearer <agent-token>`. This service accepts existing static agent tokens; it does not implement an OAuth authorization server or dynamic client registration. Any Streamable HTTP client that can send the header can connect.

The transport is stateless Streamable HTTP. Each JSON-RPC POST can return an SSE response with `Content-Type: text/event-stream`; there are no long-lived session IDs or resumable streams. Authenticated GET returns 405 because standalone server-initiated event streams are not offered. Host/Origin are validated against the configured exact MCP origin; query-string credentials, non-loopback direct peers and redirects are rejected. Four active requests and 120-second request deadlines bound concurrency. Sync tools run in worker threads with isolated request credentials, so concurrent clients cannot inherit one another's identity.

The default MCP JSON body limit is **8 MiB**, including base64 encoding. Use the CLI/HTTP API for larger files up to their normal 50 MiB limit. `MCP_BODY_LIMIT` can be set from 1 KiB to 72 MiB, and `MCP_ACTIVE_LIMIT` from 1 to 8; increase the memory cgroup limit appropriately before raising these. The default systemd MCP service is capped at 384 MiB and one CPU. The gateway has no data-directory write permission. Health is `/health`; server logs omit request paths, bodies, headers and exception messages.

For Codex, use a Streamable HTTP entry with `url` and a bearer credential source. A local `http_headers_helper` can read a mode-0600 credential file and print its Authorization header to Codex without embedding the secret in `config.toml`. Back up the stdio entry before changing it. The remote endpoint still requires Tailscale connectivity; cloud-hosted MCP clients outside the tailnet cannot reach it until an explicitly configured public ingress exists.

Regression tests cover real remote initialize/tool calls, SSE responses, anonymous/invalid/revoked tokens, revocation on an existing client, multi-agent ownership, concurrent identity isolation, Host/Origin checks and fixed/chunked body limits.


The dashboard opens in the active category. Expired and revoked artifacts are grouped under Archive; filtering happens in SQLite before pagination. Archive membership is derived from expiry/revocation, without moving files or changing links. Dark, light and system appearance choices persist across visits. Browser sessions expire after 30 days and require login again after logout, expiry or owner-token invalidation.


Markdown previews use a document layout with constrained reading width, responsive typography, code/table styles and a system/light/dark selector. The trusted viewer script is inserted only after Markdown HTML sanitization; uploaded scripts and event handlers stay forbidden. Because the public sandbox blocks browser storage, document theme changes are also saved in the URL fragment, such as `#theme=dark`, so reload/bookmark preserves them without weakening isolation. Use offline `python -m artifact_host.maintenance backfill --refresh` with both artifact services stopped to rebuild existing caches after a viewer update. Source Markdown and share URLs do not change.


Files remain public by default. To require a browser password, pass `read_password` (8–128 characters) to MCP `upload_artifact`, use CLI `./artifact file.md --password` (a hidden prompt, never a password in argv), or use the dashboard's 权限 dialog. The upload API accepts the UTF-8 password base64-encoded in `X-Artifact-Read-Password`, never in query parameters. Authenticated `POST /api/artifacts/<id>/access` accepts JSON `{"password":"..."}` to set/rotate protection or an empty string to restore public access. Only the artifact's agent or owner can change it. Existing files migrate as public. Password hashes and cookie signing keys are excluded from API listings.

Passwords use scrypt. A successful entry issues a per-artifact HttpOnly, Secure, SameSite=None cookie for 30 days. SameSite=None lets opaque sandbox documents load protected relative assets without granting them same-origin access. HTTPS is required outside loopback. Browsers that block third-party cookies may block protected relative assets; test the target browsers before public rollout. Every short/legacy route and attachment checks access, expiry and revocation. Password rotation invalidates remembered access; restoring public access removes the restriction. Cookie credentials cannot be read by sandboxed uploads. Downloaded copies cannot be recalled. Password POSTs require the exact read Origin and are limited before hashing to a burst of five with one attempt restored every 12 seconds per source, plus a global bucket. The application password buckets are per worker; proxy limits provide shared ingress enforcement.

MCP now limits all `/mcp` requests before token validation or body reads: per source burst 30, refill 60/minute; global burst 120, refill 300/minute. Missing, malformed, invalid and valid credentials all count, so rotating fake tokens cannot bypass the limit. HTTP 429 includes Retry-After; the existing four-request concurrency bound remains. Rate state is bounded to 4096 sources; restarting clears it. `MCP_AUTH_BURST` can adjust the per-source burst (1–1000). Shared NAT clients share an allowance. DoS protection beyond these limits belongs at the edge.

`deployment/nginx.conf.template` provides a public read + MCP ingress example, with separate HTTPS hostnames, IP/global rate limits, bounded bodies/timeouts, disabled caching/request logs and MCP response buffering disabled. It does not expose the admin/API. Replace its placeholders and set matching PUBLIC_URL/MCP_ORIGIN. Only when a local trusted proxy overwrites X-Real-IP on EVERY route, enable `ARTIFACT_TRUST_PROXY_IP=1` in the public and MCP services. The default ignores forwarded IP headers; under Tailscale Serve all proxied callers therefore share the loopback source allowance. Keep backend ports on loopback and preserve application security headers. Validate with nginx -t before reload; configure default vhosts/firewall/TLS renewal separately. The template has not enabled any public ingress by itself.
