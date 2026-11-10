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

The private management page supports listing, viewing, deleting/revoking artifacts, creating tokens and revoking agent tokens. It holds the owner token only in the page's password field, never cookies or local storage. Forget the token or close the page when finished.

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
