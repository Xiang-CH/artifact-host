# Security review and verification

Review scope: Git empty tree through `86115c7`, including the initial commit, followed by review and remediation of the complete service. Standards and Spec reviews ran independently in parallel, with independent follow-up checks. The originating artifact-hosting plan and the user's explicit requirement for authenticated CLI/API/MCP upload and revoke are the spec. There are no additional repository coding standards or issue-tracker configuration.

## Standards

| Finding | Resolution | Evidence |
| --- | --- | --- |
| High: CLI/MCP forward bearer credentials on redirects and allow plaintext remote endpoints | Shared client refuses redirects and ambient proxies; only HTTPS or loopback HTTP is accepted | `tests/test_client.py`, `artifact_host/client.py` |
| High: revoked token can complete a queued mutation | Authenticate again inside each mutation transaction after upload ingestion | `test_ingestion_limit_and_concurrency`, `test_slow_upload_does_not_block_revocation` |
| Medium: NaN expiry becomes no expiry | Require a finite future timestamp | `test_expiry_slug_and_cache` |
| Medium: dashboard CSP blocks its API calls | Separate private CSP with self-only scripts/connect, no opaque sandbox | `test_private_and_public_boundaries`, `tests/browser_check.py` |
| Medium: crash leftovers and failed deletion evade accounting | Account physical retained content, commit revoke before cleanup, retry deletion, unique recoverable staging | `test_physical_quota_and_failed_delete`, `test_atomic_parallel_budget` |
| Medium: public Markdown parsing exhausts resources | Pre-render at upload under process, CPU, wall, memory and output bounds; large Markdown downloads | `test_markdown_is_precomputed_and_sanitized`, `artifact_host/rendering.py` |
| Low: raw Authorization token accepted without Bearer | Require exact bearer syntax and generated token format | `test_auth_ownership_and_token_revocation` |
| Follow-up high: ZIP directory count checked after allocation, including ZIP64 override bypass | Bound EOCD and central directory before ZipFile allocation; reject ZIP64 locator and scan actual entry count | `test_zip64_metadata_is_rejected_before_parsing`, `test_zip64_locator_outside_tail_buffer`, `validate_zip_directory` |
| Follow-up medium: empty artifacts consume no quota | Minimum file/directory allocation and metadata charges, include SQLite, bound retained artifact/token counts | `test_empty_files_cannot_bypass_quota` |

Two judgment-call smells were also addressed: storage and rendering moved out of the application module, and CLI/MCP share one authenticated HTTP client. The HTTP application still owns routing and authentication so policy remains visible at each endpoint.

Standards result: 9 security concerns and 2 security-relevant smell observations addressed. Worst original Standards issue was cross-origin bearer forwarding.

## Spec

| Finding | Resolution | Evidence |
| --- | --- | --- |
| High: credential leakage violates private authenticated access | No redirect following or remote plaintext API transport | `tests/test_client.py` |
| High: metadata/file divergence breaks storage admission | Conservative disk/inode/SQLite accounting includes orphaned and retained files | `test_physical_quota_and_failed_delete` |
| High: slow request monopolizes mutation lock | Bounded disk streaming before SQLite write lock; cross-process single-upload admission and two synchronous workers | `test_slow_upload_does_not_block_revocation`, `deployment/gunicorn.conf.py` |
| Medium: token revocation race | Revalidate after body receipt and after obtaining the mutation lock | `test_ingestion_limit_and_concurrency` |
| Medium: public serving follows symlinks | Directory-descriptor walk with O_NOFOLLOW and regular-file checks | `test_symlink_escape_on_reads` |
| Medium: owner interface is blocked/incomplete | Complete list/view/revoke/delete/token controls with separate CSP | `tests/browser_check.py`, `artifact_host/dashboard.js` |
| Medium: missing restore/proxy/browser/MCP verification | Real HTTP/CLI/stdio MCP, reverse-proxy, restoration/tamper and browser runs added | `tests/test_e2e.py`, `tests/test_maintenance.py`, `docs/security-browser-check.json` |
| Follow-up high: zero-byte artifact metadata/inode exhaustion | Empty files consume budget; artifact history and active tokens have finite caps | `test_empty_files_cannot_bypass_quota` |
| Follow-up medium: archive parsing before count bound | Preflight central directory and reject ZIP64 before allocation | `test_zip64_metadata_is_rejected_before_parsing` |
| Follow-up medium: crashed renderer can write into reused staging | Each upload uses an unpredictable, unique staging directory | `artifact_host/app.py` upload staging |
| Follow-up medium: legacy Markdown no longer renders after upgrade | Offline quota-aware backfill prepares existing Markdown before cutover | `test_legacy_markdown_backfill`, `artifact_host/maintenance.py` |

Spec result: 11 concerns addressed. Worst original Spec issues were credential leakage and non-atomic resource admission.

## Verification and limits

The 23-test suite passed on macOS/Python 3.11 and Aliyun Ubuntu/Python 3.12. Tests exercise authentication through real HTTP, CLI subprocesses and real MCP stdio sessions, missing/invalid/revoked credentials, ownership, proxy asset delivery, expiry and revoke, concurrent quota admission, a slow HTTP body versus revocation, ZIP traversal/symlinks/metadata bombs, physical quota failures and backup restoration into a separate data directory. Browser checks use Chromium through agent-browser against isolated local services, including relative classic scripts, interactivity, relative images, sanitized Markdown, blocked storage/cookies/fetch and the complete management flow. Run `python tests/browser_check.py` to repeat; it writes only non-sensitive booleans to `docs/security-browser-check.json`.

The declared service/MCP dependency resolution was checked with pip-audit with no known vulnerabilities reported. Flask and Pygments were updated; the discontinued Bleach sanitizer was replaced with nh3. Audit results describe the checked versions and advisory database at review time, not a permanent guarantee.

No public hostname, Cloudflare routing or Alibaba CDN changes were made. Real public HTTPS/CDN behavior remains unverified until the dedicated hostname is configured. Browser sandboxing blocks subresource/API access but does not prevent a script navigating its own tab to an external URL. Already-open responses and downloaded copies cannot be recalled. Same-user/root filesystem compromise is outside the service boundary. See README for exact limits, proxy logging requirements and recovery procedures.


## Password isolation follow-up

The full-service review at `cc97884` confirmed a high-severity issue: origin-wide CSP plus SameSite=None read cookies allowed an unrelated public HTML document to execute a password-protected classic script after the visitor had unlocked it. A benign local Chromium regression demonstrated cross-artifact access to a synthetic marker. HttpOnly did not prevent authenticated script inclusion.

The fix accepts remembered read cookies only on browser top-level document navigations. Private resource requests require separate HMAC-signed, one-hour grants bound to the current artifact and its current password key, and recheck artifact expiry/revocation. Protected HTML/Markdown streams an initial base pointing to that grant directory; no resource Cookie or Referer is needed. Cookie scope returns to SameSite=Lax. CSP limits scripts/styles/images/fonts and bases to the current artifact/resource directory. Automatic subresource redirects are blocked, and slash-merging redirects are disabled. Original share URLs remain valid.

Regression coverage: `tests/test_isolation.py` checks cookie context rejection, CSP scoping, redirect blocking, anonymous scoped-resource access, grant expiry, tampering, cross-artifact use, password rotation and revoke. `tests/browser_check.py` proves that a private page can load its own script/image, while both unrelated public HTML and an external origin cannot execute that private script. The original opaque-origin/storage/cookie/fetch restrictions, Markdown rendering/theme and dashboard flows remain covered. Resource URLs are short-lived read capabilities and must not be shared or logged; expired open-page resources require refreshing the original share URL.

CSP redirect behavior is specified in the [W3C URL-to-source matching algorithm](https://www.w3.org/TR/CSP3/#match-url-to-source-expression).


## CodeRabbit PR #1 follow-up

The external review identified source-rejected requests consuming the shared authentication allowance, an asynchronous access-dialog save affecting a newer edit, and standalone isolation-test imports selecting the wrong data directory. The review summary also noted missing Retry-After on Nginx-generated 429 responses. Source admission now precedes shared-budget consumption in both password and MCP handlers; dialog generation checks isolate response/error/cleanup effects; test bootstrap selects and verifies its owned temporary root before importing the application. Regression tests preserve sentinel service data even when storage was preloaded. The Nginx template supplies explicit read/MCP retry responses, checked with disposable local TLS listeners. Existing public ingress remains disabled.


## CodeRabbit second full review

Four further findings are addressed: access-setting JSON receipt and scrypt hashing now occur before SQLite's writer transaction, with authorization/state/ownership checked before ingestion and again at commit; stale successful editor requests refresh metadata without closing or clearing a newer dialog; remembered cookies are scoped to canonical/legacy artifact paths and old root cookies migrate in bounded batches preserving their expiry; browser input limits no longer disagree with Python Unicode character counting. Additional MCP integration assertions verify the actual supplied read password succeeds and a wrong one fails.

New regression evidence includes real slow HTTP body receipt concurrent with successful token revocation, ownership changes before commit, 40 remembered files remaining below the request-header limit, 25 root-cookie migrations preserving expiry across batches, and a 128-code-point password ending in an emoji working through both dashboard and auth wall. The static template's source remains a constant; the unrelated static-template lint warning is not an untrusted template-injection path.
