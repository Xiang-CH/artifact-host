"""Separate private management and public capability applications."""
import fcntl
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
import zipfile
import base64
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, quote
from html import escape

from flask import Flask, Response, abort, current_app, jsonify, request, send_file
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.exceptions import NotFound

from artifact_host import storage
from artifact_host.rendering import CACHE_DIR, render_bundle
from artifact_host import read_access
from artifact_host.rate_limit import RateLimit, client_address
from artifact_host.isolation import DENY_CSP, content_policy, remembered_read_context, resource_paths

ROOT = storage.ROOT
PUBLIC = os.environ.get('PUBLIC_URL', 'http://127.0.0.1:8792').rstrip('/')
PUBLIC_PARTS = urlsplit(PUBLIC)
PUBLIC_PATH = os.environ.get('PUBLIC_PATH', '')
if PUBLIC_PATH and not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)+', PUBLIC_PATH):
    raise RuntimeError('PUBLIC_PATH must be empty or a path without a trailing slash')
PUBLIC_BASE = PUBLIC + PUBLIC_PATH
if PUBLIC_PARTS.scheme not in ('http', 'https') or not PUBLIC_PARTS.hostname or PUBLIC_PARTS.username or PUBLIC_PARTS.password or PUBLIC_PARTS.path or PUBLIC_PARTS.query or PUBLIC_PARTS.fragment:
    raise RuntimeError('PUBLIC_URL must be a dedicated HTTP(S) origin')
# The service ships loopback-only; production read hosts must use HTTPS.
if PUBLIC_PARTS.scheme == 'http' and PUBLIC_PARTS.hostname not in ('127.0.0.1', 'localhost', '::1'):
    raise RuntimeError('Public non-loopback URLs require HTTPS')
storage.initialize()

ARTIFACT_CSP = DENY_CSP

def token(owner=False):
    with storage.database() as connection:
        connection.execute('BEGIN IMMEDIATE')
        value = storage.issue_token(connection, owner)
        return value['id'], value['token']

def share_url(row):
    if current_app.config['READABLE_URLS'] and 'short_slug' in row.keys() and row['short_slug']:
        return PUBLIC_BASE + '/' + row['short_slug'] + '/'
    return PUBLIC_BASE + '/s/' + row['id'] + '/' + (row['slug'] + '/' if row['slug'] else '')

def credential():
    header = request.headers.get('Authorization', '')
    if not header and request.cookies.get('artifact_session'):
        if request.headers.get('X-Artifact-UI') != '1':
            abort(401)
        if request.method not in ('GET', 'HEAD') and request.headers.get('Origin') != (current_app.config['PRIVATE_ORIGIN'] or request.host_url.rstrip('/')):
            abort(403)
        return 'session:' + request.cookies['artifact_session']
    if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}', header):
        abort(401)
    return header[7:]

def authenticate(connection, secret, owner=False):
    if secret.startswith('session:'):
        row = connection.execute('SELECT tokens.* FROM browser_sessions JOIN tokens ON tokens.id=browser_sessions.token_id WHERE browser_sessions.hash=? AND browser_sessions.expires>? AND tokens.owner=1', (storage.digest(secret[8:]), time.time())).fetchone()
    else:
        row = connection.execute('SELECT * FROM tokens WHERE hash=?', (storage.digest(secret),)).fetchone()
    if row is None:
        abort(401)
    if owner and not row['owner']:
        abort(403)
    return row

def file_name(name):
    name = storage.safe_path(name)
    if any(part.startswith('.artifact-') for part in name.split('/')):
        raise storage.InvalidUpload('Reserved file path')
    return name

def create_app(private=False):
    app = Flask(__name__)
    if not private:
        app.url_map.merge_slashes = False
    private_origin = os.environ.get('PRIVATE_ORIGIN')
    private_hosts = os.environ.get('PRIVATE_HOSTS', 'localhost,127.0.0.1,[::1]').split(',')
    if private_origin:
        origin_parts = urlsplit(private_origin)
        if (origin_parts.scheme != 'https' or not origin_parts.hostname or origin_parts.username
                or origin_parts.password or origin_parts.path or origin_parts.query or origin_parts.fragment
                or private_origin == PUBLIC):
            raise RuntimeError('PRIVATE_ORIGIN must be a distinct HTTPS origin')
        private_hosts.append(origin_parts.hostname)
    app.config.update(MAX_CONTENT_LENGTH=storage.LIMIT, PRIVATE_ORIGIN=private_origin,
                      READABLE_URLS=os.environ.get('READABLE_URLS') == '1',
                      TRUSTED_HOSTS=private_hosts if private else [PUBLIC_PARTS.hostname])
    password_attempts = RateLimit(5, 1 / 12)
    password_total = RateLimit(20, 1)

    @app.before_request
    def boundary():
        if not private and request.method not in ('GET', 'HEAD') and not (request.method == 'POST' and request.endpoint in ('serve', 'serve_alias')):
            abort(404)
        if private:
            try:
                address = ipaddress.ip_address(request.remote_addr or '')
            except ValueError:
                abort(403)
            if not address.is_loopback:
                abort(403)
            # Reject cross-origin requests for bearer and browser-session operations.
            origin = request.headers.get('Origin')
            if origin and origin != (app.config['PRIVATE_ORIGIN'] or request.host_url.rstrip('/')):
                abort(403)
            if request.headers.get('Sec-Fetch-Site') == 'cross-site':
                abort(403)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store, max-age=0'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" if private else getattr(response, 'artifact_policy', ARTIFACT_CSP))
        if getattr(response, 'password_prompt', False):
            response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            # no-referrer makes HTML form navigation serialize Origin as null.
            # Keep exact-Origin CSRF validation while suppressing external referrers.
            response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Frame-Options'] = 'DENY'
        if not private:
            read_access.migrate_cookies(response, request.cookies, app.config['READABLE_URLS'], request.script_root)
        if not private and 300 <= response.status_code < 400 and request.method in ('GET', 'HEAD') and request.headers.get('Sec-Fetch-Dest') not in (None, '', 'document'):
            # CSP drops source-path checks after redirects. Do not provide a
            # redirect trampoline for browser subresources.
            response.status_code = 403
            response.headers.pop('Location', None)
            response.set_data(b'Forbidden')
        return response

    @app.errorhandler(Exception)
    def error_response(error):
        # Never serialize exceptions or request paths: they can contain capabilities.
        if isinstance(error, HTTPException):
            return jsonify(error=error.name), error.code
        if isinstance(error, storage.QuotaExceeded):
            return jsonify(error='Upload or storage limit exceeded'), 413
        if isinstance(error, (storage.InvalidUpload, zipfile.BadZipFile, UnicodeError, ValueError)):
            return jsonify(error='Invalid upload'), 400
        if isinstance(error, sqlite3.OperationalError):
            return jsonify(error='Storage busy or unavailable'), 503
        return jsonify(error='Storage operation failed'), 500

    @app.get('/health')
    def health():
        with storage.database() as connection:
            connection.execute('SELECT 1').fetchone()
        return {'ok': True}

    if private:
        @app.get('/')
        def dashboard():
            return Response((Path(__file__).parent / 'dashboard.html').read_text(), mimetype='text/html')

        @app.get('/dashboard.css')
        def dashboard_styles():
            return send_file(Path(__file__).parent / 'dashboard.css', mimetype='text/css', conditional=False)

        @app.get('/dashboard.js')
        def dashboard_script():
            return send_file(Path(__file__).parent / 'dashboard.js', mimetype='text/javascript', conditional=False)

        @app.post('/api/session')
        def login():
            if request.headers.get('X-Artifact-UI') != '1' or not request.headers.get('Authorization'):
                abort(401)
            secret = secrets.token_urlsafe(32)
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                agent = authenticate(connection, credential(), owner=True)
                connection.execute('DELETE FROM browser_sessions WHERE expires<=?', (time.time(),))
                connection.execute('DELETE FROM browser_sessions WHERE token_id=? AND hash NOT IN (SELECT hash FROM browser_sessions WHERE token_id=? ORDER BY expires DESC LIMIT 31)', (agent['id'], agent['id']))
                connection.execute('INSERT INTO browser_sessions VALUES(?,?,?)', (storage.digest(secret), agent['id'], time.time()+30*86400))
            response = jsonify(ok=True)
            response.set_cookie('artifact_session', secret, max_age=30*86400, httponly=True,
                                secure=bool(private_origin), samesite='Strict', path='/api')
            return response

        @app.delete('/api/session')
        def logout():
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                authenticate(connection, credential(), owner=True)
                connection.execute('DELETE FROM browser_sessions WHERE hash=?', (storage.digest(request.cookies.get('artifact_session', '')),))
            response = jsonify(ok=True)
            response.delete_cookie('artifact_session', path='/api', secure=bool(private_origin), httponly=True, samesite='Strict')
            return response

        @app.get('/api/identity')
        def identity():
            with storage.database() as connection:
                agent = authenticate(connection, credential())
                return {'id': agent['id'], 'owner': bool(agent['owner'])}

        @app.get('/api/artifacts')
        def listing():
            with storage.database() as connection:
                agent = authenticate(connection, credential())
                try:
                    offset = max(0, int(request.args.get('offset', 0)))
                except ValueError:
                    abort(400)
                query = 'SELECT artifacts.*, aliases.slug AS short_slug FROM artifacts LEFT JOIN aliases ON aliases.artifact_id=artifacts.id'
                params = ()
                conditions = []
                if not agent['owner']:
                    conditions.append('artifacts.owner=?')
                    params += (agent['id'],)
                category = request.args.get('category', 'all')
                if category == 'active':
                    conditions.append('artifacts.revoked=0 AND (artifacts.expires IS NULL OR artifacts.expires>?)')
                    params += (time.time(),)
                elif category == 'archive':
                    conditions.append('(artifacts.revoked=1 OR (artifacts.expires IS NOT NULL AND artifacts.expires<=?))')
                    params += (time.time(),)
                elif category != 'all':
                    abort(400)
                if conditions:
                    query += ' WHERE ' + ' AND '.join(conditions)
                rows = connection.execute(query + ' ORDER BY artifacts.rowid LIMIT 100 OFFSET ?', params + (offset,)).fetchall()
                return jsonify([dict({key: row[key] for key in row.keys() if key not in ('read_password_hash', 'read_cookie_key')}, password_protected=bool(row['read_password_hash']), url=share_url(row)) for row in rows])

        @app.route('/api/tokens', methods=['GET', 'POST'])
        def tokens():
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                authenticate(connection, credential(), owner=True)
                if request.method == 'POST':
                    if connection.execute('SELECT count(*) FROM tokens').fetchone()[0] >= 1000:
                        abort(413)
                    return storage.issue_token(connection), 201
                return jsonify([dict(row) for row in connection.execute('SELECT id,owner FROM tokens')])

        @app.delete('/api/tokens/<identifier>')
        def revoke_token(identifier):
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                authenticate(connection, credential(), owner=True)
                result = connection.execute('DELETE FROM tokens WHERE id=? AND owner=0', (identifier,))
                if not result.rowcount:
                    abort(404)
            return '', 204

        def bind_alias(connection, identifier, title, exact=True):
            try:
                base = storage.alias_slug(title)
            except storage.InvalidUpload:
                if exact:
                    raise
                base = 'artifact'
            current = connection.execute('SELECT slug FROM aliases WHERE artifact_id=?', (identifier,)).fetchone()
            if current:
                if current['slug'] != base:
                    abort(409)
                return base
            candidate = base
            counter = 2
            while connection.execute('SELECT 1 FROM aliases WHERE slug=?', (candidate,)).fetchone():
                if exact:
                    abort(409)
                suffix = '-' + str(counter)
                candidate = base[:64-len(suffix)] + suffix
                counter += 1
            connection.execute('INSERT INTO aliases(slug,artifact_id) VALUES(?,?)', (candidate, identifier))
            return candidate

        @app.post('/api/artifacts/<identifier>/alias')
        def set_alias(identifier):
            if not app.config['READABLE_URLS']:
                abort(404)
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                agent = authenticate(connection, credential())
                row = connection.execute('SELECT * FROM artifacts WHERE id=?', (identifier,)).fetchone()
                if row is None or row['revoked'] or (row['expires'] is not None and row['expires'] <= time.time()):
                    abort(404)
                if not agent['owner'] and row['owner'] != agent['id']:
                    abort(403)
                slug = bind_alias(connection, identifier, request.args.get('slug', ''))
                if storage.disk_usage() > storage.BUDGET:
                    raise storage.QuotaExceeded()
            return {'id': identifier, 'short_slug': slug, 'url': PUBLIC_BASE + '/' + slug + '/'}

        @app.post('/api/artifacts/<identifier>/access')
        def set_read_access(identifier):
            secret = credential()
            def authorize_access_change(connection):
                agent = authenticate(connection, secret)
                row = connection.execute('SELECT * FROM artifacts WHERE id=?', (identifier,)).fetchone()
                if row is None or row['revoked']:
                    abort(404)
                if not agent['owner'] and row['owner'] != agent['id']:
                    abort(403)
            # Authenticate without holding a writer lock while reading a body
            # that an authenticated client can send arbitrarily slowly.
            with storage.database() as connection:
                authorize_access_change(connection)
            if request.content_length is None or request.content_length > 2048:
                abort(413)
            data = request.get_json()
            if not isinstance(data, dict) or 'password' not in data:
                abort(400)
            hashed, key = read_access.password_fields(data['password'])
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                authorize_access_change(connection)
                connection.execute('UPDATE artifacts SET read_password_hash=?,read_cookie_key=? WHERE id=?', (hashed, key, identifier))
            return {'password_protected': bool(hashed)}

        @app.post('/api/artifacts')
        def upload():
            secret = credential()
            with storage.database() as connection:
                authenticate(connection, secret)
            try:
                encoded_password = request.headers.get('X-Artifact-Read-Password', '')
                if len(encoded_password) > 1024:
                    abort(400)
                password = base64.b64decode(encoded_password, validate=True).decode('utf-8')
            except (ValueError, UnicodeError):
                abort(400)
            password_hash, cookie_key = read_access.password_fields(password)
            expiry = storage.expiry_value(request.args.get('expires'))
            slug = storage.make_slug(request.args.get('slug') or Path(request.args.get('name', 'artifact')).stem)
            identifier = secrets.token_urlsafe(32)
            entry = file_name(request.args.get('name', 'download.bin'))
            if request.args.get('bundle', '0') not in ('0', '1'):
                abort(400)
            bundle = request.args.get('bundle') == '1'
            lock = (ROOT / '.upload.lock').open('a')
            try:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    abort(429)
                # One in-flight upload across processes. Recover crash leftovers.
                staging_root = ROOT / '.staging'
                if staging_root.exists():
                    shutil.rmtree(staging_root)
                staging_root.mkdir(mode=0o700)
                staging = staging_root / identifier
                staging.mkdir(mode=0o700)
                raw = staging / 'body'
                with raw.open('xb') as output:
                    storage.copy_limited(request.stream, output, min(storage.LIMIT, max(0, storage.BUDGET - storage.disk_usage())))
                # No database lock is held while receiving a potentially slow body.
                with storage.database() as connection:
                    connection.execute('BEGIN IMMEDIATE')
                    agent = authenticate(connection, secret)
                    used = storage.disk_usage() - storage.tree_usage(staging_root)
                    capacity = storage.BUDGET - used - 16384
                    count = connection.execute('SELECT count(*) FROM artifacts').fetchone()[0]
                    if count >= 10000:
                        raise storage.QuotaExceeded('Artifact record limit exceeded')
                    content = staging / 'content'
                    content.mkdir(mode=0o700)
                    if bundle:
                        entry, _ = storage.extract_bundle(raw, content, capacity - storage.file_charge(raw.stat().st_size))
                        raw.unlink()
                    else:
                        if storage.file_charge(raw.stat().st_size) + 8192 > capacity:
                            raise storage.QuotaExceeded()
                        target = content / entry
                        target.parent.mkdir(parents=True, exist_ok=True)
                        raw.rename(target)
                    render_bundle(content, capacity)
                    size = storage.tree_usage(content)
                    if size > capacity:
                        raise storage.QuotaExceeded()
                    content.rename(ROOT / identifier)
                    short_slug = None
                    try:
                        connection.execute('INSERT INTO artifacts(id,owner,entry,size,expires,slug,read_password_hash,read_cookie_key) VALUES(?,?,?,?,?,?,?,?)',
                            (identifier, agent['id'], entry, size, expiry, slug, password_hash, cookie_key))
                        if app.config['READABLE_URLS']:
                            title = request.args.get('slug') or Path(request.args.get('name', 'artifact')).stem
                            short_slug = bind_alias(connection, identifier, title, exact=bool(request.args.get('slug')))
                        if storage.disk_usage() - storage.tree_usage(staging_root) > storage.BUDGET:
                            raise storage.QuotaExceeded('Metadata exceeds storage budget')
                    except BaseException:
                        shutil.rmtree(ROOT / identifier)
                        raise
                url = PUBLIC_BASE + '/' + short_slug + '/' if short_slug else PUBLIC_BASE + '/s/' + identifier + '/' + slug + '/'
                return {'id': identifier, 'slug': slug, 'short_slug': short_slug, 'url': url}, 201
            finally:
                # Do not remove another uploader's staging after failed flock.
                try:
                    if 'staging_root' in locals() and staging_root.exists():
                        shutil.rmtree(staging_root)
                finally:
                    lock.close()

        @app.delete('/api/artifacts/<identifier>')
        def delete(identifier):
            if not storage.ID_PATTERN.fullmatch(identifier):
                abort(404)
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                agent = authenticate(connection, credential())
                row = connection.execute('SELECT * FROM artifacts WHERE id=?', (identifier,)).fetchone()
                if row is None:
                    abort(404)
                if not agent['owner'] and row['owner'] != agent['id']:
                    abort(403)
                connection.execute('UPDATE artifacts SET revoked=1 WHERE id=?', (identifier,))
            # Revocation commits even if disk cleanup fails. Retained files count
            # against physical admission, and a repeated DELETE retries cleanup.
            with storage.database() as connection:
                connection.execute('BEGIN IMMEDIATE')
                authenticate(connection, credential())
                path = ROOT / identifier
                if path.exists():
                    shutil.rmtree(path)
                connection.execute('UPDATE artifacts SET size=0 WHERE id=?', (identifier,))
            return '', 204
    else:
        @app.get('/_r/<identifier>/<grant>/', defaults={'name': None})
        @app.get('/_r/<identifier>/<grant>/<path:name>')
        def serve_resource(identifier, grant, name):
            if not storage.ID_PATTERN.fullmatch(identifier) or len(grant) > 80:
                abort(404)
            with storage.database() as connection:
                row = connection.execute('SELECT * FROM artifacts WHERE id=?', (identifier,)).fetchone()
            if row is None or row['revoked'] or (row['expires'] is not None and row['expires'] <= time.time()):
                abort(404)
            if not read_access.valid_resource_grant(row, grant):
                abort(403)
            return serve_file(row, name, grant)

        @app.route('/s/<identifier>/', defaults={'name': None}, methods=['GET', 'POST'])
        @app.route('/s/<identifier>/<path:name>', methods=['GET', 'POST'])
        def serve(identifier, name):
            if not storage.ID_PATTERN.fullmatch(identifier):
                abort(404)
            with storage.database() as connection:
                row = connection.execute('SELECT * FROM artifacts WHERE id=?', (identifier,)).fetchone()
            if row is not None and row['slug'] and name:
                if name == row['slug'] + '/':
                    name = None
                elif name.startswith(row['slug'] + '/'):
                    name = name[len(row['slug']) + 1:]
                else:
                    abort(404)
            return serve_file(row, name)

        @app.route('/<short_slug>/', defaults={'name': None}, methods=['GET', 'POST'])
        @app.route('/<short_slug>/<path:name>', methods=['GET', 'POST'])
        def serve_alias(short_slug, name):
            if not app.config['READABLE_URLS']:
                abort(404)
            with storage.database() as connection:
                row = connection.execute('SELECT artifacts.* FROM artifacts JOIN aliases ON aliases.artifact_id=artifacts.id WHERE aliases.slug=?', (short_slug,)).fetchone()
            return serve_file(row, name)

        def serve_file(row, name, grant=None):
            if row is None or row['revoked'] or (row['expires'] is not None and row['expires'] <= time.time()):
                abort(404)
            with storage.database() as connection:
                alias = connection.execute('SELECT slug FROM aliases WHERE artifact_id=?', (row['id'],)).fetchone()
            paths = resource_paths(row, alias['slug'] if alias and app.config['READABLE_URLS'] else None, request.script_root)
            resource_prefix = request.script_root + '/_r/' + row['id'] + '/' + (grant or read_access.resource_grant(row)) + '/' if row['read_password_hash'] else None
            policy = content_policy(PUBLIC, [resource_prefix] if resource_prefix else paths, resource_base=bool(resource_prefix))
            if request.method == 'POST':
                if not row['read_password_hash']:
                    abort(405)
                if request.headers.get('Origin') != PUBLIC:
                    abort(403)
                source = client_address(request.remote_addr, request.headers, os.environ.get('ARTIFACT_TRUST_PROXY_IP') == '1')
                retry = password_attempts.check(source)
                if not retry:
                    retry = password_total.check('all')
                if retry:
                    return Response('Too many attempts. Try again later.', status=429, headers={'Retry-After': str(retry)})
                raw = request.stream.read(2049)
                if len(raw) > 2048:
                    abort(413)
                try:
                    values = parse_qs(raw.decode('utf-8'), max_num_fields=2)
                    password = values.get('password', [''])[0]
                except (ValueError, UnicodeError):
                    abort(400)
                if read_access.check_password(row, password):
                    # Relative, server-derived redirect; never accept a return URL.
                    response = Response(status=303, headers={'Location': request.script_root + request.path})
                    read_access.unlock_cookie(response, row, paths)
                    return response
                response = read_access.password_page(failed=True)
                response.password_prompt = True
                return response
            if grant is None and not read_access.unlocked(row, request.cookies):
                response = read_access.password_page()
                response.password_prompt = True
                return response
            if grant is None and row['read_password_hash'] and not remembered_read_context(request.headers):
                abort(403)
            identifier = row['id']
            name = name or row['entry']

            def html_response(source):
                if resource_prefix:
                    # First base wins. CSP allows only this resource directory;
                    # later uploaded bases cannot authorize a different bundle.
                    # No cookie is required on relative scripts/images/CSS.
                    parent = Path(name).parent.as_posix()
                    directory = '' if parent == '.' else quote(parent, safe='/') + '/'
                    base = PUBLIC + resource_prefix + directory
                    prefix = b'<!doctype html><base href="' + escape(base, quote=True).encode() + b'">'
                    def body():
                        try:
                            yield prefix
                            while block := source.read(65536):
                                yield block
                        finally:
                            source.close()
                    response = Response(body(), mimetype='text/html')
                    response.content_length = len(prefix) + os.fstat(source.fileno()).st_size
                    response.call_on_close(source.close)
                else:
                    response = send_file(source, mimetype='text/html', conditional=False, etag=False)
                    response.call_on_close(source.close)
                response.artifact_policy = policy
                return response
            try:
                file_name(name)
                source = storage.open_artifact(identifier, name)
                extension = Path(name).suffix.lower()
                if extension == '.md':
                    try:
                        rendered = storage.open_artifact(identifier, CACHE_DIR + '/' + name)
                    except OSError:
                        rendered = None
                    if rendered is not None:
                        source.close()
                        return html_response(rendered)
                if extension == '.html':
                    return html_response(source)
                types = {'.html':'text/html', '.css':'text/css', '.js':'text/javascript', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif', '.webp':'image/webp', '.pdf':'application/pdf'}
                response = send_file(source, mimetype=types.get(extension, 'application/octet-stream'),
                    as_attachment=extension not in types, download_name=Path(name).name, conditional=False, etag=False)
                response.call_on_close(source.close)
                response.artifact_policy = policy
                return response
            except (OSError, storage.InvalidUpload):
                abort(404)
    if not private and PUBLIC_PATH:
        # A fixed mount, never derived from untrusted forwarding headers. Keep
        # SCRIPT_NAME so redirects, cookie paths and CSP use the external path.
        app.wsgi_app = DispatcherMiddleware(NotFound(), {PUBLIC_PATH: app.wsgi_app})
    return app

private_app = create_app(True)
public_app = create_app(False)
if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['init']:
        identifier, secret = token(True)
        print(json.dumps({'id': identifier, 'token': secret}))
