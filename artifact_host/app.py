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
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, abort, current_app, jsonify, request, send_file
from werkzeug.exceptions import HTTPException

from artifact_host import storage
from artifact_host.rendering import CACHE_DIR, render_bundle

ROOT = storage.ROOT
PUBLIC = os.environ.get('PUBLIC_URL', 'http://127.0.0.1:8792').rstrip('/')
PUBLIC_PARTS = urlsplit(PUBLIC)
if PUBLIC_PARTS.scheme not in ('http', 'https') or not PUBLIC_PARTS.hostname or PUBLIC_PARTS.username or PUBLIC_PARTS.password or PUBLIC_PARTS.path or PUBLIC_PARTS.query or PUBLIC_PARTS.fragment:
    raise RuntimeError('PUBLIC_URL must be a dedicated HTTP(S) origin')
# The service ships loopback-only; production read hosts must use HTTPS.
if PUBLIC_PARTS.scheme == 'http' and PUBLIC_PARTS.hostname not in ('127.0.0.1', 'localhost', '::1'):
    raise RuntimeError('Public non-loopback URLs require HTTPS')
storage.initialize()

ARTIFACT_CSP = "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

def token(owner=False):
    with storage.database() as connection:
        connection.execute('BEGIN IMMEDIATE')
        value = storage.issue_token(connection, owner)
        return value['id'], value['token']

def share_url(row):
    if current_app.config['READABLE_URLS'] and 'short_slug' in row.keys() and row['short_slug']:
        return PUBLIC + '/' + row['short_slug'] + '/'
    return PUBLIC + '/s/' + row['id'] + '/' + (row['slug'] + '/' if row['slug'] else '')

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

    @app.before_request
    def boundary():
        if not private and request.method not in ('GET', 'HEAD'):
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
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" if private else ARTIFACT_CSP)
        response.headers['X-Frame-Options'] = 'DENY'
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
                return jsonify([dict(row, url=share_url(row)) for row in rows])

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
            return {'id': identifier, 'short_slug': slug, 'url': PUBLIC + '/' + slug + '/'}

        @app.post('/api/artifacts')
        def upload():
            secret = credential()
            with storage.database() as connection:
                authenticate(connection, secret)
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
                        connection.execute('INSERT INTO artifacts(id,owner,entry,size,expires,slug) VALUES(?,?,?,?,?,?)',
                            (identifier, agent['id'], entry, size, expiry, slug))
                        if app.config['READABLE_URLS']:
                            title = request.args.get('slug') or Path(request.args.get('name', 'artifact')).stem
                            short_slug = bind_alias(connection, identifier, title, exact=bool(request.args.get('slug')))
                        if storage.disk_usage() - storage.tree_usage(staging_root) > storage.BUDGET:
                            raise storage.QuotaExceeded('Metadata exceeds storage budget')
                    except BaseException:
                        shutil.rmtree(ROOT / identifier)
                        raise
                url = PUBLIC + '/' + short_slug + '/' if short_slug else PUBLIC + '/s/' + identifier + '/' + slug + '/'
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
        @app.get('/s/<identifier>/', defaults={'name': None})
        @app.get('/s/<identifier>/<path:name>')
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

        @app.get('/<short_slug>/', defaults={'name': None})
        @app.get('/<short_slug>/<path:name>')
        def serve_alias(short_slug, name):
            if not app.config['READABLE_URLS']:
                abort(404)
            with storage.database() as connection:
                row = connection.execute('SELECT artifacts.* FROM artifacts JOIN aliases ON aliases.artifact_id=artifacts.id WHERE aliases.slug=?', (short_slug,)).fetchone()
            return serve_file(row, name)

        def serve_file(row, name):
            if row is None or row['revoked'] or (row['expires'] is not None and row['expires'] <= time.time()):
                abort(404)
            identifier = row['id']
            name = name or row['entry']
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
                        response = send_file(rendered, mimetype='text/html', conditional=False, etag=False)
                        response.call_on_close(rendered.close)
                        return response
                types = {'.html':'text/html', '.css':'text/css', '.js':'text/javascript', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif', '.webp':'image/webp', '.pdf':'application/pdf'}
                response = send_file(source, mimetype=types.get(extension, 'application/octet-stream'),
                    as_attachment=extension not in types, download_name=Path(name).name, conditional=False, etag=False)
                response.call_on_close(source.close)
                return response
            except (OSError, storage.InvalidUpload):
                abort(404)
    return app

private_app = create_app(True)
public_app = create_app(False)
if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['init']:
        identifier, secret = token(True)
        print(json.dumps({'id': identifier, 'token': secret}))
