"""Optional per-artifact passwords and host-only browser unlock cookies."""
import hashlib
import hmac
import secrets
import time
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import make_response, render_template_string
from artifact_host.storage import InvalidUpload
from artifact_host import storage
from artifact_host.isolation import resource_paths

REMEMBER = 30 * 86400
RESOURCE_LIFETIME = 3600


def password_fields(password):
    if not isinstance(password, str) or (password and not 8 <= len(password) <= 128):
        raise InvalidUpload('Read password must be 8–128 characters')
    return (generate_password_hash(password, method='scrypt'), secrets.token_hex(32)) if password else (None, None)


def cookie_name(row):
    return 'artifact_read_' + row['id']


def signature(row, expiry):
    return hmac.new(row['read_cookie_key'].encode(), (row['id'] + ':' + expiry).encode(), hashlib.sha256).hexdigest()


def resource_grant(row):
    expiry = str(int(time.time()) + RESOURCE_LIFETIME)
    signed = hmac.new(row['read_cookie_key'].encode(), ('resource:' + row['id'] + ':' + expiry).encode(), hashlib.sha256).hexdigest()
    return expiry + '.' + signed


def valid_resource_grant(row, value):
    if not row['read_password_hash'] or not isinstance(value, str):
        return False
    expiry, _, signed = value.partition('.')
    if not (expiry.isascii() and expiry.isdigit() and len(expiry) <= 12 and time.time() < int(expiry) <= time.time() + RESOURCE_LIFETIME + 60):
        return False
    expected = hmac.new(row['read_cookie_key'].encode(), ('resource:' + row['id'] + ':' + expiry).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signed, expected)


def unlocked(row, cookies):
    if not row['read_password_hash']:
        return True
    value = cookies.get(cookie_name(row), '')
    expiry, _, signed = value.partition('.')
    return (expiry.isascii() and expiry.isdigit() and len(expiry) <= 12
            and time.time() < int(expiry) <= time.time() + REMEMBER + 60
            and hmac.compare_digest(signed, signature(row, expiry)))


def unlock_cookie(response, row, paths, value=None):
    expiry = str(int(time.time()) + REMEMBER) if value is None else value.partition('.')[0]
    if value is None:
        value = expiry + '.' + signature(row, expiry)
    # Only top-level document navigation uses this cookie. Bundle resources use
    # short-lived artifact-scoped grants and do not need any browser cookies.
    name = cookie_name(row)
    response.delete_cookie(name, path='/', secure=True, httponly=True, samesite='Lax')
    for path in paths:
        response.set_cookie(name, value, max_age=max(0, int(expiry) - int(time.time())),
                            expires=int(expiry), secure=True, httponly=True, samesite='Lax', path=path)
    response.read_cookies_written = getattr(response, 'read_cookies_written', set()) | {row['id']}


def migrate_cookies(response, cookies, readable):
    # A request header fits at most about 30 old root cookies. Migrate up to 20
    # at a time to bound response fields, preserving each signed expiry.
    written = getattr(response, 'read_cookies_written', set())
    names = [name for name in cookies if name.startswith('artifact_read_')
             and storage.ID_PATTERN.fullmatch(name[len('artifact_read_'):])][:20]
    if not names:
        return
    try:
        with storage.database() as connection:
            for name in names:
                identifier = name[len('artifact_read_'):]
                if identifier in written:
                    continue
                row = connection.execute('SELECT artifacts.*, aliases.slug AS short_slug FROM artifacts LEFT JOIN aliases ON aliases.artifact_id=artifacts.id WHERE artifacts.id=?', (identifier,)).fetchone()
                if row is not None and row['read_password_hash'] and not row['revoked'] and (row['expires'] is None or row['expires'] > time.time()) and unlocked(row, cookies):
                    paths = resource_paths(row, row['short_slug'] if readable else None)
                    unlock_cookie(response, row, paths, value=cookies[name])
                else:
                    response.delete_cookie(name, path='/', secure=True, httponly=True, samesite='Lax')
    except sqlite3.Error:
        # Migration is optional maintenance; do not replace an existing error
        # response when the database itself is unavailable.
        return


def check_password(row, password):
    return isinstance(password, str) and len(password) <= 128 and check_password_hash(row['read_password_hash'], password)


def password_page(failed=False, status=401):
    response = make_response(render_template_string('''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问密码</title><style>
    :root{color-scheme:light dark;font-family:system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;background:light-dark(#fff,#191919);color:light-dark(#37352f,#d4d4d4)}main{width:min(360px,calc(100vw - 48px));padding:32px 0}h1{font-size:26px}p{line-height:1.7;color:light-dark(#757575,#aaa)}input,button{box-sizing:border-box;width:100%;min-height:44px;font:inherit;border:1px solid #8885;border-radius:6px;padding:10px 14px}button{margin-top:14px;cursor:pointer}label{display:block;margin:24px 0 10px}.error{color:light-dark(#b42318,#ffb4ab)}
    </style><main><h1>此文件需要访问密码</h1><p>验证后，此浏览器将记住 30 天。密码变更后需要重新验证。</p>{% if failed %}<p class="error" role="alert">密码不正确，请重试。</p>{% endif %}<form method="post"><label for="password">访问密码</label><input id="password" name="password" type="password" required autocomplete="current-password" autofocus><button>打开文件</button></form></main></html>''', failed=failed), status)
    return response
