"""Optional per-artifact passwords and host-only browser unlock cookies."""
import hashlib
import hmac
import secrets
import time
from werkzeug.security import generate_password_hash, check_password_hash
from flask import make_response, render_template_string
from artifact_host.storage import InvalidUpload

REMEMBER = 30 * 86400


def password_fields(password):
    if not isinstance(password, str) or (password and not 8 <= len(password) <= 128):
        raise InvalidUpload('Read password must be 8–128 characters')
    return (generate_password_hash(password, method='scrypt'), secrets.token_hex(32)) if password else (None, None)


def cookie_name(row):
    return 'artifact_read_' + row['id']


def signature(row, expiry):
    return hmac.new(row['read_cookie_key'].encode(), (row['id'] + ':' + expiry).encode(), hashlib.sha256).hexdigest()


def unlocked(row, cookies):
    if not row['read_password_hash']:
        return True
    value = cookies.get(cookie_name(row), '')
    expiry, _, signed = value.partition('.')
    return (expiry.isascii() and expiry.isdigit() and len(expiry) <= 12
            and time.time() < int(expiry) <= time.time() + REMEMBER + 60
            and hmac.compare_digest(signed, signature(row, expiry)))


def unlock_cookie(response, row):
    expiry = str(int(time.time()) + REMEMBER)
    # Opaque sandbox documents load relative assets as cross-site requests.
    # None is needed for those requests; the cookie stays Secure + HttpOnly.
    # Password POSTs separately enforce the exact read Origin.
    response.set_cookie(cookie_name(row), expiry + '.' + signature(row, expiry),
                        max_age=REMEMBER, secure=True, httponly=True, samesite='None', path='/')


def check_password(row, password):
    return isinstance(password, str) and len(password) <= 128 and check_password_hash(row['read_password_hash'], password)


def password_page(failed=False, status=401):
    response = make_response(render_template_string('''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问密码</title><style>
    :root{color-scheme:light dark;font-family:system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;background:light-dark(#fff,#191919);color:light-dark(#37352f,#d4d4d4)}main{width:min(360px,calc(100vw - 48px));padding:32px 0}h1{font-size:26px}p{line-height:1.7;color:light-dark(#757575,#aaa)}input,button{box-sizing:border-box;width:100%;min-height:44px;font:inherit;border:1px solid #8885;border-radius:6px;padding:10px 14px}button{margin-top:14px;cursor:pointer}label{display:block;margin:24px 0 10px}.error{color:light-dark(#b42318,#ffb4ab)}
    </style><main><h1>此文件需要访问密码</h1><p>验证后，此浏览器将记住 30 天。密码变更后需要重新验证。</p>{% if failed %}<p class="error" role="alert">密码不正确，请重试。</p>{% endif %}<form method="post"><label for="password">访问密码</label><input id="password" name="password" type="password" maxlength="128" required autocomplete="current-password" autofocus><button>打开文件</button></form></main></html>''', failed=failed), status)
    return response
