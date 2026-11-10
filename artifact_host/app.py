import os, sqlite3, secrets, hashlib, json, io, zipfile, shutil, time
from pathlib import Path, PurePosixPath
from flask import Flask, request, abort, jsonify, send_file, Response
import markdown, bleach
ROOT = Path(os.environ.get('ARTIFACT_DATA', './data')).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
LIMIT = int(os.environ.get('UPLOAD_LIMIT', 50*1024*1024))
BUDGET = int(os.environ.get('STORAGE_BUDGET', 3*1024**3))
PUBLIC = os.environ.get('PUBLIC_URL', 'http://127.0.0.1:8792').rstrip('/')
def db():
    c = sqlite3.connect(ROOT/'state.db', timeout=60)
    c.row_factory = sqlite3.Row
    return c
with db() as c:
    c.executescript('CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY, hash TEXT, owner INTEGER); CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, owner TEXT, entry TEXT, size INTEGER, expires REAL, revoked INTEGER DEFAULT 0);')
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def token(owner=False):
    key=secrets.token_urlsafe(32); ident=secrets.token_hex(8)
    with db() as c: c.execute('INSERT INTO tokens VALUES(?,?,?)',(ident,digest(key),int(owner)))
    return ident,key
def auth():
    with db() as c: row=c.execute('SELECT * FROM tokens WHERE hash=?',(digest(request.headers.get('Authorization','').removeprefix('Bearer ')),)).fetchone()
    if not row: abort(401)
    return row
def safe(name):
    p=PurePosixPath(name)
    if not name or '\\' in name or p.is_absolute() or any(x in ('..','.') for x in name.split('/')) or any(ord(x)<32 for x in name): abort(400)
    return str(p)
def create_app(private=False):
    app=Flask(__name__); app.config['MAX_CONTENT_LENGTH']=LIMIT
    @app.after_request
    def headers(r):
        r.headers['Cache-Control']='no-store'
        r.headers['Referrer-Policy']='no-referrer'
        r.headers['X-Content-Type-Options']='nosniff'
        r.headers['Content-Security-Policy']="sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; frame-src 'self'; base-uri 'none'; form-action 'none'"
        return r
    @app.get('/health')
    def health(): return {'ok':True}
    if private:
        @app.get('/')
        def dashboard():
            return Response('''<h1>Artifact management</h1><p>Links can be forwarded. Downloads cannot be recalled.</p><input id="key" type="password" placeholder="Owner token"><button onclick="load()">List artifacts</button><pre id="out"></pre><script>async function load(){out.textContent=JSON.stringify(await (await fetch('/api/artifacts',{headers:{Authorization:'Bearer '+key.value}})).json(),null,2)}</script>''',mimetype='text/html')
        @app.get('/api/artifacts')
        def listing():
            a=auth()
            with db() as c: rows=c.execute('SELECT * FROM artifacts'+('' if a['owner'] else ' WHERE owner=?'),() if a['owner'] else (a['id'],)).fetchall()
            return jsonify([dict(r) for r in rows])
        @app.route('/api/tokens',methods=['GET','POST'])
        def tokens():
            if not auth()['owner']: abort(403)
            if request.method=='POST':
                ident,key=token(); return {'id':ident,'token':key}
            with db() as c: return jsonify([dict(r) for r in c.execute('SELECT id,owner FROM tokens')])
        @app.delete('/api/tokens/<ident>')
        def revoke_token(ident):
            if not auth()['owner']: abort(403)
            with db() as c: c.execute('DELETE FROM tokens WHERE id=? AND owner=0',(ident,))
            return '',204
        @app.post('/api/artifacts')
        def upload():
            a=auth(); ident=secrets.token_urlsafe(32); dest=ROOT/ident
            # Serialize admission, extraction and commit across all workers.
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                used=c.execute('SELECT coalesce(sum(size),0) FROM artifacts').fetchone()[0]
                dest.mkdir(); size=0
                try:
                    raw=request.get_data(cache=False)
                    if request.args.get('bundle')=='1':
                        z=zipfile.ZipFile(io.BytesIO(raw)); files=z.infolist()
                        if len(files)>2000: abort(413)
                        for f in files:
                            name=safe(f.filename.rstrip('/'))
                            if (f.external_attr>>16)&0o170000 == 0o120000: abort(400)
                            if f.is_dir(): continue
                            size+=f.file_size
                            if size>LIMIT or used+size>BUDGET: abort(413)
                            path=dest/name; path.parent.mkdir(parents=True,exist_ok=True)
                            with z.open(f) as src, path.open('wb') as out: shutil.copyfileobj(src,out)
                        entry='index.html' if (dest/'index.html').is_file() else 'README.md'
                    else:
                        entry=safe(request.args.get('name','download.bin')); size=len(raw)
                        if used+size>BUDGET: abort(413)
                        p=dest/entry; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(raw)
                    if not (dest/entry).is_file(): abort(400)
                    expiry=float(request.args['expires']) if 'expires' in request.args else None
                    c.execute('INSERT INTO artifacts(id,owner,entry,size,expires) VALUES(?,?,?,?,?)',(ident,a['id'],entry,size,expiry))
                except BaseException:
                    shutil.rmtree(dest,ignore_errors=True); raise
            return {'id':ident,'url':PUBLIC+'/s/'+ident+'/'},201
        @app.delete('/api/artifacts/<ident>')
        def delete(ident):
            a=auth()
            with db() as c:
                c.execute('BEGIN IMMEDIATE'); r=c.execute('SELECT * FROM artifacts WHERE id=?',(ident,)).fetchone()
                if not r: abort(404)
                if not a['owner'] and r['owner']!=a['id']: abort(403)
                c.execute('UPDATE artifacts SET revoked=1 WHERE id=?',(ident,))
                shutil.rmtree(ROOT/ident,ignore_errors=True)
                c.execute('UPDATE artifacts SET size=0 WHERE id=?',(ident,))
            return '',204
    else:
        @app.get('/s/<ident>/',defaults={'name':None})
        @app.get('/s/<ident>/<path:name>')
        def serve(ident,name):
            with db() as c: r=c.execute('SELECT * FROM artifacts WHERE id=?',(ident,)).fetchone()
            if not r or r['revoked'] or (r['expires'] is not None and r['expires']<=time.time()): abort(404)
            p=ROOT/ident/safe(name or r['entry'])
            if not p.is_file(): abort(404)
            ext=p.suffix.lower()
            if ext=='.md':
                content=markdown.markdown(p.read_text(),extensions=['tables','fenced_code','codehilite'])
                content=bleach.clean(content,tags=set(bleach.sanitizer.ALLOWED_TAGS)|{'h1','h2','h3','h4','h5','h6','p','pre','code','div','span','table','thead','tbody','tr','td','th','img','hr','br'},attributes={'*':['class'],'a':['href','title'],'img':['src','alt']},protocols=['https','http'])
                from pygments.formatters import HtmlFormatter
                return Response('<style>'+HtmlFormatter().get_style_defs()+ '</style>'+content,mimetype='text/html')
            types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.pdf':'application/pdf'}
            return send_file(p,mimetype=types.get(ext,'application/octet-stream'),as_attachment=ext not in types,download_name=p.name)
    return app
private_app=create_app(True)
public_app=create_app(False)
if __name__=='__main__':
    import sys
    if sys.argv[1:] == ['init']: print(json.dumps(dict(zip(('id','token'),token(True)))))
