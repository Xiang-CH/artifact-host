"""Run separately with agent-browser installed; only synthetic local credentials."""
import base64
import io
import json
from pathlib import Path
import subprocess
import zipfile
from test_e2e import EndToEnd

SESSION = 'artifact-security-regression'
def browser(*args):
    result = subprocess.run(['agent-browser','--session',SESSION,*args],capture_output=True,text=True,timeout=30)
    if result.returncode:
        # Report the tool's diagnostic without echoing arguments/passwords.
        raise RuntimeError('agent-browser '+args[0]+' failed: '+(result.stderr or result.stdout).strip())
    return result.stdout.strip()
def evaluate(code):
    value = json.loads(browser('eval','(async()=>JSON.stringify(await ('+code+')))()'))
    return json.loads(value) if isinstance(value,str) else value

def main():
    EndToEnd.setUpClass()
    case = EndToEnd()
    result = {}
    try:
        png=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aX1cAAAAASUVORK5CYII=')
        html='''<!doctype html><h1>Sandbox fixture</h1><img id="asset" src="pixel.png"><button id="interactive" onclick="this.textContent='Clicked'">Click me</button><script>window.checks={inline:true};try{localStorage.setItem('x','y');checks.storageBlocked=false}catch(e){checks.storageBlocked=true}try{document.cookie='x=y';checks.cookiesBlocked=false}catch(e){checks.cookiesBlocked=true}fetch('/health').then(()=>checks.fetchBlocked=false).catch(()=>checks.fetchBlocked=true);</script><script src="app.js"></script>'''
        def upload(entries):
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w') as archive:
                for name,data in entries:archive.writestr(name,data)
            status,body,_=case.request('POST','/api/artifacts?bundle=1',buffer.getvalue(),EndToEnd.owner)
            assert status==201
            return json.loads(body)
        artifact=upload([('index.html',html),('app.js','window.checks.externalScript=true;'),('pixel.png',png)])
        browser('open',artifact['url'])
        browser('wait','--fn','window.checks && window.checks.fetchBlocked && window.checks.externalScript')
        browser('wait','--fn','document.querySelector("#asset").naturalWidth===1')
        result['sandbox']=evaluate('window.checks')
        result['relative_image']=evaluate('document.querySelector("#asset").naturalWidth')==1
        browser('click','#interactive')
        result['interactive']=evaluate('document.querySelector("#interactive").textContent')=='Clicked'
        markdown=upload([('README.md','# Browser Markdown\n\n![Pixel](pixel.png)\n<script>window.xss=true</script>'),('pixel.png',png),('private.js','window.privateMarker=true;')])
        browser('open',markdown['url'])
        browser('wait','--fn','document.querySelector("img").naturalWidth === 1')
        browser('select','#document-theme','dark')
        browser('reload')
        browser('wait','--fn','document.documentElement.dataset.theme==="dark"')
        result['markdown_theme_persisted']=True
        result['markdown']=evaluate('({heading:document.querySelector("h1").textContent,image:document.querySelector("img").naturalWidth,xss:!!window.xss})')
        # Existing upload becomes password-protected, including relative assets.
        from urllib.request import Request, urlopen
        access_path = EndToEnd.api + '/api/artifacts/' + markdown['id'] + '/access'
        with urlopen(Request(access_path, data=json.dumps({'password':'browser-test-password'}).encode(), headers={'Authorization':'Bearer '+EndToEnd.owner,'Content-Type':'application/json'}, method='POST')) as response:
            assert response.status == 200
        browser('open',markdown['url'])
        browser('wait','--fn','!!document.querySelector("#password")')
        browser('fill','#password','browser-test-password')
        browser('click','form button')
        browser('wait','--fn','document.querySelector("img")?.naturalWidth === 1')
        browser('reload')
        browser('wait','--fn','document.querySelector("img")?.naturalWidth === 1')
        result['password_remembered_with_sandboxed_assets']=True
        # A protected document can load its own classic script.
        browser('eval', "const own=document.createElement('script');own.src='private.js';document.body.append(own);true")
        browser('wait','--fn','window.privateMarker===true')
        result['protected_own_script']=True
        private_url = markdown['url'] + 'private.js'
        # An unrelated public artifact must not execute that same resource.
        browser('open',artifact['url'])
        browser('eval', "window.crossDone=false;const cross=document.createElement('script');cross.src="+json.dumps(private_url)+";cross.onload=cross.onerror=()=>window.crossDone=true;document.body.append(cross);true")
        browser('wait','--fn','window.crossDone===true')
        assert evaluate('window.privateMarker===undefined')
        result['cross_artifact_script_blocked']=True
        # An external origin has no artifact CSP: the server must still refuse.
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        external_html=('<!doctype html><script src="'+private_url+'" onerror="window.resourceDenied=true"></script>').encode()
        class ExternalPage(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(external_html)
            def log_message(self,*args): pass
        external=ThreadingHTTPServer(('127.0.0.1',0),ExternalPage)
        threading.Thread(target=external.serve_forever,daemon=True).start()
        try:
            browser('open','http://127.0.0.1:'+str(external.server_port)+'/')
            browser('wait','--fn','window.resourceDenied===true')
            assert evaluate('window.privateMarker===undefined')
            result['external_script_inclusion_blocked']=True
        finally:
            external.shutdown();external.server_close()
        # The legacy URL remains functional after unlocking through its alias.
        legacy=EndToEnd.public+'/s/'+markdown['id']+'/'+markdown['slug']+'/'
        browser('open',legacy)
        browser('wait','--fn','document.querySelector("img")?.naturalWidth===1')
        result['protected_legacy_assets']=True
        html_access=EndToEnd.api+'/api/artifacts/'+artifact['id']+'/access'
        with urlopen(Request(html_access,data=json.dumps({'password':'a'*127+'😀'}).encode(),headers={'Authorization':'Bearer '+EndToEnd.owner,'Content-Type':'application/json'},method='POST')) as response:
            assert response.status==200
        browser('open',artifact['url'])
        browser('wait','--fn','!!document.getElementById("password")')
        browser('fill','#password','a'*127+'😀')
        browser('click','form button')
        browser('wait','--fn','window.checks?.externalScript && document.querySelector("#asset").naturalWidth===1')
        browser('click','#interactive')
        assert evaluate('document.getElementById("interactive").textContent==="Clicked" && window.checks.cookiesBlocked')
        result['protected_html_interactive']=True
        browser('open',EndToEnd.api)
        browser('fill','#key',EndToEnd.owner)
        browser('click','#load')
        browser('wait','--fn','document.querySelectorAll("#artifacts p").length === 2')
        # Release a stale save after the user has opened a different editor.
        race_check = evaluate("""(async()=>{
          const originalFetch=window.fetch;
          const originalLoad=load;
          let release, resolveRefresh;
          let refreshCount=0;
          load=async()=>{await originalLoad();refreshCount++;resolveRefresh?.();};
          window.fetch=(url,options)=>String(url).endsWith('/access') && options?.method==='POST'
            ? new Promise((resolve,reject)=>{release=code=>code===200?originalFetch(url,options).then(resolve,reject):resolve(new Response(JSON.stringify({error:'old save failed'}),{status:code,headers:{'Content-Type':'application/json'}}));})
            : originalFetch(url,options);
          try {
            for (const status of [200,400]) {
              openReadAccess(files[0]);
              element('read-private').checked=false;updateReadInput();
              const before=refreshCount;
              const refreshed=new Promise(resolve=>{resolveRefresh=resolve;});
              element('read-access-form').requestSubmit(element('access-save'));
              element('access-cancel').click();
              openReadAccess(files[1]);
              element('read-private').checked=true;updateReadInput();element('read-password').value='second-edit-password';
              release(status);
              if (status===200) await refreshed; else await new Promise(resolve=>setTimeout(resolve,0));
              if (status===200 && (refreshCount!==before+1 || files[0].password_protected!==false)) return false;
              if (status===400 && refreshCount!==before) return false;
              if (!element('read-access').open || accessFile.id!==files[1].id || element('read-password').value!=='second-edit-password' || element('access-error').textContent!=='' || element('access-save').disabled) return false;
              closeReadAccess();
            }
            return true;
          } finally {window.fetch=originalFetch;load=originalLoad;closeReadAccess();}
        })()""")
        assert race_check
        result['stale_access_save_does_not_mutate_new_editor']=True
        result['canceled_save_refreshes_access_metadata']=True
        browser('eval', 'document.querySelector("#token-details summary").scrollIntoView({block:"center"})')
        browser('click','#token-details summary')
        browser('wait','--fn','document.getElementById("token-details").open')
        browser('eval', 'document.querySelector("#new-token").scrollIntoView({block:"center"})')
        browser('click','#new-token')
        browser('wait','--fn','document.querySelectorAll("#tokens p").length === 2')
        result['token_created_once']=evaluate('document.querySelector("#status").textContent.startsWith("请立即保存")')
        browser('open',EndToEnd.api)
        browser('wait','--fn','document.querySelectorAll("#artifacts p").length === 2')
        result['dashboard_no_raw_token_storage']=evaluate('document.querySelector("#key").value==="" && document.cookie===""')
        browser('select','#theme','dark')
        browser('open',EndToEnd.api)
        browser('wait','--fn','document.documentElement.dataset.theme==="dark" && document.querySelectorAll("#artifacts p").length===2')
        browser('eval', 'document.querySelector("#token-details summary").scrollIntoView({block:"center"})')
        browser('click','#token-details summary')
        browser('wait','--fn','document.getElementById("token-details").open')
        browser('click','#artifacts .file-row:last-child .row-actions button:first-of-type')
        browser('wait','--fn','document.getElementById("read-access").open')
        browser('check','#read-private')
        browser('fill','#read-password','a'*127+'😀')
        browser('click','#read-access-form button.primary')
        browser('wait','--fn','!document.getElementById("read-access").open')
        browser('open',markdown['url'])
        browser('wait','--fn','!!document.getElementById("password")')
        browser('fill','#password','a'*127+'😀')
        browser('click','form button')
        browser('wait','--fn','document.querySelector("img")?.naturalWidth===1')
        result['unicode_password_dashboard_and_unlock']=True
        browser('open',EndToEnd.api)
        browser('wait','--fn','document.querySelectorAll("#artifacts p").length===2')
        browser('eval', 'document.querySelector("#token-details summary").scrollIntoView({block:"center"})')
        browser('click','#token-details summary')
        browser('click','#artifacts .file-row:last-child .row-actions button:first-of-type')
        browser('wait','--fn','document.getElementById("read-access").open')
        browser('uncheck','#read-private')
        browser('click','#read-access-form button.primary')
        browser('wait','--fn','!document.getElementById("read-access").open')
        result['dashboard_access_dialog']=True
        browser('click','#tokens button')
        browser('dialog','accept')
        browser('wait','--fn','document.querySelectorAll("#tokens p").length === 1')
        result['token_revoked']=True
        browser('click','#artifacts .file-row:first-child button:last-child')
        browser('dialog','accept')
        browser('click','#archive-nav')
        browser('wait','--fn','document.querySelector("#artifacts").textContent.includes("已撤销")')
        result['artifact_revoked']=True
        browser('click','#forget')
        browser('wait','--fn','document.querySelector("#connection").textContent==="尚未连接" && document.querySelectorAll("#artifacts p").length===0')
        result['forgotten']=evaluate('document.querySelector("#key").value==="" && document.querySelectorAll("#artifacts p").length===0')
        assert all(result['sandbox'].values()) and all(result[k] for k in ('relative_image','interactive','token_created_once','dashboard_no_raw_token_storage','token_revoked','artifact_revoked','forgotten')), json.dumps(result,ensure_ascii=False)
        assert result['markdown']=={'heading':'Browser Markdown','image':1,'xss':False}
        destination=Path(__file__).resolve().parents[1]/'docs/security-browser-check.json'
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(result,indent=2)+'\n')
        print('Browser security checks passed; evidence: docs/security-browser-check.json')
    finally:
        try:
            browser('close')
        finally:
            EndToEnd.tearDownClass()

if __name__=='__main__':main()
