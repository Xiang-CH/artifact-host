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
    result = subprocess.run(['agent-browser','--session',SESSION,*args],check=True,capture_output=True,text=True,timeout=30)
    return result.stdout.strip()
def evaluate(code):
    value = json.loads(browser('eval','JSON.stringify('+code+')'))
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
        result['sandbox']=evaluate('window.checks')
        result['relative_image']=evaluate('document.querySelector("#asset").naturalWidth')==1
        browser('click','#interactive')
        result['interactive']=evaluate('document.querySelector("#interactive").textContent')=='Clicked'
        markdown=upload([('README.md','# Browser Markdown\n\n![Pixel](pixel.png)\n<script>window.xss=true</script>'),('pixel.png',png)])
        browser('open',markdown['url'])
        browser('wait','--fn','document.querySelector("img").naturalWidth === 1')
        result['markdown']=evaluate('({heading:document.querySelector("h1").textContent,image:document.querySelector("img").naturalWidth,xss:!!window.xss})')
        browser('open',EndToEnd.api)
        browser('fill','#key',EndToEnd.owner)
        browser('click','#load')
        browser('wait','--fn','document.querySelectorAll("#artifacts p").length === 2')
        browser('click','#new-token')
        browser('wait','--fn','document.querySelectorAll("#tokens p").length === 2')
        result['token_created_once']=evaluate('document.querySelector("#status").textContent.startsWith("Save this token now")')
        result['dashboard_no_persistence']=evaluate('localStorage.length===0 && document.cookie===""')
        browser('click','#tokens button')
        browser('wait','--fn','document.querySelectorAll("#tokens p").length === 1')
        result['token_revoked']=True
        browser('click','#artifacts button')
        browser('dialog','accept')
        browser('wait','--fn','document.querySelector("#artifacts").textContent.includes("revoked")')
        result['artifact_revoked']=True
        browser('click','#forget')
        result['forgotten']=evaluate('document.querySelector("#key").value==="" && document.querySelectorAll("#artifacts p").length===0')
        assert all(result['sandbox'].values()) and all(result[k] for k in ('relative_image','interactive','token_created_once','dashboard_no_persistence','token_revoked','artifact_revoked','forgotten'))
        assert result['markdown']=={'heading':'Browser Markdown','image':1,'xss':False}
        destination=Path(__file__).resolve().parents[1]/'docs/security-browser-check.json'
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(result,indent=2)+'\n')
        print('Browser security checks passed; evidence: docs/security-browser-check.json')
    finally:
        browser('close')
        EndToEnd.tearDownClass()

if __name__=='__main__':main()
