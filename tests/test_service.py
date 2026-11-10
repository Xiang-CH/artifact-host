import os,tempfile,unittest,io,zipfile,time
os.environ['ARTIFACT_DATA']=tempfile.mkdtemp()
from artifact_host.app import private_app,public_app,token
class Service(unittest.TestCase):
 def test_flow(self):
  p=private_app.test_client(); v=public_app.test_client(); _,key=token(); h={'Authorization':'Bearer '+key}
  self.assertEqual(p.post('/api/artifacts',data=b'x').status_code,401)
  r=p.post('/api/artifacts?name=README.md',data=b'# Report\n<script>alert(1)</script>',headers=h); self.assertEqual(r.status_code,201)
  ident=r.json['id']; self.assertIn('readme-', r.json['slug']); self.assertEqual(v.get('/s/'+ident+'/'+r.json['slug']+'/').status_code,200); page=v.get('/s/'+ident+'/'); self.assertEqual(page.status_code,200); self.assertNotIn(b'<script>',page.data)
  _,other=token(); self.assertEqual(p.delete('/api/artifacts/'+ident,headers={'Authorization':'Bearer '+other}).status_code,403)
  self.assertEqual(p.delete('/api/artifacts/'+ident,headers=h).status_code,204); self.assertEqual(v.get('/s/'+ident+'/').status_code,404)
  r=p.post('/api/artifacts?name=index.html',data=b'<script>1</script>',headers=h); page=v.get('/s/'+r.json['id']+'/'); self.assertIn('sandbox allow-scripts',page.headers['Content-Security-Policy'])
  r=p.post('/api/artifacts?name=x&expires=1',data=b'x',headers=h); self.assertEqual(v.get('/s/'+r.json['id']+'/').status_code,404)
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:z.writestr('../escape','oops')
  self.assertEqual(p.post('/api/artifacts?bundle=1',data=b.getvalue(),headers=h).status_code,400)
if __name__=='__main__':unittest.main()
