"""Standalone tests must never initialize or clean an existing service directory."""
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[1]


class TestDataSafety(unittest.TestCase):
    def check_process(self, preload):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'existing-service';root.mkdir()
            (root/'artifact').mkdir();(root/'artifact'/'sentinel').write_bytes(b'keep existing data')
            with sqlite3.connect(root/'state.db') as connection:
                connection.executescript('CREATE TABLE tokens(id TEXT PRIMARY KEY, hash TEXT, owner INTEGER); CREATE TABLE artifacts(id TEXT PRIMARY KEY, owner TEXT, entry TEXT, size INTEGER, expires REAL, revoked INTEGER DEFAULT 0);')
                connection.execute("INSERT INTO tokens VALUES('existing-token','existing-hash',1)")
            def snapshot():
                return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            before=snapshot()
            env=dict(os.environ,ARTIFACT_DATA=str(root))
            for name in ('PUBLIC_URL','PRIVATE_ORIGIN','PRIVATE_HOSTS','READABLE_URLS','PUBLIC_PATH'):
                env.pop(name,None)
            if preload:
                command=[sys.executable,'-c',"import sys;sys.path.insert(0,'tests');import artifact_host.storage;import test_isolation"]
            else:
                command=[sys.executable,'-m','unittest','discover','-s','tests','-p','test_isolation.py']
            result=subprocess.run(command,cwd=REPO,env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(snapshot(),before)
            if preload:
                self.assertNotEqual(result.returncode,0)
                self.assertIn('Tests require their own data root',result.stderr)
            else:
                self.assertEqual(result.returncode,0,result.stderr)

    def test_standalone_isolation_tests_preserve_existing_data(self):
        self.check_process(False)

    def test_preloaded_storage_fails_before_touching_existing_data(self):
        self.check_process(True)
