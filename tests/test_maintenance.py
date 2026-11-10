import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import test_service
from artifact_host import storage
from artifact_host.maintenance import backup,restore,backfill

class Maintenance(unittest.TestCase):
    setUp = test_service.Service.setUp
    headers = test_service.Service.headers
    upload = test_service.Service.upload
    get = test_service.Service.get
    # Inherit helpers only, not duplicate the entire suite.
    def test_backup_restore_and_tamper(self):
        value=self.upload('report.md',b'# Backup survives').json
        with tempfile.TemporaryDirectory() as temporary:
            snapshot=Path(temporary)/'snapshot';restored=Path(temporary)/'restored'
            backup(snapshot)
            self.private.delete('/api/artifacts/'+value['id'],headers=self.headers())
            restore(snapshot,restored)
            with patch.object(storage,'ROOT',restored):
                result=self.get(value);self.assertEqual(result.status_code,200);self.assertIn(b'Backup survives',result.data);result.close()
                self.assertEqual(self.private.get('/api/artifacts',headers=self.headers()).status_code,200)
            (snapshot/value['id']/'report.md').write_text('changed')
            with self.assertRaises(ValueError):restore(snapshot,Path(temporary)/'corrupt')

    def test_legacy_markdown_backfill(self):
        value=self.upload('legacy.md',b'# Old report').json
        import shutil
        shutil.rmtree(storage.ROOT/value['id']/'.artifact-render')
        self.assertEqual(self.get(value).mimetype,'application/octet-stream')
        backfill()
        self.assertEqual(self.get(value).mimetype,'text/html')
        self.assertIn(b'<h1>Old report</h1>',self.get(value).data)
