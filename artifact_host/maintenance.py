"""Coherent local backups and restore into a new, offline data directory."""
import argparse
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path
from artifact_host import storage

def tree_files(directory):
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('Backup trees cannot contain symlinks')
        if path.is_file():
            yield path

def checksum(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            value.update(block)
    return value.hexdigest()

def backup(destination):
    destination = Path(destination).absolute()
    if destination == storage.ROOT or storage.ROOT in destination.parents:
        raise ValueError('Backup destination must be outside data directory')
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        with (storage.ROOT / '.upload.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with storage.database() as barrier:
                barrier.execute('BEGIN IMMEDIATE')
                # Separate read connection avoids backing up an uncommitted write transaction.
                source = sqlite3.connect(storage.ROOT / 'state.db')
                target = sqlite3.connect(destination / 'state.db')
                try:
                    source.backup(target)
                finally:
                    source.close(); target.close()
                for path in tree_files(storage.ROOT):
                    relative = path.relative_to(storage.ROOT)
                    if relative.parts[0] in ('.staging', '.upload.lock') or relative.parts[0].startswith('state.db'):
                        continue
                    output = destination / relative
                    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copyfile(path, output)
                manifest = {str(p.relative_to(destination)): checksum(p) for p in tree_files(destination)}
                (destination / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
        for path in tree_files(destination):
            path.chmod(0o600)
    except BaseException:
        shutil.rmtree(destination)
        raise

def restore(source, destination):
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if destination.exists() or destination == storage.ROOT:
        raise ValueError('Restore only into a new, offline data directory')
    manifest = json.loads((source / 'manifest.json').read_text())
    actual = {str(p.relative_to(source)): checksum(p) for p in tree_files(source) if p.name != 'manifest.json' or p.parent != source}
    if manifest != actual:
        raise ValueError('Backup checksum mismatch')
    connection = sqlite3.connect('file:' + str(source / 'state.db') + '?mode=ro', uri=True)
    try:
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Backup database is corrupt')
    finally:
        connection.close()
    destination.mkdir(mode=0o700, parents=True)
    try:
        for name in manifest:
            storage.safe_path(name)
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
            target.chmod(0o600)
    except BaseException:
        shutil.rmtree(destination)
        raise

def backfill(refresh=False):
    """Prepare legacy Markdown caches offline before restarting an upgraded service."""
    from artifact_host.rendering import CACHE_DIR, render_bundle
    with (storage.ROOT / '.upload.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with storage.database() as connection:
            connection.execute('BEGIN IMMEDIATE')
            rows = connection.execute('SELECT * FROM artifacts WHERE revoked=0').fetchall()
            for row in rows:
                if not storage.ID_PATTERN.fullmatch(row['id']):
                    raise ValueError('Invalid stored artifact ID')
                directory = storage.ROOT / row['id']
                if directory.is_symlink():
                    raise ValueError('Artifact directory is a symlink')
                list(tree_files(directory))  # Reject nested symlinks too.
                if (directory / CACHE_DIR).exists() and not refresh:
                    continue
                before = storage.tree_usage(directory)
                capacity = storage.BUDGET - storage.disk_usage() + before - 16384
                pending = directory / '.artifact-render-next'
                if pending.exists(): shutil.rmtree(pending)
                try:
                    render_bundle(directory, capacity, cache_dir='.artifact-render-next')
                except BaseException:
                    shutil.rmtree(pending, ignore_errors=True)
                    raise
                if pending.exists():
                    if (directory / CACHE_DIR).exists(): shutil.rmtree(directory / CACHE_DIR)
                    pending.rename(directory / CACHE_DIR)
                size = storage.tree_usage(directory)
                if size > capacity:
                    raise ValueError('Legacy rendering exceeds storage quota')
                connection.execute('UPDATE artifacts SET size=? WHERE id=?', (size, row['id']))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('backfill').add_argument('--refresh', action='store_true')
    p = sub.add_parser('backup'); p.add_argument('destination')
    p = sub.add_parser('restore'); p.add_argument('source'); p.add_argument('destination')
    args = parser.parse_args()
    try:
        if args.command == 'backup': backup(args.destination)
        elif args.command == 'backfill': backfill(refresh=args.refresh)
        else: restore(args.source, args.destination)
    except Exception:
        parser.exit(1, 'Backup/restore failed. Check paths, permissions, integrity, and upload activity.\n')
    print('Maintenance complete')

if __name__ == '__main__': main()
