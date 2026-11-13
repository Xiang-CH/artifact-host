"""Disk and SQLite boundaries shared by the private and public applications."""
import hashlib
import math
import os
import re
import secrets
import sqlite3
import stat
import struct
import time
import unicodedata
import zipfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(os.environ.get('ARTIFACT_DATA', './data')).absolute()
LIMIT = int(os.environ.get('UPLOAD_LIMIT', 50 * 1024 * 1024))
BUDGET = int(os.environ.get('STORAGE_BUDGET', 3 * 1024**3))
MAX_FILES = 2000
ID_PATTERN = re.compile(r'[A-Za-z0-9_-]{43}\Z')

class InvalidUpload(ValueError):
    pass

class QuotaExceeded(InvalidUpload):
    pass

@contextmanager
def database():
    connection = sqlite3.connect(ROOT / 'state.db', timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()

def initialize():
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if ROOT.is_symlink():
        raise RuntimeError('Data root must not be a symlink')
    ROOT.chmod(0o700)
    with database() as connection:
        connection.execute('BEGIN IMMEDIATE')
        connection.executescript('CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY, hash TEXT, owner INTEGER); CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, owner TEXT, entry TEXT, size INTEGER, expires REAL, revoked INTEGER DEFAULT 0);')
        # Serialize the additive migration across both service processes.
        connection.execute('BEGIN IMMEDIATE')
        if 'slug' not in {r[1] for r in connection.execute('PRAGMA table_info(artifacts)')}:
            connection.execute('ALTER TABLE artifacts ADD COLUMN slug TEXT')
        connection.execute('CREATE UNIQUE INDEX IF NOT EXISTS artifact_slug ON artifacts(slug)')
        connection.execute('CREATE TABLE IF NOT EXISTS aliases(slug TEXT PRIMARY KEY, artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id))')
    (ROOT / 'state.db').chmod(0o600)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def issue_token(connection, owner=False):
    secret = secrets.token_urlsafe(32)
    identifier = secrets.token_hex(8)
    connection.execute('INSERT INTO tokens VALUES(?,?,?)', (identifier, digest(secret), int(owner)))
    return {'id': identifier, 'token': secret}

def make_slug(title):
    title = unicodedata.normalize('NFKD', title).encode('ascii', 'ignore').decode().lower()
    return (re.sub(r'[^a-z0-9]+', '-', title).strip('-')[:64] or 'artifact') + '-' + secrets.token_hex(6)

def alias_slug(title):
    title = unicodedata.normalize('NFKD', title).encode('ascii', 'ignore').decode().lower()
    slug = re.sub(r'[^a-z0-9]+', '-', title).strip('-')[:64].rstrip('-')
    if not slug or slug in {'s', 'api', 'health', 'static', 'favicon', 'robots'}:
        raise InvalidUpload('Invalid or reserved slug')
    return slug

def safe_path(name):
    if (not name or len(name.encode('utf-8')) > 1024 or name.startswith('/') or '\\' in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise InvalidUpload('Invalid file path')
    parts = name.split('/')
    if len(parts) > 20 or any(not p or p in ('.', '..') or len(p.encode('utf-8')) > 255 for p in parts):
        raise InvalidUpload('Invalid file path')
    return name

def expiry_value(value):
    if value is None:
        return None
    try:
        expiry = float(value)
    except (ValueError, TypeError):
        raise InvalidUpload('Expiry must be a finite future Unix timestamp') from None
    if not math.isfinite(expiry) or expiry <= time.time():
        raise InvalidUpload('Expiry must be a finite future Unix timestamp')
    return expiry

def copy_limited(source, destination, maximum):
    if maximum < 0:
        raise QuotaExceeded('Upload or storage limit exceeded')
    count = 0
    while True:
        block = source.read(min(64 * 1024, maximum - count + 1))
        if not block:
            return count
        count += len(block)
        if count > maximum:
            raise QuotaExceeded('Upload or storage limit exceeded')
        destination.write(block)

def file_charge(size):
    # Reserve allocation rounding plus inode/directory-entry metadata, even for
    # empty files. This is deliberately conservative across filesystems.
    return ((size + 4095) // 4096) * 4096 + 4096

def tree_usage(root):
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        total += max(4096, Path(directory).lstat().st_size) + 4096
        for name in files:
            total += file_charge((Path(directory) / name).lstat().st_size)
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                total += 4096
    return total

def disk_usage():
    return tree_usage(ROOT)

def validate_zip_directory(archive_path):
    """Bound central-directory allocation before ZipFile builds ZipInfo objects.

    ZIP64 and multi-disk archives are unnecessary for the 50 MiB service limit.
    Reject them, inconsistent offsets, and oversized central-directory metadata.
    """
    length = archive_path.stat().st_size
    with archive_path.open('rb') as source:
        source.seek(max(0, length - 65557))
        tail = source.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    if offset < 0 or len(tail) - offset < 22:
        raise InvalidUpload('Invalid ZIP directory')
    physical_offset = length - len(tail) + offset
    if physical_offset >= 20:
        with archive_path.open('rb') as source:
            source.seek(physical_offset - 20)
            if source.read(4) == b'PK\x06\x07':
                raise InvalidUpload('ZIP64 locator is forbidden')
    record = struct.unpack_from('<4s4H2LH', tail, offset)
    _, disk, central_disk, disk_count, count, size, start, comment = record
    if disk or central_disk or disk_count != count or count == 65535 or start == 0xffffffff or size == 0xffffffff:
        raise InvalidUpload('ZIP64 and multi-disk archives are not supported')
    if len(tail) - offset != 22 + comment or start + size != length - len(tail) + offset:
        raise InvalidUpload('Inconsistent ZIP directory')
    if count > MAX_FILES or size > min(4 * 1024**2, MAX_FILES * 1070):
        raise QuotaExceeded('ZIP directory exceeds limit')
    with archive_path.open('rb') as source:
        source.seek(start)
        directory = source.read(size)
    cursor = actual = 0
    while cursor < size:
        if cursor + 46 > size or directory[cursor:cursor+4] != b'PK\x01\x02':
            raise InvalidUpload('Invalid central directory')
        filename, extra, note, member_disk = struct.unpack_from('<4H', directory, cursor + 28)
        if member_disk:
            raise InvalidUpload('Multi-disk member is forbidden')
        cursor += 46 + filename + extra + note
        actual += 1
        if actual > MAX_FILES:
            raise QuotaExceeded('Too many ZIP entries')
    if cursor != size or actual != count:
        raise InvalidUpload('ZIP directory count mismatch')


def extract_bundle(archive_path, destination, capacity):
    validate_zip_directory(archive_path)
    size = 0
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise QuotaExceeded('Too many archive entries')
        seen = set()
        directories = {''}
        declared = 0
        # Charge every implicit directory and empty file before allocating them.
        for entry in entries:
            name = safe_path(entry.filename[:-1] if entry.is_dir() else entry.filename)
            parts = name.split('/')
            directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
            if entry.is_dir(): directories.add(name)
            else: declared += file_charge(entry.file_size)
        if declared + len(directories) * 8192 > capacity:
            raise QuotaExceeded('Expanded archive exceeds storage budget')
        for entry in entries:
            name = safe_path(entry.filename[:-1] if entry.is_dir() else entry.filename)
            if any(part.startswith('.artifact-') for part in name.split('/')):
                raise InvalidUpload('Reserved file path')
            if name in seen or entry.orig_filename != entry.filename:
                raise InvalidUpload('Duplicate or invalid archive path')
            seen.add(name)
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG):
                raise InvalidUpload('Archive special files are forbidden')
            if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise InvalidUpload('Encrypted or unsupported archive')
            if entry.file_size > min(LIMIT, capacity) - size:
                raise QuotaExceeded('Expanded archive exceeds limit')
            target = destination / name
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open('xb') as output:
                actual = copy_limited(source, output, min(LIMIT, capacity) - size)
            if actual != entry.file_size:
                raise InvalidUpload('Archive length mismatch')
            size += actual
    entry = 'index.html' if (destination / 'index.html').is_file() else 'README.md'
    if not (destination / entry).is_file():
        raise InvalidUpload('Bundle needs index.html or README.md')
    return entry, size

def open_artifact(identifier, name):
    """Walk directory descriptors without following symlinks, including parents."""
    if not ID_PATTERN.fullmatch(identifier):
        raise FileNotFoundError
    parts = [identifier] + safe_path(name).split('/')
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        result = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result)
            raise FileNotFoundError
        return os.fdopen(result, 'rb')
    finally:
        os.close(descriptor)
