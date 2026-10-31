#!/usr/bin/env python3
"""Import Sandstorm Maildir DMARC attachments; retains original messages."""
import argparse
from email import policy
from email.parser import BytesParser
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import stat
import time
from app import create_app, import_file, ReportError, LIMIT

MAX_EMAIL = 32 * 1024 * 1024
MAX_ATTACHMENTS = 50
MAX_DECODED = 40 * 1024 * 1024
STOP = False
LOG = logging.getLogger('mail-import')
LEDGER = """
CREATE TABLE IF NOT EXISTS mail_imports (
 digest TEXT PRIMARY KEY,
 status TEXT NOT NULL,
 result TEXT NOT NULL,
 processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

def stop(*_):
    global STOP
    STOP = True

def read_message(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Not a regular file')
        if info.st_size > MAX_EMAIL:
            raise ValueError('Email exceeds 32 MiB')
        data = f.read(MAX_EMAIL + 1)
        if len(data) > MAX_EMAIL:
            raise ValueError('Email exceeds 32 MiB')
        return data

def attachments(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    candidates = []
    decoded_total = 0
    for i, part in enumerate(message.walk()):
        if i > 1000:
            raise ValueError('Too many MIME parts')
        if part.is_multipart():
            continue
        name = (part.get_filename() or '').lower()
        mime = part.get_content_type().lower()
        supported_name = name.endswith(('.xml', '.gz', '.gzip', '.zip'))
        supported_mime = mime in {'application/xml', 'text/xml', 'application/zip',
                                  'application/gzip', 'application/x-gzip',
                                  'application/x-zip-compressed'}
        if not (supported_name or supported_mime):
            continue
        data = part.get_payload(decode=True)
        if data is None:
            raise ValueError('Attachment cannot be decoded')
        decoded_total += len(data)
        if len(data) > LIMIT or decoded_total > MAX_DECODED:
            raise ValueError('Decoded attachment size limit exceeded')
        candidates.append(data)
        if len(candidates) > MAX_ATTACHMENTS:
            raise ValueError('More than 50 report attachments')
    return candidates

def process(db, raw, reprocess=False, retry_errors=False):
    digest = hashlib.sha256(raw).hexdigest()
    old = db.execute('SELECT status FROM mail_imports WHERE digest=?', (digest,)).fetchone()
    if old and not reprocess and not (retry_errors and old[0] in ('error', 'partial')):
        return None
    results = []
    try:
        parts = attachments(raw)
        for data in parts:
            try:
                results.append(import_file(db, data))
            except (ReportError, ValueError, OSError) as e:
                results.append({'error': str(e)[:500]})
        errors = sum('error' in result for result in results)
        if not results:
            status = 'ignored'
        elif errors == len(results):
            status = 'error'
        elif errors:
            status = 'partial'
        else:
            status = 'done'
    except (ValueError, TypeError) as e:
        status = 'error'
        results = [{'error': str(e)[:500]}]
    with db:
        db.execute('INSERT INTO mail_imports(digest,status,result) VALUES(?,?,?) '
                   'ON CONFLICT(digest) DO UPDATE SET status=excluded.status, '
                   'result=excluded.result, processed_at=CURRENT_TIMESTAMP',
                   (digest, status, json.dumps(results)))
    LOG.info('message=%s status=%s results=%s', digest[:12], status, json.dumps(results))
    return status

def scan(db, maildir, reprocess=False, retry_errors=False):
    for folder in ('new', 'cur'):
        with os.scandir(maildir / folder) as entries:
            for entry in entries:
                if STOP:
                    return
                if not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    raw = read_message(entry.path)
                    process(db, raw, reprocess, retry_errors)
                except FileNotFoundError:
                    # Another Maildir reader may have moved new -> cur.
                    continue
                except (OSError, ValueError):
                    LOG.exception('Could not read/import a maildir message')
                # Database exceptions deliberately propagate: a broken DB should
                # stop startup or visibly terminate the importer, not lose mail.

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--once', action='store_true', help='one scan (default)')
    mode.add_argument('--watch', action='store_true', help='scan repeatedly')
    parser.add_argument('--interval', type=int, default=60)
    parser.add_argument('--maildir', default=os.environ.get('MAILDIR', '/var/mail'))
    parser.add_argument('--retry-errors', action='store_true')
    parser.add_argument('--reprocess', action='store_true', help='ignore message ledger for first scan')
    args = parser.parse_args()
    if args.interval < 1:
        parser.error('--interval must be positive')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    directory = Path(os.environ.get('DATA_DIR', './data'))
    directory.mkdir(parents=True, exist_ok=True)
    # Avoid two importer processes racing through the same message ledger.
    with (directory / 'mail-import.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            LOG.info('Another importer is running; exiting')
            return
        app = create_app()  # Initialize schema, including destination patch migration.
        maildir = Path(args.maildir)
        for folder in ('new', 'cur', 'tmp'):
            (maildir / folder).mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(directory / 'dmarc.sqlite3', timeout=30)
        db.execute('PRAGMA foreign_keys=ON')
        db.executescript(LEDGER)
        try:
            first = True
            while not STOP:
                scan(db, maildir, args.reprocess and first, args.retry_errors)
                first = False
                if not args.watch:
                    break
                # Short sleeps permit prompt termination.
                for _ in range(args.interval):
                    if STOP:
                        break
                    time.sleep(1)
        finally:
            db.close()

if __name__ == '__main__':
    main()
