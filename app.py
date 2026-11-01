import gzip
import hashlib
import io
import ipaddress
import json
import os
import secrets
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, abort, g, jsonify, render_template, request, session
from defusedxml import ElementTree as ET

LIMIT = 20 * 1024 * 1024
MAX_MEMBERS = 100
MAX_RECORDS = 50000
SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY, domain TEXT NOT NULL, reporter TEXT NOT NULL,
 report_id TEXT NOT NULL, begin INTEGER NOT NULL, end INTEGER NOT NULL,
 digest TEXT NOT NULL UNIQUE, policy TEXT NOT NULL, metadata TEXT NOT NULL,
 imported TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(domain,reporter,report_id,begin,end));
CREATE TABLE IF NOT EXISTS records (
 id INTEGER PRIMARY KEY, report INTEGER NOT NULL REFERENCES reports(id),
 ip TEXT NOT NULL, count INTEGER NOT NULL CHECK(count>0),
 disposition TEXT NOT NULL, dkim TEXT NOT NULL, spf TEXT NOT NULL,
 passed INTEGER NOT NULL, header_from TEXT NOT NULL, envelope_from TEXT NOT NULL,
 auth TEXT NOT NULL, reasons TEXT NOT NULL, envelope_to TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS report_domain_dates ON reports(domain,begin,end);
CREATE INDEX IF NOT EXISTS records_report ON records(report);
CREATE INDEX IF NOT EXISTS records_pass ON records(passed);
"""

class ReportError(ValueError):
    pass

def text(node, path, default=''):
    return node.findtext(path, default=default).strip() if node is not None else default

def fields(node):
    return {c.tag: (c.text or '').strip() for c in node} if node is not None else {}

def number(value, label):
    try:
        n = int(value)
        if n < 0 or n > 2**53 - 1:
            raise ValueError()
        return n
    except (TypeError, ValueError):
        raise ReportError('Invalid ' + label)

def parse_xml(data):
    try:
        root = ET.fromstring(data, forbid_dtd=True)
    except Exception as e:
        raise ReportError('Invalid or unsafe XML') from e
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    if root.tag != 'feedback':
        raise ReportError('Expected a DMARC aggregate feedback report (not a forensic report)')
    domain = text(root, 'policy_published/domain').lower().rstrip('.')
    reporter = text(root, 'report_metadata/org_name')
    rid = text(root, 'report_metadata/report_id')
    if not domain or not reporter or not rid:
        raise ReportError('Missing domain, reporting organization, or report ID')
    begin = number(text(root, 'report_metadata/date_range/begin'), 'start timestamp')
    end = number(text(root, 'report_metadata/date_range/end'), 'end timestamp')
    if end < begin or end > 253402300799:
        raise ReportError('Invalid report period')
    nodes = root.findall('record')
    if not nodes or len(nodes) > MAX_RECORDS:
        raise ReportError('Report must contain 1–50,000 records')
    rows = []
    total = 0
    for rec in nodes:
        ip = text(rec, 'row/source_ip')
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ReportError('Invalid source IP')
        count = number(text(rec, 'row/count'), 'message count')
        total += count
        if count == 0 or total > 2**53 - 1:
            raise ReportError('Invalid message count or report total')
        policy = rec.find('row/policy_evaluated')
        dkim, spf = text(policy, 'dkim'), text(policy, 'spf')
        disposition = text(policy, 'disposition')
        if dkim not in ('pass', 'fail') or spf not in ('pass', 'fail'):
            raise ReportError('Missing or invalid evaluated SPF/DKIM result')
        if disposition not in ('none', 'pass', 'quarantine', 'reject'):
            raise ReportError(f'Invalid disposition: {disposition!r}')
        auth = {kind: [fields(x) for x in rec.findall('auth_results/' + kind)]
                for kind in ('dkim', 'spf')}
        rows.append((ip, count, disposition, dkim, spf, int('pass' in (dkim, spf)),
                     text(rec, 'identifiers/header_from'), text(rec, 'identifiers/envelope_from'),
                     json.dumps(auth), json.dumps([fields(x) for x in policy.findall('reason')]),
                     text(rec, 'identifiers/envelope_to')))
    return dict(domain=domain, reporter=reporter, report_id=rid, begin=begin, end=end,
                digest=hashlib.sha256(data).hexdigest(),
                policy=json.dumps(fields(root.find('policy_published'))),
                metadata=json.dumps(fields(root.find('report_metadata'))), rows=rows)

def bounded_read(stream, limit=LIMIT):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ReportError('Expanded data exceeds 20 MiB limit')
    return data

def unpack(data):
    if data[:2] == b'\x1f\x8b':
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                return [('gzip report', bounded_read(f))]
        except (OSError, EOFError) as e:
            raise ReportError('Invalid gzip archive') from e
    if data[:2] == b'PK':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                members = z.infolist()
                if len(members) > MAX_MEMBERS:
                    raise ReportError('ZIP contains more than 100 entries')
                result, used = [], 0
                for item in members:
                    if item.is_dir() or item.filename.startswith('__MACOSX/'):
                        continue
                    if not item.filename.lower().endswith('.xml'):
                        continue
                    if item.file_size > LIMIT or used + item.file_size > LIMIT:
                        raise ReportError('Expanded ZIP exceeds 20 MiB limit')
                    with z.open(item) as f:
                        content = bounded_read(f, LIMIT - used)
                    used += len(content)
                    result.append((item.filename, content))
                if not result:
                    raise ReportError('ZIP contains no XML reports')
                return result
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as e:
            raise ReportError('Invalid, encrypted, or unsupported ZIP') from e
    return [('XML report', data)]

def import_file(db, data):
    # Validate the entire container before writing; each uploaded file is atomic.
    reports = [parse_xml(content) for _, content in unpack(data)]
    imported = duplicates = 0
    with db:
        for report in reports:
            identity = (report['domain'], report['reporter'], report['report_id'], report['begin'], report['end'])
            old = db.execute('SELECT digest,id FROM reports WHERE domain=? AND reporter=? AND report_id=? AND begin=? AND end=?', identity).fetchone()
            if old:
                # Only backfill when the original decompressed XML is identical.
                # Do not replace reports reissued with different contents.
                if old[0] == report['digest']:
                    existing = db.execute('SELECT id FROM records WHERE report=? ORDER BY id', (old[1],)).fetchall()
                    if len(existing) != len(report['rows']):
                        raise ReportError('Stored record count differs; destination backfill aborted')
                    db.executemany('UPDATE records SET envelope_to=? WHERE id=?',
                                   [(row[-1], saved[0]) for saved, row in zip(existing, report['rows'])])
                duplicates += 1
                continue
            columns = ('domain','reporter','report_id','begin','end','digest','policy','metadata')
            cur = db.execute('INSERT OR IGNORE INTO reports (' + ','.join(columns) + ') VALUES (?,?,?,?,?,?,?,?)', tuple(report[k] for k in columns))
            if not cur.rowcount:
                duplicates += 1
                continue
            db.executemany('INSERT INTO records(report,ip,count,disposition,dkim,spf,passed,header_from,envelope_from,auth,reasons,envelope_to) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           [(cur.lastrowid,) + row for row in report['rows']])
            imported += 1
    return {'imported': imported, 'duplicates': duplicates}

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=25*1024*1024,
                      DATA_DIR=os.environ.get('DATA_DIR', './data'),
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
    if test_config:
        app.config.update(test_config)
    directory = Path(app.config['DATA_DIR'])
    directory.mkdir(parents=True, exist_ok=True)
    secret = directory / 'session.key'
    try:
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_hex(32))
    app.secret_key = secret.read_text()
    database = directory / 'dmarc.sqlite3'
    with sqlite3.connect(database) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        # destination-domain-patch-v1: preserve existing data, add optional field.
        columns = {row[1] for row in db.execute('PRAGMA table_info(records)')}
        if 'envelope_to' not in columns:
            db.execute("ALTER TABLE records ADD COLUMN envelope_to TEXT NOT NULL DEFAULT ''")
        db.execute('PRAGMA user_version=2')

    def connection():
        if 'db' not in g:
            g.db = sqlite3.connect(database, timeout=30)
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON')
        return g.db

    @app.teardown_appcontext
    def close(_):
        if 'db' in g:
            g.db.close()

    @app.before_request
    def csrf():
        if request.method == 'POST':
            token = session.get('csrf')
            if not token or not secrets.compare_digest(token, request.headers.get('X-CSRF-Token', '')):
                abort(403)

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'"
        return response

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error='Upload exceeds 25 MiB request limit'), 413

    @app.get('/')
    def index():
        session.setdefault('csrf', secrets.token_hex(32))
        return render_template('index.html', csrf=session['csrf'])

    @app.post('/api/import')
    def upload():
        uploads = request.files.getlist('files')
        if not uploads or len(uploads) > 50:
            return jsonify(error='Supply 1–50 files per request'), 400
        results = []
        for file in uploads:
            try:
                result = import_file(connection(), bounded_read(file.stream))
                results.append(dict(file=file.filename, **result))
            except ReportError as e:
                results.append(dict(file=file.filename, error=str(e)))
        return jsonify(results=results)

    def filters():
        where, params = [], []
        domain = request.args.get('domain', '')
        if domain:
            where.append('p.domain=?'); params.append(domain)
        for key, clause in [('start', 'p.end>=?'), ('end', 'p.begin<=?')]:
            value = request.args.get(key)
            if value:
                try:
                    dt = datetime.strptime(value, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                    timestamp = int(dt.timestamp()) + (86399 if key == 'end' else 0)
                except ValueError:
                    abort(400, 'Invalid date')
                where.append(clause); params.append(timestamp)
        return (' AND '.join(where) or '1=1'), params

    @app.get('/api/dashboard')
    def dashboard():
        db = connection()
        where, params = filters()
        base = ' FROM records r JOIN reports p ON p.id=r.report WHERE ' + where
        stats = dict(db.execute('SELECT COALESCE(SUM(r.count),0) total, COALESCE(SUM(r.count*r.passed),0) passed, COALESCE(SUM(r.count*(1-r.passed)),0) failed, COALESCE(SUM(CASE WHEN disposition=\'quarantine\' THEN count ELSE 0 END),0) quarantined, COALESCE(SUM(CASE WHEN disposition=\'reject\' THEN count ELSE 0 END),0) rejected, COUNT(DISTINCT p.id) reports' + base, params).fetchone())
        domains = [r[0] for r in db.execute('SELECT DISTINCT domain FROM reports ORDER BY domain')]
        groups = [dict(r) for r in db.execute('SELECT p.domain, SUM(r.count) total, SUM(r.count*(1-r.passed)) failed' + base + ' GROUP BY p.domain ORDER BY total DESC', params)]
        try:
            page = max(1, int(request.args.get('page', 1)))
        except ValueError:
            abort(400)
        failure_only = request.args.get('failures', '1') == '1'
        extra = ' AND r.passed=0' if failure_only else ''
        row_count = db.execute('SELECT COUNT(*)' + base + extra, params).fetchone()[0]
        rows = [dict(r) for r in db.execute('SELECT r.*,p.domain,p.reporter,p.report_id,p.begin,p.end' + base + extra + ' ORDER BY p.begin DESC,r.count DESC,r.id DESC LIMIT 100 OFFSET ?', params + [(page-1)*100])]
        for row in rows:
            row['auth'] = json.loads(row['auth']); row['reasons'] = json.loads(row['reasons'])
        return jsonify(stats=stats, domains=domains, groups=groups, rows=rows, row_count=row_count, page=page)

    @app.get('/api/report/<int:report_id>')
    def report_detail(report_id):
        row = connection().execute('SELECT * FROM reports WHERE id=?', (report_id,)).fetchone()
        if row is None:
            abort(404)
        data = dict(row)
        for key in ('policy', 'metadata'):
            data[key] = json.loads(data[key])
        return jsonify(data)
    return app

if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=8000)
