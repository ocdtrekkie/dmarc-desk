# DMARC Desk

A Python/Flask web application designed to run inside a Sandstorm grain, with a browser-based drag-and-drop interface and SQLite persistence. This source distribution is not a prebuilt or signed .spk. Sandstorm packaging must be performed on a Linux host with Sandstorm's spk tools.

## Features

- Multiple-file drag-and-drop or file picker for XML, gzip-compressed XML and ZIPs containing XML reports.
- Multiple policy domains in one grain; automatic discovery and domain/date filtering.
- Message-weighted totals, DMARC pass/fail, pass rate, reported quarantine/reject, report count, per-domain summary.
- Paginated source records; failure-only toggle; JSON drill-down with report ID, organization, period, source IP, count, aligned SPF/DKIM, raw authentication results (including multiple signatures and selectors), header/envelope From, policy, and override reasons.
- SQLite persistence, transactions, indexes, WAL mode and duplicate protection.
- No CDN, external JS, DNS queries, mailbox credentials or outbound connections needed at runtime.

## Run locally

Use Python 3.10+ and a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:8000. Local data defaults to ./data. Set DATA_DIR to change this. The development server binds only to loopback. Do not publish this application directly to the internet: it deliberately delegates authentication to Sandstorm and has no independent login system.

For a local production-server smoke test:

```sh
DATA_DIR=./data gunicorn --bind 127.0.0.1:8000 --workers 1 --threads 4 --timeout 120 'app:create_app()'
```

## Tests and samples

```sh
python -m unittest discover -s tests -v
```

The full suite contains 13 tests covering parsing, alignment semantics, archive formats, deduplication, namespaces, XML security, expansion limits, atomic imports, HTTP CSRF, multi-domain filtering, persistence, report details and validation.

See VERIFICATION.txt for actual execution status in the creation environment: 15 parser/database checks ran successfully, but Flask was not available, so the full HTTP suite was not executed. Sandstorm and SPK packaging were also not executed here.

Drop samples/two-domains.zip into a fresh app: expect two domains, 200 observed messages, 180 passes, 20 failures, 20 reported rejects and a 90% pass rate. Then drop samples/example.xml.gz: expect a duplicate, not additional messages. example.xml and example.xml.gz are the same report in different formats.

## Sandstorm packaging

Reference: https://docs.sandstorm.io/en/latest/developing/raw-packaging-guide/

Prerequisites: a clean Linux packaging host, Python with venv support, an installed local Sandstorm server, and spk on PATH. Dependency installation requires network access on the build host; the running grain does not. The helper copies only runtime code into /opt/dmarc-desk, outside the source checkout and venv used for local work.

From the extracted source directory:

```sh
sh package-init.sh
```

This installs dependencies under /opt/dmarc-desk/venv and runs:

```sh
spk init -p 8000 -- /bin/sh /opt/dmarc-desk/start-sandstorm.sh
```

spk generates sandstorm-pkgdef.capnp and a signing identity. Do not rerun spk init for upgrades: retain the generated definition and signing key. Set the generated manifest's appTitle to "DMARC Desk", and set an appropriate version/marketingVersion before publishing. Keep the private Sandstorm keyring secure and outside the distributed source archive.

Then run:

```sh
spk dev
```

Open your local Sandstorm server, create a grain, and exercise every feature while spk dev is running: XML, gzip and ZIP uploads, duplicate uploads, invalid uploads, filtering, all-record/failure-only views, details dialog and pagination. Also close and reopen the grain to confirm persistence. Sandstorm traces dependencies exercised during development. Review sandstorm-files.list and the generated package definition before release; use a clean build host to avoid including personal host files. The dependency version ranges in requirements.txt are not a reproducible lockfile; freeze and review exact versions on your release host.

Stop dev mode, then build:

```sh
spk pack dmarc-desk.spk
```

Upload that signed package through your Sandstorm server's /install page. Test the packaged app in a fresh grain, not only in dev mode. Keep the generated manifest and signing identity for future releases.

The startup script sets DATA_DIR=/var/dmarc-desk and PYTHONDONTWRITEBYTECODE=1, and starts Gunicorn on 127.0.0.1:8000. SQLite, its WAL/SHM files, and a persistent session-signing key live under the grain's writable /var directory. Code and dependencies are read-only. One worker and four threads keep the implementation simple and suit SQLite write serialization; concurrent requests use independent SQLite connections with a 30-second busy timeout.

### Sharing and security model

This version intentionally has a single collaborative access level: anyone who can open the grain can read all domains and import reports. It does not implement separate viewer/editor roles or per-domain access control. Share separate grains for data that needs different access boundaries. Sandstorm controls access to the grain; there is no in-app login or role inferred from untrusted user headers. Runtime must remain behind Sandstorm's HTTP bridge (or loopback for local development).

Imports require a session-bound CSRF token. Report strings are rendered via DOM textContent rather than HTML. The app sets a same-origin resource CSP without frame-ancestors or X-Frame-Options, allowing Sandstorm's frame embedding. It uses HttpOnly, SameSite=Lax session cookies; external HTTPS is handled by Sandstorm.

## Parsing and data semantics

This app consumes aggregate RUA XML reports, not RUF/forensic messages, RFC822 attachments or mailbox exports. ZIP members must have an .xml extension; nested archives are not supported. ZIP entries are read in memory and never extracted to the filesystem. Non-XML files and __MACOSX entries are ignored. Gzip detection uses its magic bytes; raw XML may include namespaces.

Limits: 25 MiB HTTP request, 20 MiB compressed input per file, 20 MiB expanded data per file/container, 100 ZIP entries, 50,000 rows per report and 50 uploaded files per API request. The UI sends one file per request. Encrypted or unsupported ZIPs are rejected. XML DTDs/entities are forbidden through defusedxml. An invalid XML report inside a ZIP rejects the whole uploaded ZIP, without partial inserts. Other selected files continue independently.

Counts use each row's message count, not the number of records. A row passes DMARC if either policy_evaluated/dkim or policy_evaluated/spf is pass. These are the receiver's aligned evaluations; raw auth_results may pass while DMARC alignment fails. The app does not recompute alignment using current DNS or a public-suffix list.

Disposition is separate from DMARC result. A failure can have disposition none due to monitoring or receiver overrides. No disposition proves inbox placement or complete end-to-end delivery; aggregate reports summarize receiver observations, and do not enumerate recipients or message contents.

The domain selector groups by policy_published/domain, not header_from. Subdomains appear separately only when reports publish a separate policy domain. From/through filters use UTC and include entire reports whose intervals overlap the selection, so counts are not prorated to partial days. Overlapping distinct reports may double-count traffic; the app cannot infer message-level duplicates from aggregate data.

Deduplication uses SHA-256 of the decompressed XML plus a unique (policy domain, reporter organization, report ID, begin, end) identity. A report reissued with the same identity is skipped even if its contents differ; corrected reports are not silently applied as replacements. Distinct reporting organizations or periods remain distinct. Semantic duplicates with changed reporting identities are not detected.

Malformed required fields, invalid IPs, nonpositive counts, invalid timestamps, or unknown evaluated results/dispositions reject a report instead of silently turning unknown results into failures. No schema-complete XSD validation is performed. Original XML is not retained; normalized policy, key metadata and record details are stored. Contact email, report ID and organization are retained; optional report error arrays and arbitrary XML extensions are not preserved.

## Database and backup

reports stores report identity, policy domain, organization, time range, digest, policy JSON, selected metadata and import timestamp. records stores each source row, message count, pass flag, evaluated results, disposition, identifiers, raw authentication JSON and override JSON. The initial schema has PRAGMA user_version=1; later schema versions will need explicit migrations before deployment.

Use Sandstorm grain backups for normal backups. For a live standalone database use SQLite's backup API or its .backup command, not a naked copy of the main database while WAL is active. For example, from a host where the database is accessible:

```sh
sqlite3 data/dmarc.sqlite3 ".backup 'dmarc-backup.sqlite3'"
```

Treat report data and backups as sensitive. There is no retention/deletion UI, scheduled collection, CSV export, per-domain ACL, IP reputation, geolocation or mailbox polling in this initial version. Imported data persists until the grain is deleted or an administrator performs database maintenance. No encryption beyond the hosting platform's storage controls is added by the app.
