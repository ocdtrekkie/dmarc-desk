#!/bin/sh
set -eu
export DATA_DIR=/var/dmarc-desk
export MAILDIR=/var/mail
export PYTHONDONTWRITEBYTECODE=1
cd /opt/dmarc-desk
mkdir -p "$MAILDIR/new" "$MAILDIR/cur" "$MAILDIR/tmp"
PYTHON=/opt/dmarc-desk/venv/bin/python
# Migrate and scan synchronously before serving requests.
"$PYTHON" mail_import.py --once
# Pick up mail delivered after that scan, while this grain is running.
"$PYTHON" mail_import.py --watch --interval 60 &
exec /opt/dmarc-desk/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 1 --threads 4 --timeout 120 --worker-tmp-dir /tmp --chdir /opt/dmarc-desk 'app:create_app()'
