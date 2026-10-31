#!/bin/bash
set -euo pipefail
export DATA_DIR=/var/data
export MAILDIR=/var/mail
VENV=/opt/app-venv
cd /opt/app

mkdir -p "$MAILDIR/new" "$MAILDIR/cur" "$MAILDIR/tmp"
$VENV/bin/python3 mail_import.py --once
$VENV/bin/python3 mail_import.py --watch --interval 60 &
$VENV/bin/python3 app.py

exit 0
