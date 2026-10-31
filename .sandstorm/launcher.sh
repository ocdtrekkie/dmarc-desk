#!/bin/bash
set -euo pipefail
export DATA_DIR=/var/data
VENV=/opt/app-venv
cd /opt/app

mkdir -p /var/mail
mkdir -p /var/mail/new
mkdir -p /var/mail/cur
mkdir -p /var/mail/tmp

# Change app.py to your app's filename
$VENV/bin/python3 app.py

exit 0
