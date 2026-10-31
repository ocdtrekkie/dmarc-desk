#!/bin/sh
set -eu
export DATA_DIR=/var/dmarc-desk
export PYTHONDONTWRITEBYTECODE=1
exec /opt/dmarc-desk/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 1 --threads 4 --timeout 120 --worker-tmp-dir /tmp --chdir /opt/dmarc-desk 'app:create_app()'
