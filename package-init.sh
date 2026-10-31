#!/bin/sh
set -eu
# Run from the extracted source directory on a clean Linux packaging host.
sudo mkdir -p /opt/dmarc-desk
sudo cp app.py requirements.txt start-sandstorm.sh /opt/dmarc-desk/
sudo cp -R templates static /opt/dmarc-desk/
sudo python3 -m venv /opt/dmarc-desk/venv
sudo /opt/dmarc-desk/venv/bin/pip install -r /opt/dmarc-desk/requirements.txt
sudo chmod 755 /opt/dmarc-desk/start-sandstorm.sh
spk init -p 8000 -- /bin/sh /opt/dmarc-desk/start-sandstorm.sh
printf '\nPackage initialized. Set the manifest title to DMARC Desk, then run spk dev.\n'
