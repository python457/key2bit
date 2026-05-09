#!/bin/bash
set -e
echo "[+] Installing Key2Bit v2.0..."
chmod +x key2bit.py
sudo cp key2bit.py /usr/local/bin/key2bit
echo "[+] Installed successfully."
echo "[+] Run: key2bit --help"
