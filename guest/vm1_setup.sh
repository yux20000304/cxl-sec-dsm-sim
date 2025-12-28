#!/usr/bin/env bash
set -euo pipefail

# Run inside VM1 to install base deps (Redis + Python) and optionally Gramine.

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

apt-get update
apt-get install -y python3 python3-pip redis-server redis-tools numactl net-tools

echo "[*] If Gramine repo is configured, install it now (optional for SGX):"
echo "    sudo apt-get install -y gramine"
echo "[+] Done."
