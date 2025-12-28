#!/usr/bin/env bash
set -euo pipefail

# Run inside VM2 to install client-side tools.

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

apt-get update
apt-get install -y python3 python3-pip redis-tools numactl net-tools
echo "[+] Done. You can run the client shim and redis-benchmark."
