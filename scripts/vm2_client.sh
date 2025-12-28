#!/usr/bin/env bash
set -euo pipefail

# Run inside VM2 to:
# 1) Bind ivshmem to /dev/uioX
# 2) Start client-side shim listening on TCP (default 6380)
#
# Usage:
#   sudo bash scripts/vm2_client.sh --uio /dev/uio0 --listen 0.0.0.0:6380
#
# Optional:
#   --repo /mnt/hostshare/cxl-sec-dsm-sim  (if using 9p mount)

UIO="/dev/uio0"
SHM_PATH=""
MAP_SIZE=""
LISTEN="0.0.0.0:6380"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uio) UIO="$2"; shift 2 ;;
    --path) SHM_PATH="$2"; shift 2 ;;      # e.g., /sys/bus/pci/devices/0000:00:02.0/resource2
    --map-size) MAP_SIZE="$2"; shift 2 ;;  # bytes to mmap (e.g., 134217728 for 128MB)
    --listen) LISTEN="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: sudo $0 [--uio /dev/uio0 | --path /sys/.../resource2] [--map-size BYTES] [--listen 0.0.0.0:6380] [--repo PATH]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

echo "[*] Binding ivshmem to uio_pci_generic..."
bash "${REPO}/guest/bind_ivshmem_uio.sh"

echo "[*] Starting client agent on ${LISTEN}, uio=${UIO}"
AGENT_ARGS=()
if [[ -n "${SHM_PATH}" ]]; then
  AGENT_ARGS+=(--path "${SHM_PATH}")
else
  AGENT_ARGS+=(--uio "${UIO}")
fi
if [[ -n "${MAP_SIZE}" ]]; then
  AGENT_ARGS+=(--map-size "${MAP_SIZE}")
fi
nohup python3 "${REPO}/shim/cxl_client_agent.py" "${AGENT_ARGS[@]}" --listen "${LISTEN}" >/tmp/cxl_client_agent.log 2>&1 &
echo "[+] Client agent pid=$!"
echo "    tail -f /tmp/cxl_client_agent.log"
