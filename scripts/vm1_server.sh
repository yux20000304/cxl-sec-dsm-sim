#!/usr/bin/env bash
set -euo pipefail

# Run inside VM1 to:
# 1) Bind ivshmem to /dev/uioX
# 2) Start Redis (bare or already running service)
# 3) Start server-side shim (shared memory -> Redis)
#
# Usage (inside VM1):
#   sudo bash scripts/vm1_server.sh --uio /dev/uio0 --redis 127.0.0.1:6379
#
# Optional:
#   --repo /mnt/hostshare/cxl-sec-dsm-sim  (if running from a mounted 9p share)
#   --no-redis   (skip launching Redis, assume service already running)

UIO="/dev/uio0"
SHM_PATH=""
MAP_SIZE=""
REDIS="127.0.0.1:6379"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START_REDIS=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uio) UIO="$2"; shift 2 ;;
    --path) SHM_PATH="$2"; shift 2 ;;   # e.g., /sys/bus/pci/devices/0000:00:02.0/resource2
    --map-size) MAP_SIZE="$2"; shift 2 ;; # bytes to mmap (e.g., 134217728 for 128MB)
    --redis) REDIS="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --no-redis) START_REDIS=0; shift ;;
    -h|--help)
      echo "Usage: sudo $0 [--uio /dev/uio0 | --path /sys/.../resource2] [--map-size BYTES] [--redis host:port] [--repo PATH] [--no-redis]"
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

if [[ "${START_REDIS}" -eq 1 ]]; then
  if ! command -v redis-server >/dev/null 2>&1; then
    echo "[*] redis-server not found; installing..."
    apt-get update
    apt-get install -y redis-server redis-tools
  fi
  echo "[*] Starting Redis (background)..."
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^redis-server.service'; then
    systemctl restart redis-server
  else
    nohup redis-server /etc/redis/redis.conf >/tmp/redis.log 2>&1 &
  fi
else
  echo "[*] Skipping Redis launch (--no-redis)"
fi

echo "[*] Starting server agent on ${UIO}, redis=${REDIS}"
AGENT_ARGS=()
if [[ -n "${SHM_PATH}" ]]; then
  AGENT_ARGS+=(--path "${SHM_PATH}")
else
  AGENT_ARGS+=(--uio "${UIO}")
fi
if [[ -n "${MAP_SIZE}" ]]; then
  AGENT_ARGS+=(--map-size "${MAP_SIZE}")
fi
nohup python3 "${REPO}/shim/cxl_server_agent.py" "${AGENT_ARGS[@]}" --redis "${REDIS}" >/tmp/cxl_server_agent.log 2>&1 &
echo "[+] Server agent pid=$!"
echo "    tail -f /tmp/cxl_server_agent.log"
