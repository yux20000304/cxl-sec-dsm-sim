#!/usr/bin/env bash
set -euo pipefail

# Create a shared backing file to emulate CXL memory.
# Usage: create_cxl_shared.sh /tmp/cxl_shared.raw 4G

usage() {
  echo "Usage: $0 <path> [size]" >&2
  echo "  path: where to place the shared backing file (default: /tmp/cxl_shared.raw)" >&2
  echo "  size: file size (default: 4G)" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SHARED_PATH="${1:-/tmp/cxl_shared.raw}"
SIZE="${2:-4G}"

echo "[*] Creating shared CXL backing file at ${SHARED_PATH} (size ${SIZE})"
sudo mkdir -p "$(dirname "${SHARED_PATH}")"
sudo truncate -s "${SIZE}" "${SHARED_PATH}"
sudo chmod 666 "${SHARED_PATH}"

echo "[+] Done. You can point QEMU -object memory-backend-file,...,mem-path=${SHARED_PATH}"
