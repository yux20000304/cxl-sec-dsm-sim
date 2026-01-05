#!/usr/bin/env bash
set -euo pipefail

# Create per-VM qcow2 disks from a base Ubuntu cloud image.
# Example:
#   bash infra/create_vm_images.sh \
#     --base /path/to/ubuntu-24.04-server-cloudimg-amd64.img \
#     --outdir infra/images --vm1 vm1.qcow2 --vm2 vm2.qcow2 --size 12G

usage() {
  cat >&2 <<'EOF'
Usage: create_vm_images.sh --base <cloud-image> --outdir <dir> [--vm1 vm1.qcow2] [--vm2 vm2.qcow2] [--size 10G]
EOF
}

BASE=""
OUTDIR=""
VM1="vm1.qcow2"
VM2="vm2.qcow2"
SIZE="10G"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --vm1) VM1="$2"; shift 2 ;;
    --vm2) VM2="$2"; shift 2 ;;
    --size) SIZE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${BASE}" || -z "${OUTDIR}" ]]; then
  usage
  exit 1
fi

if [[ ! -f "${BASE}" ]]; then
  echo "[!] Base image not found: ${BASE}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"

echo "[*] Creating VM1 disk ${OUTDIR}/${VM1}"
qemu-img create -f qcow2 -b "${BASE}" -F qcow2 "${OUTDIR}/${VM1}" "${SIZE}"

echo "[*] Creating VM2 disk ${OUTDIR}/${VM2}"
qemu-img create -f qcow2 -b "${BASE}" -F qcow2 "${OUTDIR}/${VM2}" "${SIZE}"

echo "[+] Done. Disks created in ${OUTDIR}"
