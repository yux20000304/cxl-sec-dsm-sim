#!/usr/bin/env bash
set -euo pipefail

# One-stop host launcher:
# 1) Create shared CXL file if missing
# 2) Create VM disks + cloud-init seeds if missing
# 3) Launch both VMs with ivshmem sharing + SSH port forwards
#
# Requirements on host: qemu-system-x86, qemu-utils, cloud-localds, numactl (optional)
#
# Usage:
#   BASE_IMG=/path/to/jammy-server-cloudimg-amd64.img \
#   bash scripts/host_quickstart.sh
#
# Tunables (env):
#   BASE_IMG      : path to Ubuntu cloud image (required)
#   OUTDIR        : where to place qcow2/seed images (default: infra/images)
#   CXL_PATH      : shared backing file (default: /tmp/cxl_shared.raw)
#   CXL_SIZE      : size of shared file (default: 4G)
#   VM1_SSH       : host SSH port for VM1 (default: 2222)
#   VM2_SSH       : host SSH port for VM2 (default: 2223)
#   VM1_MEM/VM2_MEM (default: 4G)
#   VM1_CPUS/VM2_CPUS (default: 4)
#   HOSTSHARE     : path to share into guest via 9p (default: repo root)
#   VM1_CPU_NODE/VM2_CPU_NODE/CXL_MEM_NODE : optional numactl binding

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA="${ROOT}/infra"

# BASE_IMG="${BASE_IMG:-}"
BASE_IMG="/home/yyang460/projects/mirror/jammy-server-cloudimg-amd64.img"
OUTDIR="${OUTDIR:-${INFRA}/images}"
CXL_PATH="${CXL_PATH:-/tmp/cxl_shared.raw}"
CXL_SIZE="${CXL_SIZE:-4G}"
VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"
VM1_MEM="${VM1_MEM:-4G}"
VM2_MEM="${VM2_MEM:-4G}"
VM1_CPUS="${VM1_CPUS:-4}"
VM2_CPUS="${VM2_CPUS:-4}"
HOSTSHARE="${HOSTSHARE:-${ROOT}}"

if [[ -z "${BASE_IMG}" ]]; then
  echo "[!] Please set BASE_IMG to Ubuntu cloud image path (e.g. jammy-server-cloudimg-amd64.img)" >&2
  exit 1
fi
if [[ ! -f "${BASE_IMG}" ]]; then
  echo "[!] BASE_IMG not found: ${BASE_IMG}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"

echo "[1/3] Shared CXL backing file..."
if [[ ! -f "${CXL_PATH}" ]]; then
  bash "${INFRA}/create_cxl_shared.sh" "${CXL_PATH}" "${CXL_SIZE}"
else
  echo "    reuse ${CXL_PATH}"
fi

echo "[2/3] VM disks + cloud-init seeds..."
if [[ ! -f "${OUTDIR}/vm1.qcow2" || ! -f "${OUTDIR}/vm2.qcow2" ]]; then
  bash "${INFRA}/create_vm_images.sh" --base "${BASE_IMG}" --outdir "${OUTDIR}" --vm1 vm1.qcow2 --vm2 vm2.qcow2
else
  echo "    reuse ${OUTDIR}/vm1.qcow2, vm2.qcow2"
fi
if [[ ! -f "${OUTDIR}/seed-vm1.img" || ! -f "${OUTDIR}/seed-vm2.img" ]]; then
  bash "${INFRA}/create_cloud_init.sh" --outdir "${OUTDIR}"
else
  echo "    reuse ${OUTDIR}/seed-vm1.img, seed-vm2.img"
fi

echo "[3/3] Launching VMs..."
bash "${INFRA}/run_vms.sh" \
  --cxl "${CXL_PATH}" --cxl-size "${CXL_SIZE}" \
  --vm1-disk "${OUTDIR}/vm1.qcow2" --vm1-seed "${OUTDIR}/seed-vm1.img" \
  --vm2-disk "${OUTDIR}/vm2.qcow2" --vm2-seed "${OUTDIR}/seed-vm2.img" \
  --vm1-ssh "${VM1_SSH}" --vm2-ssh "${VM2_SSH}" \
  --vm1-mem "${VM1_MEM}" --vm2-mem "${VM2_MEM}" \
  --vm1-cpus "${VM1_CPUS}" --vm2-cpus "${VM2_CPUS}" \
  --hostshare "${HOSTSHARE}"

echo "[+] Done. SSH:"
echo "    VM1: ssh ubuntu@127.0.0.1 -p ${VM1_SSH}"
echo "    VM2: ssh ubuntu@127.0.0.1 -p ${VM2_SSH}"
