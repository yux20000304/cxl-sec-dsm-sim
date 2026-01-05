#!/usr/bin/env bash
set -euo pipefail

# Launch two QEMU VMs sharing the same file-backed memory (ivshmem),
# simulating multi-host CXL shared memory.
#
# Example:
#   bash infra/run_vms.sh \
#     --cxl /tmp/cxl_shared.raw --cxl-size 4G \
#     --vm1-disk infra/images/vm1.qcow2 --vm1-seed infra/images/seed-vm1.img \
#     --vm2-disk infra/images/vm2.qcow2 --vm2-seed infra/images/seed-vm2.img
#
# Optional NUMA binding (host):
#   VM1_CPU_NODE=0 VM2_CPU_NODE=0 CXL_MEM_NODE=1 bash infra/run_vms.sh ...

usage() {
  cat >&2 <<'EOF'
Usage: run_vms.sh --cxl <path> --cxl-size <size> --vm1-disk <qcow2> --vm1-seed <seed.img> --vm2-disk <qcow2> --vm2-seed <seed.img>
Optional:
  --vm1-ssh 2222 --vm2-ssh 2223
  --vm1-mem 4G --vm2-mem 4G
  --vm1-cpus 4 --vm2-cpus 4
  --hostshare <path-to-share-into-guests>
Environment:
  VMNET_ENABLE=1 (default) enables a VM-to-VM internal NIC via QEMU socket netdev.
  VMNET_HOST=127.0.0.1 (default) host address for the point-to-point netdev socket.
  VMNET_PORT=0 (default) auto-picks a free TCP port on VMNET_HOST.
  VMNET_VM1_MAC / VMNET_VM2_MAC set internal NIC MACs (used by cloud-init netplan).
Environment:
  VM1_CPU_NODE (bind qemu vCPUs to host NUMA node)
  VM2_CPU_NODE
  CXL_MEM_NODE (bind shared memory allocation to host NUMA node)
EOF
}

CXL_PATH=""
CXL_SIZE=""
VM1_DISK=""
VM2_DISK=""
VM1_SEED=""
VM2_SEED=""
VM1_SSH_PORT=2222
VM2_SSH_PORT=2223
VM1_MEM="4G"
VM2_MEM="4G"
VM1_CPUS=4
VM2_CPUS=4
HOSTSHARE="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cxl) CXL_PATH="$2"; shift 2 ;;
    --cxl-size) CXL_SIZE="$2"; shift 2 ;;
    --vm1-disk) VM1_DISK="$2"; shift 2 ;;
    --vm2-disk) VM2_DISK="$2"; shift 2 ;;
    --vm1-seed) VM1_SEED="$2"; shift 2 ;;
    --vm2-seed) VM2_SEED="$2"; shift 2 ;;
    --vm1-ssh) VM1_SSH_PORT="$2"; shift 2 ;;
    --vm2-ssh) VM2_SSH_PORT="$2"; shift 2 ;;
    --vm1-mem) VM1_MEM="$2"; shift 2 ;;
    --vm2-mem) VM2_MEM="$2"; shift 2 ;;
    --vm1-cpus) VM1_CPUS="$2"; shift 2 ;;
    --vm2-cpus) VM2_CPUS="$2"; shift 2 ;;
    --hostshare) HOSTSHARE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

for f in CXL_PATH CXL_SIZE VM1_DISK VM2_DISK VM1_SEED VM2_SEED; do
  if [[ -z "${!f}" ]]; then
    echo "[!] Missing required arg: ${f}" >&2
    usage
    exit 1
  fi
done

if [[ ! -f "${CXL_PATH}" ]]; then
  echo "[!] Shared CXL file not found: ${CXL_PATH}" >&2
  exit 1
fi
for f in "${VM1_DISK}" "${VM2_DISK}" "${VM1_SEED}" "${VM2_SEED}"; do
  if [[ ! -f "${f}" ]]; then
    echo "[!] Missing file: ${f}" >&2
    exit 1
  fi
done

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"

if ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
  echo "[!] qemu-system-x86_64 not found. Install qemu-system-x86." >&2
  exit 1
fi

VMNET_ENABLE="${VMNET_ENABLE:-1}"
VMNET_HOST="${VMNET_HOST:-127.0.0.1}"
VMNET_PORT="${VMNET_PORT:-0}"
VMNET_VM1_MAC="${VMNET_VM1_MAC:-52:54:00:12:34:01}"
VMNET_VM2_MAC="${VMNET_VM2_MAC:-52:54:00:12:34:02}"

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .
    return $?
  fi
  return 1
}

pick_free_port() {
  local port=""
  for _ in $(seq 1 200); do
    port=$(( 40000 + (RANDOM % 20000) ))
    if ! port_in_use "${port}"; then
      echo "${port}"
      return 0
    fi
  done
  echo "[!] Failed to pick a free VMNET_PORT" >&2
  return 1
}

if [[ "${VMNET_ENABLE}" == "1" ]]; then
  if [[ "${VMNET_PORT}" == "0" ]]; then
    VMNET_PORT="$(pick_free_port)"
  elif port_in_use "${VMNET_PORT}"; then
    echo "[!] VMNET_PORT already in use on host: ${VMNET_HOST}:${VMNET_PORT}" >&2
    echo "    Hint: set VMNET_PORT=0 to auto-pick a free port." >&2
    exit 1
  fi
  VMNET_ADDR="${VMNET_HOST}:${VMNET_PORT}"
fi

enable_kvm=()
if [[ -e /dev/kvm ]]; then
  enable_kvm=( -enable-kvm -cpu host )
fi

VM1_CPU_NODE="${VM1_CPU_NODE:-}"
VM2_CPU_NODE="${VM2_CPU_NODE:-}"
CXL_MEM_NODE="${CXL_MEM_NODE:-}"

bind_cmd() {
  local node="$1"; shift
  if [[ -n "${node}" ]]; then
    echo "numactl --cpunodebind=${node} --membind=${node} $*"
  else
    echo "$*"
  fi
}

run_vm() {
  local name="$1"; shift
  local ssh_port="$1"; shift
  local disk="$1"; shift
  local seed="$1"; shift
  local mem="$1"; shift
  local cpus="$1"; shift
  local mem_node="$1"; shift
  local cpu_node="$1"; shift

  local monitor="/tmp/${name}.monitor"
  local pidfile="/tmp/${name}.pid"
  local log="/tmp/${name}.log"

  local cxl_opts="-object memory-backend-file,id=cxlmem-${name},share=on,mem-path=${CXL_PATH},size=${CXL_SIZE}"
  if [[ -n "${CXL_MEM_NODE}" ]]; then
    cxl_opts+=",host-nodes=${CXL_MEM_NODE},policy=bind"
  fi

  local vmnet_opts=()
  if [[ "${VMNET_ENABLE}" == "1" ]]; then
    if [[ "${name}" == "vm1" ]]; then
      vmnet_opts=(
        -netdev socket,id=net1,listen="${VMNET_ADDR}"
        -device virtio-net-pci,netdev=net1,mac="${VMNET_VM1_MAC}"
      )
    else
      for _ in $(seq 1 50); do
        if command -v ss >/dev/null 2>&1; then
          ss -H -ltn "sport = :${VMNET_PORT}" 2>/dev/null | grep -q . && break
        else
          break
        fi
        sleep 0.1
      done
      vmnet_opts=(
        -netdev socket,id=net1,connect="${VMNET_ADDR}"
        -device virtio-net-pci,netdev=net1,mac="${VMNET_VM2_MAC}"
      )
    fi
  fi

  local cmd=(
    ${QEMU_BIN}
    -name "${name}"
    -machine q35
    "${enable_kvm[@]}"
    -display none
    -smp "${cpus}"
    -m "${mem}"
    -overcommit mem-lock=off
    ${cxl_opts}
    -device ivshmem-plain,memdev=cxlmem-${name},id=ivshmem0
    -drive if=virtio,file="${disk}",format=qcow2
    -drive if=virtio,file="${seed}",format=raw
    -netdev user,id=net0,hostfwd=tcp::${ssh_port}-:22
    -device virtio-net-pci,netdev=net0
    "${vmnet_opts[@]}"
    -virtfs local,path="${HOSTSHARE}",mount_tag=hostshare,security_model=none,id=hostshare
    -daemonize
    -monitor unix:"${monitor}",server,nowait
    -pidfile "${pidfile}"
    -serial file:"${log}"
  )

  echo "[*] Launching ${name} (SSH port ${ssh_port})"
  local full_cmd
  full_cmd=$(bind_cmd "${cpu_node}" "${cmd[@]}")
  eval "${full_cmd}"
}

run_vm "vm1" "${VM1_SSH_PORT}" "${VM1_DISK}" "${VM1_SEED}" "${VM1_MEM}" "${VM1_CPUS}" "${CXL_MEM_NODE}" "${VM1_CPU_NODE}"
run_vm "vm2" "${VM2_SSH_PORT}" "${VM2_DISK}" "${VM2_SEED}" "${VM2_MEM}" "${VM2_CPUS}" "${CXL_MEM_NODE}" "${VM2_CPU_NODE}"

echo "[+] VMs started."
echo "    VM1 ssh: ssh ubuntu@127.0.0.1 -p ${VM1_SSH_PORT}"
echo "    VM2 ssh: ssh ubuntu@127.0.0.1 -p ${VM2_SSH_PORT}"
echo "    Shared file: ${CXL_PATH}"
