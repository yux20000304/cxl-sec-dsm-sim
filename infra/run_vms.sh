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
Environment (optional SGX-in-guest):
  VM_SGX_ENABLE=1 enables SGX virtualization in guests (requires KVM + QEMU SGX support).
  VM1_SGX_ENABLE / VM2_SGX_ENABLE override per-VM (default: VM_SGX_ENABLE).
  SGX_EPC_SIZE=256M EPC section size per enabled VM.
  VM1_SGX_EPC_SIZE / VM2_SGX_EPC_SIZE override per-VM EPC size.
  SGX_EPC_PREALLOC=auto|on|off controls EPC preallocation (default: auto).
  VM1_SGX_EPC_PREALLOC / VM2_SGX_EPC_PREALLOC override per-VM EPC preallocation.
Environment (optional TDX-in-guest):
  VM_TDX_ENABLE=1 enables Intel TDX confidential guests (requires KVM + TDX-enabled host + QEMU tdx-guest support).
  VM1_TDX_ENABLE / VM2_TDX_ENABLE override per-VM (default: VM_TDX_ENABLE).
  TDX_BIOS=/path/to/OVMF.fd sets the TDVF/OVMF firmware file (passed via `-bios`, required by TDX).
  VM1_TDX_BIOS / VM2_TDX_BIOS override per-VM firmware path.
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

default_vm_state_dir() {
  if [[ -n "${VM_STATE_DIR:-}" ]]; then
    echo "${VM_STATE_DIR}"
  elif [[ "${EUID}" -eq 0 ]]; then
    echo "/tmp"
  else
    echo "/tmp/cxl-sec-dsm-sim-${UID}"
  fi
}

VM_STATE_DIR="$(default_vm_state_dir)"
mkdir -p "${VM_STATE_DIR}"

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
host_has_aes=0
if grep -q -m1 -w aes /proc/cpuinfo 2>/dev/null; then
  host_has_aes=1
fi

host_has_kvm=0
host_has_kvm_access=0
refresh_kvm_access() {
  host_has_kvm=0
  host_has_kvm_access=0
  if [[ -c /dev/kvm ]]; then
    host_has_kvm=1
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then
      host_has_kvm_access=1
    fi
  fi
}
refresh_kvm_access

VM_SGX_ENABLE="${VM_SGX_ENABLE:-0}"
VM1_SGX_ENABLE="${VM1_SGX_ENABLE:-${VM_SGX_ENABLE}}"
VM2_SGX_ENABLE="${VM2_SGX_ENABLE:-${VM_SGX_ENABLE}}"
SGX_EPC_SIZE="${SGX_EPC_SIZE:-256M}"
VM1_SGX_EPC_SIZE="${VM1_SGX_EPC_SIZE:-${SGX_EPC_SIZE}}"
VM2_SGX_EPC_SIZE="${VM2_SGX_EPC_SIZE:-${SGX_EPC_SIZE}}"
SGX_EPC_PREALLOC="${SGX_EPC_PREALLOC:-auto}"
VM1_SGX_EPC_PREALLOC="${VM1_SGX_EPC_PREALLOC:-${SGX_EPC_PREALLOC}}"
VM2_SGX_EPC_PREALLOC="${VM2_SGX_EPC_PREALLOC:-${SGX_EPC_PREALLOC}}"

VM_TDX_ENABLE="${VM_TDX_ENABLE:-0}"
VM1_TDX_ENABLE="${VM1_TDX_ENABLE:-${VM_TDX_ENABLE}}"
VM2_TDX_ENABLE="${VM2_TDX_ENABLE:-${VM_TDX_ENABLE}}"
TDX_BIOS="${TDX_BIOS:-}"
VM1_TDX_BIOS="${VM1_TDX_BIOS:-${TDX_BIOS}}"
VM2_TDX_BIOS="${VM2_TDX_BIOS:-${TDX_BIOS}}"

host_has_sgx=0
if grep -q -m1 -w sgx /proc/cpuinfo 2>/dev/null; then
  host_has_sgx=1
fi

host_has_vtx=0
if grep -Eq -m1 '\<(vmx|svm)\>' /proc/cpuinfo 2>/dev/null; then
  host_has_vtx=1
fi

qemu_has_sgx_epc=0
if "${QEMU_BIN}" -object help 2>/dev/null | grep -q 'memory-backend-epc'; then
  qemu_has_sgx_epc=1
fi

qemu_has_tdx=0
if "${QEMU_BIN}" -object help 2>/dev/null | grep -q 'tdx-guest'; then
  qemu_has_tdx=1
fi

default_tdx_bios() {
  local c
  for c in \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/qemu/OVMF.fd \
    /usr/share/OVMF/OVMF.fd; do
    if [[ -f "${c}" ]]; then
      echo "${c}"
      return 0
    fi
  done
  return 1
}

if [[ "${VM1_TDX_ENABLE}" == "1" || "${VM2_TDX_ENABLE}" == "1" ]]; then
  if [[ "${VM1_SGX_ENABLE}" == "1" || "${VM2_SGX_ENABLE}" == "1" ]]; then
    echo "[!] Cannot enable both SGX-in-guest and TDX-in-guest at the same time." >&2
    exit 1
  fi

  if [[ "${host_has_kvm}" != "1" && "${EUID}" -eq 0 ]]; then
    modprobe kvm >/dev/null 2>&1 || true
    modprobe kvm_intel >/dev/null 2>&1 || true
    modprobe kvm_amd >/dev/null 2>&1 || true
  fi
  refresh_kvm_access
  if [[ "${host_has_kvm_access}" != "1" ]]; then
    echo "[!] VM_TDX_ENABLE=1 requires /dev/kvm with RW access (KVM acceleration)." >&2
    if [[ "${host_has_kvm}" == "1" ]]; then
      echo "    /dev/kvm exists but is not accessible (add your user to group 'kvm' or run with sudo)." >&2
    fi
    if [[ "${host_has_vtx}" != "1" ]]; then
      echo "    CPU virtualization flags (vmx/svm) are not visible; nested virtualization is likely disabled." >&2
    fi
    echo "    - Bare metal: enable VT-x/AMD-V in BIOS and load KVM modules (modprobe kvm_intel|kvm_amd)." >&2
    echo "    - VM/cloud: enable nested virtualization in your hypervisor/provider." >&2
    exit 1
  fi
  if [[ "${qemu_has_tdx}" != "1" ]]; then
    echo "[!] QEMU does not support TDX guests (missing 'tdx-guest' object)." >&2
    echo "    Check: ${QEMU_BIN} -object help | grep tdx-guest" >&2
    exit 1
  fi

  if [[ -z "${VM1_TDX_BIOS}" || ! -f "${VM1_TDX_BIOS}" || -z "${VM2_TDX_BIOS}" || ! -f "${VM2_TDX_BIOS}" ]]; then
    auto_bios="$(default_tdx_bios || true)"
    if [[ "${VM1_TDX_ENABLE}" == "1" && ( -z "${VM1_TDX_BIOS}" || ! -f "${VM1_TDX_BIOS}" ) ]]; then
      VM1_TDX_BIOS="${auto_bios}"
    fi
    if [[ "${VM2_TDX_ENABLE}" == "1" && ( -z "${VM2_TDX_BIOS}" || ! -f "${VM2_TDX_BIOS}" ) ]]; then
      VM2_TDX_BIOS="${auto_bios}"
    fi
  fi
  if [[ "${VM1_TDX_ENABLE}" == "1" && ( -z "${VM1_TDX_BIOS}" || ! -f "${VM1_TDX_BIOS}" ) ]]; then
    echo "[!] VM1_TDX_BIOS is required and must exist when VM1_TDX_ENABLE=1." >&2
    echo "    Tip (Ubuntu): sudo apt-get install -y ovmf" >&2
    exit 1
  fi
  if [[ "${VM2_TDX_ENABLE}" == "1" && ( -z "${VM2_TDX_BIOS}" || ! -f "${VM2_TDX_BIOS}" ) ]]; then
    echo "[!] VM2_TDX_BIOS is required and must exist when VM2_TDX_ENABLE=1." >&2
    echo "    Tip (Ubuntu): sudo apt-get install -y ovmf" >&2
    exit 1
  fi

  enable_kvm=( -enable-kvm -cpu host )
elif [[ "${VM1_SGX_ENABLE}" == "1" || "${VM2_SGX_ENABLE}" == "1" ]]; then
  if [[ "${host_has_kvm}" != "1" && "${EUID}" -eq 0 ]]; then
    modprobe kvm >/dev/null 2>&1 || true
    modprobe kvm_intel >/dev/null 2>&1 || true
    modprobe kvm_amd >/dev/null 2>&1 || true
  fi
  refresh_kvm_access
  if [[ "${host_has_kvm_access}" != "1" ]]; then
    echo "[!] VM_SGX_ENABLE=1 requires /dev/kvm with RW access (KVM acceleration)." >&2
    if [[ "${host_has_kvm}" == "1" ]]; then
      echo "    /dev/kvm exists but is not accessible (add your user to group 'kvm' or run with sudo)." >&2
    fi
    if [[ "${host_has_vtx}" != "1" ]]; then
      echo "    CPU virtualization flags (vmx/svm) are not visible; nested virtualization is likely disabled." >&2
    fi
    echo "    - Bare metal: enable VT-x/AMD-V in BIOS and load KVM modules (modprobe kvm_intel|kvm_amd)." >&2
    echo "    - VM/cloud: enable nested virtualization in your hypervisor/provider, or use host SGX tests (no VMs)." >&2
    exit 1
  fi
  if [[ "${host_has_aes}" != "1" ]]; then
    echo "[!] VM_SGX_ENABLE=1 requires host AES-NI ('aes' flag) because Gramine requires it." >&2
    exit 1
  fi
  if [[ "${host_has_sgx}" != "1" ]]; then
    echo "[!] VM_SGX_ENABLE=1 requires host SGX ('sgx' flag). Check BIOS SGX setting." >&2
    exit 1
  fi
  if [[ "${qemu_has_sgx_epc}" != "1" ]]; then
    echo "[!] QEMU does not support SGX EPC objects (missing 'memory-backend-epc')." >&2
    echo "    You need a QEMU build with SGX virtualization enabled to run gramine-sgx inside guests." >&2
    echo "    Check: ${QEMU_BIN} -object help | grep memory-backend-epc" >&2
    exit 1
  fi

  enable_kvm=( -enable-kvm -cpu host )
elif [[ "${host_has_kvm_access}" == "1" && "${host_has_aes}" == "1" ]]; then
  enable_kvm=( -enable-kvm -cpu host )
else
  # No usable KVM path (either missing /dev/kvm, or host CPU doesn't expose AES).
  # Gramine (Linux backend) requires AES-NI (`aes` CPUID flag). When we can't
  # pass through host CPU features via KVM, force a CPU model that exposes AES
  # so Gramine can at least run under TCG (functional testing; very slow).
  if "${QEMU_BIN}" -cpu help 2>/dev/null | grep -q '^x86 max'; then
    enable_kvm=( -cpu max )
  else
    enable_kvm=( -cpu qemu64,+aes )
  fi

  if [[ "${host_has_kvm}" != "1" ]]; then
    echo "[!] /dev/kvm not found; running QEMU without KVM (TCG). Performance will be very slow." >&2
  elif [[ "${host_has_kvm_access}" != "1" ]]; then
    echo "[!] /dev/kvm exists but is not accessible; running QEMU without KVM (TCG). Performance will be very slow." >&2
  elif [[ "${host_has_aes}" != "1" ]]; then
    echo "[!] Host CPU doesn't expose AES-NI ('aes' flag). Gramine requires it; using TCG with emulated AES (slow)." >&2
  fi
fi

VM1_CPU_NODE="${VM1_CPU_NODE:-}"
VM2_CPU_NODE="${VM2_CPU_NODE:-}"
CXL_MEM_NODE="${CXL_MEM_NODE:-}"

sanitize_numa_node_var() {
  local var_name="$1"
  local node="${!var_name:-}"
  if [[ -z "${node}" ]]; then
    return 0
  fi
  if [[ ! -d "/sys/devices/system/node/node${node}" ]]; then
    echo "[!] ${var_name}=${node} but /sys/devices/system/node/node${node} not found; ignoring ${var_name}." >&2
    printf -v "${var_name}" '%s' ""
  fi
}

sanitize_numa_node_var VM1_CPU_NODE
sanitize_numa_node_var VM2_CPU_NODE
sanitize_numa_node_var CXL_MEM_NODE

sanitize_sgx_epc_prealloc_var() {
  local var_name="$1"
  local val="${!var_name:-}"
  case "${val}" in
    auto|on|off) ;;
    1|true) printf -v "${var_name}" '%s' "on" ;;
    0|false) printf -v "${var_name}" '%s' "off" ;;
    *)
      echo "[!] ${var_name} must be one of auto|on|off (got: ${val})." >&2
      exit 1
      ;;
  esac
}

sanitize_sgx_epc_prealloc_var SGX_EPC_PREALLOC
sanitize_sgx_epc_prealloc_var VM1_SGX_EPC_PREALLOC
sanitize_sgx_epc_prealloc_var VM2_SGX_EPC_PREALLOC

run_vm() {
  local name="$1"; shift
  local tdx_enable="$1"; shift
  local tdx_bios="$1"; shift
  local sgx_enable="$1"; shift
  local sgx_epc_size="$1"; shift
  local sgx_epc_prealloc="$1"; shift
  local ssh_port="$1"; shift
  local disk="$1"; shift
  local seed="$1"; shift
  local mem="$1"; shift
  local cpus="$1"; shift
  local mem_node="$1"; shift
  local cpu_node="$1"; shift

  local monitor="${VM_STATE_DIR}/${name}.monitor"
  local pidfile="${VM_STATE_DIR}/${name}.pid"
  local log="${VM_STATE_DIR}/${name}.log"

  local existing_pid=""
  if [[ -f "${pidfile}" ]]; then
    existing_pid="$(cat "${pidfile}" 2>/dev/null || true)"
  fi
  if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
    echo "[!] ${name} appears to be running already (pid=${existing_pid})." >&2
    echo "    Stop it first or set VM_STATE_DIR to a different directory." >&2
    exit 1
  fi
  if ! rm -f "${pidfile}" "${monitor}" "${log}" 2>/dev/null; then
    echo "[!] Cannot clean existing VM state files in VM_STATE_DIR=${VM_STATE_DIR}." >&2
    echo "    Pick a writable directory, e.g.: VM_STATE_DIR=/tmp/cxl-sec-dsm-sim-${UID}" >&2
    exit 1
  fi

  local machine="q35"
  local tdx_opts=()
  if [[ "${tdx_enable}" == "1" ]]; then
    # Intel TDX confidential guests (requires KVM+TDX+QEMU support).
    # QEMU syntax reference: https://www.qemu.org/docs/master/system/i386/tdx.html
    local tdx_id="tdx-${name}"
    tdx_opts=(
      -object "tdx-guest,id=${tdx_id}"
      -bios "${tdx_bios}"
    )
    machine="q35,kernel-irqchip=split,confidential-guest-support=${tdx_id},smm=off"
  fi

  local sgx_opts=()
  if [[ "${sgx_enable}" == "1" ]]; then
    local prealloc="${sgx_epc_prealloc}"
    if [[ "${prealloc}" != "auto" && "${prealloc}" != "on" && "${prealloc}" != "off" ]]; then
      echo "[!] ${name}: invalid SGX EPC prealloc mode: ${prealloc} (expected auto|on|off)." >&2
      return 1
    fi
    if [[ "${prealloc}" == "auto" ]]; then
      prealloc="on"
    fi
    # Provide a virtual EPC section to the guest. This requires host SGX + KVM SGX virtualization.
    # QEMU syntax reference: /usr/share/doc/qemu-system-common/system/i386/sgx.html
    sgx_opts=(
      -object "memory-backend-epc,id=epc-${name},size=${sgx_epc_size},prealloc=${prealloc}"
    )
    machine="q35,sgx-epc.0.memdev=epc-${name},sgx-epc.0.node=0"
  fi

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
    "${enable_kvm[@]}"
    "${tdx_opts[@]}"
    "${sgx_opts[@]}"
    -machine "${machine}"
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

  local full_cmd=()
  if [[ -n "${cpu_node}" ]]; then
    full_cmd+=( numactl --cpunodebind="${cpu_node}" --membind="${cpu_node}" )
  fi
  full_cmd+=( "${cmd[@]}" )

  local out=""
  local rc=0
  set +e
  out="$("${full_cmd[@]}" 2>&1)"
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi

  if [[ "${sgx_enable}" == "1" && "${sgx_epc_prealloc}" == "auto" ]] && printf '%s' "${out}" | grep -q 'qemu_prealloc_mem: preallocating memory failed'; then
    echo "[!] ${name}: EPC preallocation failed; retrying with SGX_EPC_PREALLOC=off." >&2
    rm -f "${pidfile}" "${monitor}" "${log}" 2>/dev/null || true

    sgx_opts=( -object "memory-backend-epc,id=epc-${name},size=${sgx_epc_size},prealloc=off" )
    cmd=(
      ${QEMU_BIN}
      -name "${name}"
      "${enable_kvm[@]}"
      "${tdx_opts[@]}"
      "${sgx_opts[@]}"
      -machine "${machine}"
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

    full_cmd=()
    if [[ -n "${cpu_node}" ]]; then
      full_cmd+=( numactl --cpunodebind="${cpu_node}" --membind="${cpu_node}" )
    fi
    full_cmd+=( "${cmd[@]}" )

    set +e
    out="$("${full_cmd[@]}" 2>&1)"
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then
      printf '%s\n' "${out}" >&2
    fi
    return "${rc}"
  fi

  printf '%s\n' "${out}" >&2
  return "${rc}"
}

run_vm "vm1" "${VM1_TDX_ENABLE}" "${VM1_TDX_BIOS}" "${VM1_SGX_ENABLE}" "${VM1_SGX_EPC_SIZE}" "${VM1_SGX_EPC_PREALLOC}" "${VM1_SSH_PORT}" "${VM1_DISK}" "${VM1_SEED}" "${VM1_MEM}" "${VM1_CPUS}" "${CXL_MEM_NODE}" "${VM1_CPU_NODE}"
run_vm "vm2" "${VM2_TDX_ENABLE}" "${VM2_TDX_BIOS}" "${VM2_SGX_ENABLE}" "${VM2_SGX_EPC_SIZE}" "${VM2_SGX_EPC_PREALLOC}" "${VM2_SSH_PORT}" "${VM2_DISK}" "${VM2_SEED}" "${VM2_MEM}" "${VM2_CPUS}" "${CXL_MEM_NODE}" "${VM2_CPU_NODE}"

echo "[+] VMs started."
echo "    VM1 ssh: ssh ubuntu@127.0.0.1 -p ${VM1_SSH_PORT}"
echo "    VM2 ssh: ssh ubuntu@127.0.0.1 -p ${VM2_SSH_PORT}"
echo "    Shared file: ${CXL_PATH}"
