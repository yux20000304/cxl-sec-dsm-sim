#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 as Intel TDX confidential guests (2 VMs + ivshmem),
# then run two benchmarks inside the guests:
# 1) Native Redis (TCP/RESP) baseline (VM2 -> VM1 via internal NIC cxl0).
# 2) Ring-enabled Redis (shared-memory ring, no RESP) (VM2 -> VM1 via ivshmem BAR2).
#
# TDX provides a VM-level TEE, so Gramine is NOT required for this workflow.
# (You may still use Gramine inside a TDX guest for additional isolation, but
# it's orthogonal to "run in a TEE".)
#
# Requirements on host:
# - Intel TDX-capable platform with TDX enabled and initialized in the host kernel.
# - KVM acceleration available (/dev/kvm) and QEMU built with TDX support
#   (must accept `-object tdx-guest,...`).
# - A TDVF/OVMF firmware file for `-bios` (Ubuntu: package `ovmf`).
#
# Usage:
#   sudo -E bash scripts/host_recreate_and_bench_tdx.sh
#
# Tunables (env):
#   BASE_IMG       : ubuntu cloud image path (24.04 preferred)
#   VM1_SSH/VM2_SSH: forwarded SSH ports (default: 2222/2223)
#   REQ_N          : total requests for TCP benchmark (default: 200000)
#   CLIENTS        : redis-benchmark concurrency (default: 4)
#   THREADS        : redis-benchmark threads (default: 4)
#   PIPELINE       : redis-benchmark pipeline depth (-P) (default: 256)
#   VMNET_VM1_IP   : VM1 internal IP on cxl0 (default: 192.168.100.1)
#   RING_MAP_SIZE  : BAR2 mmap size (default: 134217728 = 128MB)
#   RING_COUNT     : number of rings (default: 4)
#   MAX_INFLIGHT   : ring client inflight limit (default: 512)
#   SEC_MGR_PORT   : TCP port for cxl_sec_mgr inside vm1 (default: 19001)
#   TDX_BIOS       : firmware file passed to QEMU `-bios` (default auto-detected)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[*] Not running as root; KVM (/dev/kvm) must be accessible to your user for TDX." >&2
  echo "    If you hit a /dev/kvm permission error, rerun with: sudo -E $0" >&2
fi

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"

REQ_N="${REQ_N:-200000}"
CLIENTS="${CLIENTS:-4}"
THREADS="${THREADS:-4}"
PIPELINE="${PIPELINE:-256}"
VMNET_VM1_IP="${VMNET_VM1_IP:-192.168.100.1}"

RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}" # 128MB
RING_COUNT="${RING_COUNT:-4}"
MAX_INFLIGHT="${MAX_INFLIGHT:-512}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19001}"

BASE_IMG="${BASE_IMG:-}"
TDX_BIOS="${TDX_BIOS:-}"

need_cmd() {
  local cmd="$1"
  if command -v "${cmd}" >/dev/null 2>&1; then
    return 0
  fi
  echo "[!] Missing command: ${cmd}" >&2
  return 1
}

need_cmd ssh
need_cmd ssh-keygen
need_cmd bash

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "[!] Missing command: qemu-system-x86_64" >&2
  echo "    Install on Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y qemu-system-x86" >&2
  exit 1
fi
if ! qemu-system-x86_64 -object help 2>/dev/null | grep -q 'tdx-guest'; then
  echo "[!] QEMU does not support TDX guests on this host (missing 'tdx-guest' object)." >&2
  qemu_ver="$(qemu-system-x86_64 -version 2>/dev/null | head -n 1 || true)"
  [[ -n "${qemu_ver}" ]] && echo "    Detected: ${qemu_ver}" >&2
  echo "    Check: qemu-system-x86_64 -object help | grep tdx-guest" >&2
  echo "    You need a TDX-enabled QEMU build + TDX-enabled host kernel to run this workflow." >&2
  exit 1
fi

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-tdx.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

sshkey="${tmpdir}/vm_sshkey"
ssh-keygen -t ed25519 -N "" -f "${sshkey}" -q

ssh_opts=(
  -i "${sshkey}"
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_vm1() { ssh "${ssh_opts[@]}" -p "${VM1_SSH}" ubuntu@127.0.0.1 "$@"; }
ssh_vm2() { ssh "${ssh_opts[@]}" -p "${VM2_SSH}" ubuntu@127.0.0.1 "$@"; }

wait_ssh() {
  local name="$1"
  local port="$2"
  echo "[*] Waiting for ${name} SSH on 127.0.0.1:${port} ..."
  for _ in $(seq 1 300); do
    if ssh "${ssh_opts[@]}" -p "${port}" ubuntu@127.0.0.1 "true" >/dev/null 2>&1; then
      echo "    ${name} SSH ready."
      return 0
    fi
    sleep 1
  done
  echo "[!] Timeout waiting for ${name} SSH." >&2
  return 1
}

ssh_retry_lock() {
  local ssh_func="$1"
  local desc="$2"
  local cmd="$3"
  local out=""
  local rc=0

  for _ in $(seq 1 180); do
    set +e
    out="$(${ssh_func} "${cmd}" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
      [[ -n "${out}" ]] && printf '%s\n' "${out}"
      return 0
    fi

    if printf '%s' "${out}" | grep -qiE 'could not get lock|unable to lock directory'; then
      echo "[*] ${desc}: apt lock held, waiting..."
      sleep 2
      continue
    fi

    printf '%s\n' "${out}" >&2
    return "${rc}"
  done

  echo "[!] ${desc}: timed out waiting for apt lock" >&2
  printf '%s\n' "${out}" >&2
  return 1
}

echo "[*] Recreating TDX VMs (2 guests + ivshmem) ..."
STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${BASE_IMG}" \
VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
VM_TDX_ENABLE=1 TDX_BIOS="${TDX_BIOS}" \
CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
bash "${ROOT}/scripts/host_quickstart.sh"

wait_ssh "vm1" "${VM1_SSH}"
wait_ssh "vm2" "${VM2_SSH}"

echo "[*] Guest OS versions:"
ssh_vm1 "lsb_release -sd || true"
ssh_vm2 "lsb_release -sd || true"

echo "[*] Waiting for cloud-init to finish (avoids apt/dpkg locks) ..."
ssh_vm1 "sudo timeout 300 cloud-init status --wait >/dev/null 2>&1 || true"
ssh_vm2 "sudo timeout 300 cloud-init status --wait >/dev/null 2>&1 || true"

mount_hostshare='
sudo mkdir -p /mnt/hostshare
if ! mountpoint -q /mnt/hostshare; then
  sudo mount -t 9p -o trans=virtio hostshare /mnt/hostshare
fi
'
ssh_vm1 "${mount_hostshare}"
ssh_vm2 "${mount_hostshare}"

echo "[*] TDX guest hints (best-effort):"
ssh_vm1 "dmesg | grep -i tdx | tail -n 20 || true"
ssh_vm2 "dmesg | grep -i tdx | tail -n 20 || true"

echo "[*] Installing dependencies in guests ..."
ssh_retry_lock ssh_vm1 "vm1 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release redis-server redis-tools net-tools tmux pciutils libsodium-dev"

ssh_retry_lock ssh_vm2 "vm2 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm2 "vm2 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release redis-tools net-tools tmux pciutils libsodium-dev"

echo "[*] Building Redis (ring version) in vm1 ..."
ssh_vm1 "sudo systemctl disable --now redis-server >/dev/null 2>&1 || true"
ssh_vm1 "cd /mnt/hostshare/redis/src && make -j2 MALLOC=libc USE_LTO=no CFLAGS='-O2 -fno-lto' LDFLAGS='-fno-lto'"

echo "[*] Building ring client in vm2 (/tmp/cxl_ring_direct) ..."
ssh_vm2 "cd /mnt/hostshare/ring_client && gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct cxl_ring_direct.c -lsodium"

echo "[*] Building cxl_sec_mgr in vm1 (/tmp/cxl_sec_mgr) ..."
ssh_vm1 "make -C /mnt/hostshare/cxl_sec_mgr BIN=/tmp/cxl_sec_mgr"

detect_ring_path='
set -euo pipefail
for dev in /sys/bus/pci/devices/*; do
  [[ -f "${dev}/vendor" && -f "${dev}/device" ]] || continue
  ven=$(cat "${dev}/vendor")
  did=$(cat "${dev}/device")
  if [[ "${ven}" == "0x1af4" && "${did}" == "0x1110" && -e "${dev}/resource2" ]]; then
    echo "${dev}/resource2"
    exit 0
  fi
done
exit 1
'

echo "[*] Detecting ivshmem BAR2 path in guests ..."
RING_PATH_VM1="$(ssh_vm1 "${detect_ring_path}" || true)"
RING_PATH_VM2="$(ssh_vm2 "${detect_ring_path}" || true)"
if [[ -z "${RING_PATH_VM1}" || -z "${RING_PATH_VM2}" ]]; then
  echo "[!] Failed to detect ivshmem BAR2 path inside guests." >&2
  echo "    Check: lspci -nn | grep 1af4:1110, and /sys/bus/pci/devices/*/resource2" >&2
  exit 1
fi
echo "    vm1 BAR2: ${RING_PATH_VM1}"
echo "    vm2 BAR2: ${RING_PATH_VM2}"

ts="$(date +%Y%m%d_%H%M%S)"
native_log="${RESULTS_DIR}/tdx_native_tcp_${ts}.log"
ring_log="${RESULTS_DIR}/tdx_ring_${ts}.log"
ring_csv="${RESULTS_DIR}/tdx_ring_${ts}.csv"
ring_secure_log="${RESULTS_DIR}/tdx_ring_secure_${ts}.log"
ring_secure_csv="${RESULTS_DIR}/tdx_ring_secure_${ts}.csv"
compare_csv="${RESULTS_DIR}/tdx_compare_${ts}.csv"

echo "[*] Internal VM network (cxl0):"
ssh_vm1 "ip -brief addr show cxl0 2>/dev/null || true"
ssh_vm2 "ip -brief addr show cxl0 2>/dev/null || true"

echo "[*] Benchmark 1/3: native Redis (TCP/RESP) inside TDX guests"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_tdx >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_native_tdx \"/usr/bin/redis-server --port 6379 --protected-mode no --save '' --appendonly no >/tmp/redis_native_tdx.log 2>&1\""
ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_tdx.log >&2 || true; exit 1"

ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h ${VMNET_VM1_IP} -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"
ssh_vm2 "redis-benchmark -h ${VMNET_VM1_IP} -p 6379 -t set,get -n ${REQ_N} -c ${CLIENTS} --threads ${THREADS} -P ${PIPELINE}" | tee "${native_log}"

ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_tdx >/dev/null 2>&1 || true"

echo "[*] Benchmark 2/3: ring Redis (shared-memory) inside TDX guests"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_ring_tdx \"cd /mnt/hostshare/redis/src && sudo env CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_COUNT=${RING_COUNT} ./redis-server --port 7379 --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx.log 2>&1\""

for _ in $(seq 1 200); do
  if ssh_vm2 "sudo timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
    break
  fi
  sleep 0.25
done
if ! ssh_vm2 "sudo timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
  echo "[!] ring transport not ready. Dumping diagnostics..." >&2
  ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx.log" >&2 || true
  exit 1
fi

ring_label="tdx_ring_${ts}"
ring_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
ssh_vm2 "cd /tmp && sudo /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_n_per_thread} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_label}.csv --label ${ring_label}" | tee "${ring_log}"
ssh_vm2 "cat /tmp/${ring_label}.csv" > "${ring_csv}"

ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

echo "[*] Benchmark 3/3: secure ring Redis inside TDX guests (ACL + software crypto)"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr_tdx >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_tdx_secure >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

ssh_vm1 "tmux new-session -d -s cxl_sec_mgr_tdx \"sudo /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >/tmp/cxl_sec_mgr_tdx_${ts}.log 2>&1\""
ssh_vm1 "tmux new-session -d -s redis_ring_tdx_secure \"cd /mnt/hostshare/redis/src && sudo env CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_COUNT=${RING_COUNT} CXL_SEC_ENABLE=1 CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 ./redis-server --port 7379 --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx_secure.log 2>&1\""

for _ in $(seq 1 200); do
  if ssh_vm2 "sudo timeout 2 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
    break
  fi
  sleep 0.25
done
if ! ssh_vm2 "sudo timeout 2 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
  echo "[!] secure ring transport not ready. Dumping diagnostics..." >&2
  ssh_vm1 "tail -n 200 /tmp/cxl_sec_mgr_tdx_${ts}.log" >&2 || true
  ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx_secure.log" >&2 || true
  exit 1
fi

ring_secure_label="tdx_ring_secure_${ts}"
ring_secure_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
ssh_vm2 "cd /tmp && sudo /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_secure_n_per_thread} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_secure_label}.csv --label ${ring_secure_label}" | tee "${ring_secure_log}"
ssh_vm2 "cat /tmp/${ring_secure_label}.csv" > "${ring_secure_csv}"

ssh_vm1 "tmux kill-session -t redis_ring_tdx_secure >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr_tdx >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

native_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
native_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
ring_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_csv}" || true)"
ring_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_csv}" || true)"
ring_secure_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_secure_csv}" || true)"
ring_secure_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_secure_csv}" || true)"

{
  echo "label,op,throughput_rps"
  echo "TDXNativeTCP,SET,${native_set}"
  echo "TDXNativeTCP,GET,${native_get}"
  echo "TDXRing,SET,${ring_set}"
  echo "TDXRing,GET,${ring_get}"
  echo "TDXRingSecure,SET,${ring_secure_set}"
  echo "TDXRingSecure,GET,${ring_secure_get}"
} > "${compare_csv}"

echo "[+] Done."
echo "    ${native_log}"
echo "    ${ring_log}"
echo "    ${ring_csv}"
echo "    ${ring_secure_log}"
echo "    ${ring_secure_csv}"
echo "    ${compare_csv}"
