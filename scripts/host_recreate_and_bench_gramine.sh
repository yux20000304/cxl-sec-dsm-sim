#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 from a fresh Ubuntu cloud image (prefer 24.04 "noble"),
# then run five benchmarks:
# 1) Native Redis (no Gramine) over TCP (direct VM-to-VM via internal NIC).
# 2) Native Redis under Gramine over TCP (direct VM-to-VM via internal NIC).
# 3) Native Redis under Gramine over libsodium-encrypted TCP (user-space tunnel).
# 4) Ring-enabled Redis under Gramine over BAR2 (shared ivshmem).
# 5) Secure ring Redis under Gramine (ACL + software crypto in shared memory).
#
# This script can be run as a regular user (QEMU will fall back to TCG if KVM is
# not accessible), but sudo/root is recommended for best performance (KVM).
#
# Usage:
#   sudo bash scripts/host_recreate_and_bench_gramine.sh
#
# Tunables (env):
#   BASE_IMG     : path to ubuntu-24.04-server-cloudimg-amd64.img (optional; if unset, host_quickstart downloads 24.04 by default)
#   VM1_SSH/VM2_SSH: ssh forwarded ports (default: 2222/2223)
#   REQ_N        : total requests for TCP benchmark (default: 200000)
#   CLIENTS      : redis-benchmark concurrency (default: 4)
#   THREADS      : thread count for both benches (default: 4)
#   PIPELINE     : redis-benchmark pipeline depth (-P) (default: 256)
#   VMNET_VM1_IP : VM1 internal IP on cxl0 (default: 192.168.100.1)
#   RING_MAP_SIZE: bytes to mmap for BAR2 (default: 134217728 = 128MB)
#   RING_PATH    : BAR2 resource file (default: /sys/bus/pci/devices/0000:00:02.0/resource2)
#   MAX_INFLIGHT : ring client inflight limit (default: 512)
#   SODIUM_KEY_HEX: pre-shared key for libsodium tunnel (hex64, default: deterministic test key)
#   SODIUM_PORT  : vm1 tunnel listen port on cxl0 (default: 6380)
#   SODIUM_LOCAL_PORT: vm2 local tunnel listen port (default: 6380)
#   SEC_MGR_PORT : TCP port for cxl_sec_mgr inside vm1 (default: 19001)
#   CXL_SHM_DELAY_NS: inject artificial latency on each shared-memory ring access (ns). If unset and host has <2 NUMA nodes, auto-defaults to CXL_SHM_DELAY_NS_DEFAULT.
#   CXL_SHM_DELAY_NS_DEFAULT: default delay to use on 1-NUMA hosts when CXL_SHM_DELAY_NS is unset (default: 150).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 && "${FORCE_SUDO:-0}" == "1" ]]; then
  echo "[*] FORCE_SUDO=1: re-exec with sudo..."
  exec sudo -E bash "$0" "$@"
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "[*] Host is not root; QEMU may run without KVM (slow). To use KVM, add your user to group 'kvm' or rerun with sudo." >&2
fi

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"

REQ_N="${REQ_N:-200000}"
CLIENTS="${CLIENTS:-4}"
THREADS="${THREADS:-4}"
PIPELINE="${PIPELINE:-256}"
VMNET_VM1_IP="${VMNET_VM1_IP:-192.168.100.1}"

RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}" # 128MB
RING_PATH="${RING_PATH:-/sys/bus/pci/devices/0000:00:02.0/resource2}"
MAX_INFLIGHT="${MAX_INFLIGHT:-512}"

SODIUM_KEY_HEX="${SODIUM_KEY_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
SODIUM_PORT="${SODIUM_PORT:-6380}"
SODIUM_LOCAL_PORT="${SODIUM_LOCAL_PORT:-6380}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19001}"

# YCSB (optional; runs inside VM2 against TCP endpoints)
YCSB_ENABLE="${YCSB_ENABLE:-0}"
YCSB_RECORDS="${YCSB_RECORDS:-100000}"
YCSB_OPS="${YCSB_OPS:-100000}"
YCSB_THREADS="${YCSB_THREADS:-4}"
YCSB_TARGET="${YCSB_TARGET:-}"
YCSB_WORKLOADS="${YCSB_WORKLOADS:-workloada}"
YCSB_PASSWORD="${YCSB_PASSWORD:-}"
YCSB_CLUSTER="${YCSB_CLUSTER:-false}"

BASE_IMG="${BASE_IMG:-}"

CXL_SHM_DELAY_NS="${CXL_SHM_DELAY_NS:-}"
CXL_SHM_DELAY_NS_DEFAULT="${CXL_SHM_DELAY_NS_DEFAULT:-150}"

host_numa_node_count() {
  local n=0
  for d in /sys/devices/system/node/node[0-9]*; do
    [[ -d "${d}" ]] && n=$((n + 1))
  done
  if [[ "${n}" -le 0 ]]; then
    n=1
  fi
  echo "${n}"
}

HOST_NUMA_NODES="$(host_numa_node_count)"
if [[ "${HOST_NUMA_NODES}" -lt 2 && -z "${CXL_SHM_DELAY_NS}" ]]; then
  CXL_SHM_DELAY_NS="${CXL_SHM_DELAY_NS_DEFAULT}"
  echo "[*] Host has ${HOST_NUMA_NODES} NUMA node(s); enabling simulated CXL shared-memory latency: CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} (ns)."
  echo "    Override: CXL_SHM_DELAY_NS=0 (disable) or set a custom ns value."
fi

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-gramine.XXXXXX)"
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
ssh_vm1_tty() { ssh -tt "${ssh_opts[@]}" -p "${VM1_SSH}" ubuntu@127.0.0.1 "$@"; }

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

base_desc="${BASE_IMG:-auto (download Ubuntu 24.04 if missing)}"
echo "[*] Recreating VMs (BASE_IMG=${base_desc})"
STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${BASE_IMG}" \
VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
bash "${ROOT}/scripts/host_quickstart.sh"

wait_ssh "vm1" "${VM1_SSH}"
wait_ssh "vm2" "${VM2_SSH}"

echo "[*] Guest OS versions:"
ssh_vm1 "lsb_release -sd || true"
ssh_vm2 "lsb_release -sd || true"

echo "[*] Waiting for cloud-init to finish (avoids apt/dpkg locks) ..."
ssh_vm1 "sudo timeout 300 cloud-init status --wait >/dev/null 2>&1 || true"
echo "    vm1 cloud-init: done."
ssh_vm2 "sudo timeout 300 cloud-init status --wait >/dev/null 2>&1 || true"
echo "    vm2 cloud-init: done."

mount_hostshare='
sudo mkdir -p /mnt/hostshare
if ! mountpoint -q /mnt/hostshare; then
  sudo mount -t 9p -o trans=virtio hostshare /mnt/hostshare
fi
'
ssh_vm1 "${mount_hostshare}"
ssh_vm2 "${mount_hostshare}"

echo "[*] Installing dependencies in guests ..."
ssh_retry_lock ssh_vm1 "vm1 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config ca-certificates curl lsb-release redis-server redis-tools net-tools tmux libsodium-dev"

ssh_retry_lock ssh_vm2 "vm2 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm2 "vm2 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release redis-tools net-tools tmux libsodium-dev"

echo "[*] Installing Gramine in vm1 (direct mode; no SGX hardware required) ..."
ssh_vm1 '
set -e
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg https://packages.gramineproject.io/gramine-keyring-$(lsb_release -sc).gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/gramine.list >/dev/null
'
ssh_retry_lock ssh_vm1 "vm1 apt-get update (gramine repo)" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install gramine" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y gramine"

echo "[*] Building Redis (ring version) and Gramine manifests in vm1 ..."
ssh_vm1 "sudo systemctl disable --now redis-server >/dev/null 2>&1 || true"
ssh_vm1 "cd /mnt/hostshare/redis/src && sudo make -j2 MALLOC=libc USE_LTO=no CFLAGS='-O2 -fno-lto' LDFLAGS='-fno-lto'"
# NOTE: `/mnt/hostshare` is a 9p mount that exposes host UID/GID numbers.
# Running as `ubuntu` (uid=1000) may not be able to write there, so use sudo.
ssh_vm1 "cd /mnt/hostshare/gramine && sudo make clean && sudo make links native ring"

echo "[*] Building ring client in vm2 (/tmp/cxl_ring_direct) ..."
ssh_vm2 "cd /mnt/hostshare/ring_client && gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct cxl_ring_direct.c -lsodium"

echo "[*] Building libsodium tunnel in guests (/tmp/cxl_sodium_tunnel) ..."
ssh_vm1 "make -C /mnt/hostshare/sodium_tunnel BIN=/tmp/cxl_sodium_tunnel"
ssh_vm2 "make -C /mnt/hostshare/sodium_tunnel BIN=/tmp/cxl_sodium_tunnel"

echo "[*] Building cxl_sec_mgr in vm1 (/tmp/cxl_sec_mgr) ..."
ssh_vm1 "make -C /mnt/hostshare/cxl_sec_mgr BIN=/tmp/cxl_sec_mgr"

ts="$(date +%Y%m%d_%H%M%S)"
plain_dir_vm1="/tmp/cxl-sec-dsm-sim-redis-plain-${ts}"
plain_log="${RESULTS_DIR}/gramine_plain_tcp_${ts}.log"
native_log="${RESULTS_DIR}/gramine_native_tcp_${ts}.log"
sodium_log="${RESULTS_DIR}/gramine_sodium_tcp_${ts}.log"
ring_log="${RESULTS_DIR}/gramine_ring_${ts}.log"
ring_csv="${RESULTS_DIR}/gramine_ring_${ts}.csv"
ring_secure_log="${RESULTS_DIR}/gramine_ring_secure_${ts}.log"
ring_secure_csv="${RESULTS_DIR}/gramine_ring_secure_${ts}.csv"
compare_csv="${RESULTS_DIR}/gramine_compare_${ts}.csv"

echo "[*] Internal VM network (cxl0):"
ssh_vm1 "ip -brief addr show cxl0 2>/dev/null || true"
ssh_vm2 "ip -brief addr show cxl0 2>/dev/null || true"

echo "[*] Benchmark 1/5: native Redis (no Gramine) (TCP via cxl0)"
ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_plain_tcp >/dev/null 2>&1 || true"
ssh_vm1 "rm -rf '${plain_dir_vm1}' >/dev/null 2>&1 || true; mkdir -p '${plain_dir_vm1}'"
ssh_vm1 "tmux new-session -d -s redis_plain_tcp \"redis-server /mnt/hostshare/gramine/redis.conf --dir '${plain_dir_vm1}' --dbfilename dump.rdb >/tmp/redis_plain_tcp.log 2>&1\""
if ! ssh_vm1 "for i in \$(seq 1 80); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; exit 1"; then
  echo "[!] redis-server (plain) not ready (vm1). Dumping diagnostics..." >&2
  ssh_vm1 "tail -n 200 /tmp/redis_plain_tcp.log 2>/dev/null || true" >&2
  ssh_vm1 "ss -lntp 2>/dev/null | grep -E ':6379\\b' || true" >&2
  ssh_vm1 "pgrep -a redis-server 2>/dev/null || true" >&2
  exit 1
fi
ssh_vm2 "for i in \$(seq 1 120); do redis-cli -h ${VMNET_VM1_IP} -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"
ssh_vm2 "redis-benchmark -h ${VMNET_VM1_IP} -p 6379 -t set,get -n ${REQ_N} -c ${CLIENTS} --threads ${THREADS} -P ${PIPELINE}" | tee "${plain_log}"

# Optional: run YCSB against native TCP endpoint
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: native TCP (VM2 -> VM1:${VMNET_VM1_IP}:6379)"
  ycsb_args=("--host" "${VMNET_VM1_IP}" "--port" "6379" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
  ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
  ssh_vm2 "sudo -n bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_plain_tcp >/dev/null 2>&1 || true"
ssh_vm1 "rm -rf '${plain_dir_vm1}' >/dev/null 2>&1 || true"

echo "[*] Benchmark 2/5: native Redis under Gramine (TCP via cxl0)"
ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_gramine >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_native_gramine \"cd /mnt/hostshare/gramine && gramine-direct ./redis-native /repo/gramine/redis.conf >/tmp/redis_native_gramine.log 2>&1\""
if ! ssh_vm1 "for i in \$(seq 1 600); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; exit 1"; then
  echo "[!] redis-server not ready (vm1). Dumping diagnostics..." >&2
  ssh_vm1 "head -n 120 /tmp/redis_native_gramine.log 2>/dev/null || true" >&2
  ssh_vm1 "tail -n 200 /tmp/redis_native_gramine.log 2>/dev/null || true" >&2
  ssh_vm1 "ss -lntp 2>/dev/null | grep -E ':6379\\b' || true" >&2
  ssh_vm1 "pgrep -a redis-server 2>/dev/null || true" >&2
  ssh_vm1 "pgrep -a gramine-direct 2>/dev/null || true" >&2
  ssh_vm1 "pgrep -a '/usr/lib/.*/gramine/.*/loader' 2>/dev/null || true" >&2
  ssh_vm1 "tmux capture-pane -pt redis_native_gramine -S -200 2>/dev/null || true" >&2
  exit 1
fi

# Wait until VM2 can reach VM1 over the internal NIC.
ssh_vm2 "for i in \$(seq 1 120); do redis-cli -h ${VMNET_VM1_IP} -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"

ssh_vm2 "redis-benchmark -h ${VMNET_VM1_IP} -p 6379 -t set,get -n ${REQ_N} -c ${CLIENTS} --threads ${THREADS} -P ${PIPELINE}" | tee "${native_log}"

# Optional: run YCSB against gramine-native TCP endpoint
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: gramine-native TCP (VM2 -> VM1:${VMNET_VM1_IP}:6379)"
  ycsb_args=("--host" "${VMNET_VM1_IP}" "--port" "6379" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
  ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
  ssh_vm2 "sudo -n bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

echo "[*] Benchmark 3/5: native Redis over libsodium-encrypted TCP (tunnel)"
ssh_vm1 "tmux kill-session -t sodium_server >/dev/null 2>&1 || true"
ssh_vm2 "tmux kill-session -t sodium_client >/dev/null 2>&1 || true"

ssh_vm1 "tmux new-session -d -s sodium_server \"/tmp/cxl_sodium_tunnel --mode server --listen 0.0.0.0:${SODIUM_PORT} --backend 127.0.0.1:6379 --key ${SODIUM_KEY_HEX} >/tmp/sodium_server_${ts}.log 2>&1\""
ssh_vm2 "tmux new-session -d -s sodium_client \"/tmp/cxl_sodium_tunnel --mode client --listen 127.0.0.1:${SODIUM_LOCAL_PORT} --connect ${VMNET_VM1_IP}:${SODIUM_PORT} --key ${SODIUM_KEY_HEX} >/tmp/sodium_client_${ts}.log 2>&1\""

if ! ssh_vm2 "for i in \$(seq 1 600); do redis-cli -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; exit 1"; then
  echo "[!] libsodium tunnel not ready. Dumping diagnostics..." >&2
  ssh_vm2 "tail -n 200 /tmp/sodium_client_${ts}.log 2>/dev/null || true" >&2
  ssh_vm1 "tail -n 200 /tmp/sodium_server_${ts}.log 2>/dev/null || true" >&2
  ssh_vm1 "ss -lntp 2>/dev/null | grep -E ':${SODIUM_PORT}\\b' || true" >&2
  ssh_vm2 "ss -lntp 2>/dev/null | grep -E ':${SODIUM_LOCAL_PORT}\\b' || true" >&2
  exit 1
fi

ssh_vm2 "redis-benchmark -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} -t set,get -n ${REQ_N} -c ${CLIENTS} --threads ${THREADS} -P ${PIPELINE}" | tee "${sodium_log}"

# Optional: run YCSB against libsodium-encrypted TCP tunnel
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: sodium TCP (VM2 127.0.0.1:${SODIUM_LOCAL_PORT} -> VM1 ${VMNET_VM1_IP}:${SODIUM_PORT})"
  ycsb_args=("--host" "127.0.0.1" "--port" "${SODIUM_LOCAL_PORT}" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
  ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
  ssh_vm2 "sudo -n bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

ssh_vm2 "tmux kill-session -t sodium_client >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t sodium_server >/dev/null 2>&1 || true"

ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_gramine >/dev/null 2>&1 || true"

echo "[*] Benchmark 4/5: ring Redis under Gramine (BAR2 shared memory)"
ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_gramine >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_ring_gramine \"cd /mnt/hostshare/gramine && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} gramine-direct ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_gramine.log 2>&1\""

# Wait until the ring is usable by doing a small shared-memory ping from VM2.
ssh_vm2 "for i in \$(seq 1 600); do sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'ring not ready' >&2; exit 1"

ring_label="gramine_ring_${ts}"
ring_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))

ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} /tmp/cxl_ring_direct --path ${RING_PATH} --map-size ${RING_MAP_SIZE} --bench ${ring_n_per_thread} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_label}.csv --label ${ring_label}" | tee "${ring_log}"
ssh_vm2 "cat /tmp/${ring_label}.csv" > "${ring_csv}"

# Optional: run YCSB against ring via local RESP proxy
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: ring via RESP proxy (VM2 127.0.0.1:6381 -> ring BAR2)"
  ycsb_args=("--host" "127.0.0.1" "--port" "6381" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  # Start local proxy inside VM2 pointing to BAR2 path
  ssh_vm2 "sudo -n env RING_RESP_PROXY=1 RING_PATH=${RING_PATH} RING_MAP_SIZE=${RING_MAP_SIZE} RING_RESP_LISTEN=127.0.0.1:6381 bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_gramine >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

echo "[*] Benchmark 5/5: secure ring Redis under Gramine (ACL + software crypto)"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_gramine_secure >/dev/null 2>&1 || true"

ssh_vm1 "tmux new-session -d -s cxl_sec_mgr \"sudo /tmp/cxl_sec_mgr --ring ${RING_PATH} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >/tmp/cxl_sec_mgr_${ts}.log 2>&1\""
ssh_vm1 "tmux new-session -d -s redis_ring_gramine_secure \"cd /mnt/hostshare/gramine && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_SEC_ENABLE=1 CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 gramine-direct ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_gramine_secure.log 2>&1\""

ssh_vm2 "for i in \$(seq 1 600); do sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 5 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'secure ring not ready' >&2; exit 1"

ring_secure_label="gramine_ring_secure_${ts}"
ring_secure_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))

ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH} --map-size ${RING_MAP_SIZE} --bench ${ring_secure_n_per_thread} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_secure_label}.csv --label ${ring_secure_label}" | tee "${ring_secure_log}"
ssh_vm2 "cat /tmp/${ring_secure_label}.csv" > "${ring_secure_csv}"

# Optional: run YCSB against secure ring via local RESP proxy
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: secure ring via RESP proxy (VM2 127.0.0.1:6382 -> ring BAR2)"
  ycsb_args=("--host" "127.0.0.1" "--port" "6382" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  ssh_vm2 "sudo -n env RING_RESP_PROXY=1 RING_RESP_SECURE=1 RING_PATH=${RING_PATH} RING_MAP_SIZE=${RING_MAP_SIZE} RING_RESP_LISTEN=127.0.0.1:6382 bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

ssh_vm1 "tmux kill-session -t redis_ring_gramine_secure >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

plain_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${plain_log}" || true)"
plain_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${plain_log}" || true)"
native_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
native_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
sodium_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${sodium_log}" || true)"
sodium_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${sodium_log}" || true)"
ring_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_csv}" || true)"
ring_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_csv}" || true)"
ring_secure_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_secure_csv}" || true)"
ring_secure_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_secure_csv}" || true)"

{
  echo "label,op,throughput_rps"
  echo "NativeTCP,SET,${plain_set}"
  echo "NativeTCP,GET,${plain_get}"
  echo "GramineNativeTCP,SET,${native_set}"
  echo "GramineNativeTCP,GET,${native_get}"
  echo "GramineSodiumTCP,SET,${sodium_set}"
  echo "GramineSodiumTCP,GET,${sodium_get}"
  echo "GramineRing,SET,${ring_set}"
  echo "GramineRing,GET,${ring_get}"
  echo "GramineRingSecure,SET,${ring_secure_set}"
  echo "GramineRingSecure,GET,${ring_secure_get}"
} > "${compare_csv}"

echo "[+] Done."
echo "    ${plain_log}"
echo "    ${native_log}"
echo "    ${sodium_log}"
echo "    ${ring_log}"
echo "    ${ring_csv}"
echo "    ${ring_secure_log}"
echo "    ${ring_secure_csv}"
echo "    ${compare_csv}"
