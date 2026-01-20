#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 from a fresh Ubuntu cloud image, enable SGX virtualization in VM1,
# then run a sweep of:
# - "default" benchmarks (redis-benchmark + ring_client) with CLIENTS=THREADS in {1,2,4,8}
# - YCSB workloads A/B/C/D with threads in {1,2,4,8} (clients recorded as same value)
#
# Outputs CSVs into ./results:
# - sgxvm_bench_sweep_<ts>.csv
# - sgxvm_ycsb_sweep_workload{a,b,c,d}_<ts>.csv
#
# Usage:
#   sudo -E bash scripts/host_recreate_and_sweep_bench_ycsb_gramine_sgxvm.sh
#
# Core knobs (env):
#   BASE_IMG             : ubuntu cloud image path (optional; if unset, host_quickstart downloads 24.04 by default)
#   VM1_SSH/VM2_SSH      : forwarded SSH ports (default: 2222/2223)
#   VM1_CPUS/VM2_CPUS    : vCPUs per VM (default: 8)
#   VMNET_VM1_IP         : VM1 internal IP on cxl0 (default: 192.168.100.1)
#
# Sweep knobs (env):
#   SWEEP_VALUES         : space-separated list (default: "1 2 4 8")
#
# Default benchmark knobs (env):
#   REQ_N                : total requests per op for redis-benchmark (default: 1000000)
#   PIPELINE             : redis-benchmark pipeline depth (-P) (default: 256)
#   RING_MAP_SIZE        : BAR2 mmap size (default: 134217728 = 128MB)
#   MAX_INFLIGHT         : ring client inflight limit (default: 512)
#
# YCSB knobs (env):
#   YCSB_VERSION         : YCSB release version (default: 0.17.0)
#   YCSB_RECORDCOUNT     : YCSB recordcount (default: 10000)
#   YCSB_OPERATIONCOUNT  : YCSB operationcount (default: 10000)
#   YCSB_TIMEOUT_MS      : ring JNI timeout per op (default: 5000)
#
# SGX-in-guest knobs:
#   VM1_SGX_EPC_SIZE      : EPC section size for VM1 (default: 512M)
#   SGX_TOKEN_MODE        : auto|require|skip (default: auto)
#
# Shared-memory (CXL) latency simulation:
#   CXL_SHM_DELAY_NS      : inject artificial latency on each shared-memory ring access (ns)
#   CXL_SHM_DELAY_NS_DEFAULT: default delay to use on 1-NUMA hosts when CXL_SHM_DELAY_NS is unset (default: 150)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"
VM1_CPUS="${VM1_CPUS:-8}"
VM2_CPUS="${VM2_CPUS:-8}"
VMNET_VM1_IP="${VMNET_VM1_IP:-192.168.100.1}"

SWEEP_VALUES="${SWEEP_VALUES:-1 2 4 8}"

REQ_N="${REQ_N:-1000000}"
PIPELINE="${PIPELINE:-256}"

RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}" # 128MB
MAX_INFLIGHT="${MAX_INFLIGHT:-512}"

SODIUM_KEY_HEX="${SODIUM_KEY_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
SODIUM_PORT="${SODIUM_PORT:-6380}"
SODIUM_LOCAL_PORT="${SODIUM_LOCAL_PORT:-6380}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19001}"

YCSB_VERSION="${YCSB_VERSION:-0.17.0}"
YCSB_RECORDCOUNT="${YCSB_RECORDCOUNT:-10000}"
YCSB_OPERATIONCOUNT="${YCSB_OPERATIONCOUNT:-10000}"
YCSB_TIMEOUT_MS="${YCSB_TIMEOUT_MS:-5000}"

VM1_SGX_EPC_SIZE="${VM1_SGX_EPC_SIZE:-512M}"
SGX_TOKEN_MODE="${SGX_TOKEN_MODE:-auto}"

BASE_IMG="${BASE_IMG:-}"

CXL_SHM_DELAY_NS="${CXL_SHM_DELAY_NS:-}"
CXL_SHM_DELAY_NS_DEFAULT="${CXL_SHM_DELAY_NS_DEFAULT:-150}"

max_sweep_value() {
  local max=0
  local v
  for v in ${SWEEP_VALUES}; do
    [[ "${v}" =~ ^[0-9]+$ ]] || continue
    if [[ "${v}" -gt "${max}" ]]; then
      max="${v}"
    fi
  done
  echo "${max}"
}

MAX_SWEEP="$(max_sweep_value)"
if [[ "${MAX_SWEEP}" -gt 8 ]]; then
  echo "[!] SWEEP_VALUES includes ${MAX_SWEEP}, but ring modes support at most 8 threads (MAX_RINGS=8)." >&2
  exit 1
fi

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

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-sweep-sgxvm.XXXXXX)"
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

ts="$(date +%Y%m%d_%H%M%S)"
bench_csv="${RESULTS_DIR}/sgxvm_bench_sweep_${ts}.csv"
ycsb_csv_a="${RESULTS_DIR}/sgxvm_ycsb_sweep_workloada_${ts}.csv"
ycsb_csv_b="${RESULTS_DIR}/sgxvm_ycsb_sweep_workloadb_${ts}.csv"
ycsb_csv_c="${RESULTS_DIR}/sgxvm_ycsb_sweep_workloadc_${ts}.csv"
ycsb_csv_d="${RESULTS_DIR}/sgxvm_ycsb_sweep_workloadd_${ts}.csv"

echo "threads,clients,label,op,throughput_rps" > "${bench_csv}"
echo "workload,threads,clients,label,throughput_ops_sec" > "${ycsb_csv_a}"
echo "workload,threads,clients,label,throughput_ops_sec" > "${ycsb_csv_b}"
echo "workload,threads,clients,label,throughput_ops_sec" > "${ycsb_csv_c}"
echo "workload,threads,clients,label,throughput_ops_sec" > "${ycsb_csv_d}"

tp_from_redis_bench_log() {
  local op="$1"
  local log="$2"
  awk -v op="${op}" '
    $0 ~ ("====== " op " ======") {sec=1; next}
    sec && /throughput summary:/ {print $3; exit}
    sec && /requests per second/ {print $1; exit}
  ' "${log}" 2>/dev/null || true
}

tp_from_ring_csv() {
  local op="$1"
  local csv="$2"
  awk -F, -v op="${op}" 'NR>1 && $2==op {print $8; exit}' "${csv}" 2>/dev/null || true
}

tp_from_ycsb_log() {
  local log="$1"
  awk -F', ' '/\[OVERALL\], Throughput\(ops\/sec\),/ {print $3; exit}' "${log}" 2>/dev/null || true
}

append_bench_row() {
  local threads="$1"
  local clients="$2"
  local label="$3"
  local op="$4"
  local tp="$5"
  echo "${threads},${clients},${label},${op},${tp}" >> "${bench_csv}"
}

append_ycsb_row() {
  local workload="$1"
  local threads="$2"
  local clients="$3"
  local label="$4"
  local tp="$5"
  local out_csv="$6"
  echo "${workload},${threads},${clients},${label},${tp}" >> "${out_csv}"
}

base_desc="${BASE_IMG:-auto (download Ubuntu 24.04 if missing)}"
echo "[*] Recreating VMs (BASE_IMG=${base_desc})"
STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${BASE_IMG}" \
VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
VM1_CPUS="${VM1_CPUS}" VM2_CPUS="${VM2_CPUS}" \
VM_SGX_ENABLE=1 VM1_SGX_ENABLE=1 VM2_SGX_ENABLE=0 VM1_SGX_EPC_SIZE="${VM1_SGX_EPC_SIZE}" \
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

echo "[*] Checking SGX availability in vm1 ..."
ssh_vm1 "grep -m1 -w sgx /proc/cpuinfo >/dev/null 2>&1 || (echo '[!] vm1: SGX flag missing in /proc/cpuinfo' >&2; exit 1)"
ssh_vm1 "sudo modprobe intel_sgx >/dev/null 2>&1 || true"
ssh_vm1 "ls -l /dev/sgx_enclave /dev/sgx/enclave /dev/isgx 2>/dev/null | head -n 5 || (echo '[!] vm1: no SGX device node found' >&2; exit 1)"

echo "[*] Installing dependencies in guests ..."
ssh_retry_lock ssh_vm1 "vm1 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config ca-certificates curl lsb-release redis-server redis-tools net-tools tmux libsodium-dev"

ssh_retry_lock ssh_vm2 "vm2 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm2 "vm2 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release redis-tools net-tools tmux libsodium-dev default-jdk python-is-python3"

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

echo "[*] Installing Gramine in vm1 (SGX) ..."
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
ssh_vm1 "cd /mnt/hostshare/gramine && sudo make clean && sudo make links native ring USE_RUNTIME_GLIBC=1 CXL_RING_PATH='${RING_PATH_VM1}' CXL_RING_MAP_SIZE='${RING_MAP_SIZE}' CXL_RING_COUNT='8'"
ssh_vm1 "cd /mnt/hostshare/gramine && sudo make sgx-sign"

set +e
token_out="$(ssh_vm1 "cd /mnt/hostshare/gramine && sudo make sgx-token" 2>&1)"
token_rc=$?
set -e
if [[ "${token_rc}" -ne 0 ]]; then
  msg="[!] Failed to fetch SGX launch token in vm1 (sgx-token)."
  if [[ "${SGX_TOKEN_MODE}" == "require" ]]; then
    echo "${msg}" >&2
    printf '%s\n' "${token_out}" >&2
    echo "    Install/enable AESM in vm1 or provide a token via your SGX stack, then rerun." >&2
    exit 1
  fi
  if [[ "${SGX_TOKEN_MODE}" != "skip" ]]; then
    echo "${msg} Continuing (SGX_TOKEN_MODE=${SGX_TOKEN_MODE})." >&2
    printf '%s\n' "${token_out}" >&2
  fi
fi

echo "[*] Building ring client in vm2 (/tmp/cxl_ring_direct) ..."
ssh_vm2 "cd /mnt/hostshare/ring_client && gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct cxl_ring_direct.c -lsodium"

echo "[*] Building libsodium tunnel in guests (/tmp/cxl_sodium_tunnel) ..."
ssh_vm1 "make -C /mnt/hostshare/sodium_tunnel BIN=/tmp/cxl_sodium_tunnel"
ssh_vm2 "make -C /mnt/hostshare/sodium_tunnel BIN=/tmp/cxl_sodium_tunnel"

echo "[*] Building cxl_sec_mgr in vm1 (/tmp/cxl_sec_mgr) ..."
ssh_vm1 "make -C /mnt/hostshare/cxl_sec_mgr BIN=/tmp/cxl_sec_mgr"

echo "[*] Downloading YCSB and building ring JNI binding in vm2 ..."
ssh_vm2 "
set -euo pipefail
cd /tmp
if [[ ! -d ycsb-${YCSB_VERSION} ]]; then
  curl -fsSL -o ycsb.tgz https://github.com/brianfrankcooper/YCSB/releases/download/${YCSB_VERSION}/ycsb-${YCSB_VERSION}.tar.gz
  tar -xzf ycsb.tgz
fi
rm -rf /tmp/cxl_ring_binding /tmp/cxl-ycsb
cp -a /mnt/hostshare/ycsb/cxl_ring_binding /tmp/cxl_ring_binding
OUT_DIR=/tmp/cxl-ycsb YCSB_HOME=/tmp/ycsb-${YCSB_VERSION} bash /tmp/cxl_ring_binding/build.sh
cp /tmp/cxl-ycsb/cxl-ycsb-binding.jar /tmp/ycsb-${YCSB_VERSION}/lib/
"

echo "[*] Internal VM network (cxl0):"
ssh_vm1 "ip -brief addr show cxl0 2>/dev/null || true"
ssh_vm2 "ip -brief addr show cxl0 2>/dev/null || true"

wait_tcp_ready_vm2() {
  local host="$1"
  local port="$2"
  ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h ${host} -p ${port} ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"
}

wait_ring_ready_vm2() {
  local secure="$1"
  if [[ "${secure}" == "1" ]]; then
    ssh_vm2 "for i in \$(seq 1 200); do sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 5 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'secure ring not ready' >&2; exit 1"
  else
    ssh_vm2 "for i in \$(seq 1 200); do sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'ring not ready' >&2; exit 1"
  fi
}

run_default_bench_plain() {
  echo "[*] Default bench: native Redis (TCP)"
  local dir_vm1="/tmp/cxl-sec-dsm-sim-redis-plain-sweep-${ts}"
  ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_plain_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "rm -rf '${dir_vm1}' >/dev/null 2>&1 || true; mkdir -p '${dir_vm1}'"
  ssh_vm1 "tmux new-session -d -s redis_plain_sweep \"redis-server /mnt/hostshare/gramine/redis.conf --dir '${dir_vm1}' --dbfilename dump.rdb >/tmp/redis_plain_sweep.log 2>&1\""
  ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_plain_sweep.log >&2 || true; exit 1"
  wait_tcp_ready_vm2 "${VMNET_VM1_IP}" 6379

  local n
  for n in ${SWEEP_VALUES}; do
    local log="${RESULTS_DIR}/sgxvm_bench_plain_tcp_c${n}_t${n}_${ts}.log"
    ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
    echo "    clients=${n} threads=${n}"
    ssh_vm2 "redis-benchmark -h ${VMNET_VM1_IP} -p 6379 -t set,get -n ${REQ_N} -c ${n} --threads ${n} -P ${PIPELINE}" | tee "${log}"
    append_bench_row "${n}" "${n}" "SGXVMNativeTCP" "SET" "$(tp_from_redis_bench_log SET "${log}")"
    append_bench_row "${n}" "${n}" "SGXVMNativeTCP" "GET" "$(tp_from_redis_bench_log GET "${log}")"
  done

  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_plain_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "rm -rf '${dir_vm1}' >/dev/null 2>&1 || true"
}

run_default_bench_gramine_tcp() {
  echo "[*] Default bench: Gramine SGX Redis (TCP)"
  ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_native_sweep \"cd /mnt/hostshare/gramine && sudo gramine-sgx ./redis-native /repo/gramine/redis.conf >/tmp/redis_native_sweep.log 2>&1\""
  ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_sweep.log >&2 || true; exit 1"
  wait_tcp_ready_vm2 "${VMNET_VM1_IP}" 6379

  local n
  for n in ${SWEEP_VALUES}; do
    local log="${RESULTS_DIR}/sgxvm_bench_gramine_tcp_c${n}_t${n}_${ts}.log"
    ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
    echo "    clients=${n} threads=${n}"
    ssh_vm2 "redis-benchmark -h ${VMNET_VM1_IP} -p 6379 -t set,get -n ${REQ_N} -c ${n} --threads ${n} -P ${PIPELINE}" | tee "${log}"
    append_bench_row "${n}" "${n}" "GramineSGXVMNativeTCP" "SET" "$(tp_from_redis_bench_log SET "${log}")"
    append_bench_row "${n}" "${n}" "GramineSGXVMNativeTCP" "GET" "$(tp_from_redis_bench_log GET "${log}")"
  done

  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_default_bench_sodium() {
  echo "[*] Default bench: Gramine SGX Redis over libsodium-encrypted TCP (tunnel)"
  ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_sweep_sodium >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_native_sweep_sodium \"cd /mnt/hostshare/gramine && sudo gramine-sgx ./redis-native /repo/gramine/redis.conf >/tmp/redis_native_sweep_sodium.log 2>&1\""
  ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_sweep_sodium.log >&2 || true; exit 1"

  ssh_vm1 "tmux kill-session -t sodium_server_sweep >/dev/null 2>&1 || true"
  ssh_vm2 "tmux kill-session -t sodium_client_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s sodium_server_sweep \"/tmp/cxl_sodium_tunnel --mode server --listen 0.0.0.0:${SODIUM_PORT} --backend 127.0.0.1:6379 --key ${SODIUM_KEY_HEX} >/tmp/sodium_server_sweep_${ts}.log 2>&1\""
  ssh_vm2 "tmux new-session -d -s sodium_client_sweep \"/tmp/cxl_sodium_tunnel --mode client --listen 127.0.0.1:${SODIUM_LOCAL_PORT} --connect ${VMNET_VM1_IP}:${SODIUM_PORT} --key ${SODIUM_KEY_HEX} >/tmp/sodium_client_sweep_${ts}.log 2>&1\""

  ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tunnel not ready' >&2; exit 1"

  local n
  for n in ${SWEEP_VALUES}; do
    local log="${RESULTS_DIR}/sgxvm_bench_gramine_sodium_c${n}_t${n}_${ts}.log"
    ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
    echo "    clients=${n} threads=${n}"
    ssh_vm2 "redis-benchmark -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} -t set,get -n ${REQ_N} -c ${n} --threads ${n} -P ${PIPELINE}" | tee "${log}"
    append_bench_row "${n}" "${n}" "GramineSGXVMSodiumTCP" "SET" "$(tp_from_redis_bench_log SET "${log}")"
    append_bench_row "${n}" "${n}" "GramineSGXVMSodiumTCP" "GET" "$(tp_from_redis_bench_log GET "${log}")"
  done

  ssh_vm2 "tmux kill-session -t sodium_client_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t sodium_server_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_sweep_sodium >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_default_bench_ring() {
  echo "[*] Default bench: ring Redis under Gramine SGX (BAR2 shared memory)"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_ring_sweep \"cd /mnt/hostshare/gramine && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} gramine-sgx ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_sweep.log 2>&1\""
  wait_ring_ready_vm2 0

  local n
  for n in ${SWEEP_VALUES}; do
    local label="sgxvm_ring_sweep_c${n}_t${n}_${ts}"
    local log="${RESULTS_DIR}/${label}.log"
    local csv="${RESULTS_DIR}/${label}.csv"
    local n_per_thread=$(( (REQ_N + n - 1) / n ))
    ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
    echo "    threads=${n} (clients=${n} recorded)"
    ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${n_per_thread} --pipeline --threads ${n} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${label}.csv --label ${label}" | tee "${log}"
    ssh_vm2 "cat /tmp/${label}.csv" > "${csv}"
    append_bench_row "${n}" "${n}" "GramineSGXVMRing" "SET" "$(tp_from_ring_csv SET "${csv}")"
    append_bench_row "${n}" "${n}" "GramineSGXVMRing" "GET" "$(tp_from_ring_csv GET "${csv}")"
  done

  ssh_vm1 "tmux kill-session -t redis_ring_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_default_bench_ring_secure() {
  echo "[*] Default bench: secure ring Redis under Gramine SGX (ACL + software crypto)"
  ssh_vm1 "tmux kill-session -t cxl_sec_mgr_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_sweep_secure >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s cxl_sec_mgr_sweep \"sudo /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >/tmp/cxl_sec_mgr_sweep_${ts}.log 2>&1\""
  ssh_vm1 "tmux new-session -d -s redis_ring_sweep_secure \"cd /mnt/hostshare/gramine && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_SEC_ENABLE=1 CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 gramine-sgx ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_sweep_secure.log 2>&1\""
  wait_ring_ready_vm2 1

  local n
  for n in ${SWEEP_VALUES}; do
    local label="sgxvm_ring_secure_sweep_c${n}_t${n}_${ts}"
    local log="${RESULTS_DIR}/${label}.log"
    local csv="${RESULTS_DIR}/${label}.csv"
    local n_per_thread=$(( (REQ_N + n - 1) / n ))
    ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
    echo "    threads=${n} (clients=${n} recorded)"
    ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${n_per_thread} --pipeline --threads ${n} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${label}.csv --label ${label}" | tee "${log}"
    ssh_vm2 "cat /tmp/${label}.csv" > "${csv}"
    append_bench_row "${n}" "${n}" "GramineSGXVMRingSecure" "SET" "$(tp_from_ring_csv SET "${csv}")"
    append_bench_row "${n}" "${n}" "GramineSGXVMRingSecure" "GET" "$(tp_from_ring_csv GET "${csv}")"
  done

  ssh_vm1 "tmux kill-session -t redis_ring_sweep_secure >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t cxl_sec_mgr_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_ycsb_redis() {
  local workload_file="$1"
  local threads="$2"
  local host="$3"
  local port="$4"
  local out_load="$5"
  local out_run="$6"

  local cp="/tmp/ycsb-${YCSB_VERSION}/conf:/tmp/ycsb-${YCSB_VERSION}/lib/*:/tmp/ycsb-${YCSB_VERSION}/redis-binding/conf:/tmp/ycsb-${YCSB_VERSION}/redis-binding/lib/*"
  ssh_vm2 "java -cp '${cp}' site.ycsb.Client -db site.ycsb.db.RedisClient -s -P ${workload_file} -threads ${threads} -p redis.host=${host} -p redis.port=${port} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -load" | tee "${out_load}"
  ssh_vm2 "java -cp '${cp}' site.ycsb.Client -db site.ycsb.db.RedisClient -s -P ${workload_file} -threads ${threads} -p redis.host=${host} -p redis.port=${port} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -t" | tee "${out_run}"
}

run_ycsb_ring() {
  local workload_file="$1"
  local threads="$2"
  local secure="$3"
  local out_load="$4"
  local out_run="$5"

  local java_opts="-Dcxl.ring.jni.path=/tmp/cxl-ycsb/libcxlringjni.so"
  local cp="/tmp/ycsb-${YCSB_VERSION}/conf:/tmp/ycsb-${YCSB_VERSION}/lib/*"
  local props="-p cxl.ring.path=${RING_PATH_VM2} -p cxl.ring.map_size=${RING_MAP_SIZE} -p cxl.ring.count=${threads} -p cxl.ring.timeout_ms=${YCSB_TIMEOUT_MS}"
  if [[ "${secure}" == "1" ]]; then
    props="${props} -p cxl.ring.secure=true -p cxl.sec.mgr=${VMNET_VM1_IP}:${SEC_MGR_PORT} -p cxl.sec.node_id=2"
  else
    props="${props} -p cxl.ring.secure=false"
  fi

  ssh_vm2 "sudo -E java ${java_opts} -cp '${cp}' site.ycsb.Client -db site.ycsb.db.CxlRingClient -s -P ${workload_file} -threads ${threads} ${props} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -load" | tee "${out_load}"
  ssh_vm2 "sudo -E java ${java_opts} -cp '${cp}' site.ycsb.Client -db site.ycsb.db.CxlRingClient -s -P ${workload_file} -threads ${threads} ${props} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -t" | tee "${out_run}"
}

csv_for_workload_letter() {
  case "$1" in
    a|A) echo "${ycsb_csv_a}" ;;
    b|B) echo "${ycsb_csv_b}" ;;
    c|C) echo "${ycsb_csv_c}" ;;
    d|D) echo "${ycsb_csv_d}" ;;
    *) echo "" ;;
  esac
}

workload_file_for_letter() {
  local wl="$1"
  printf '/tmp/ycsb-%s/workloads/workload%s' "${YCSB_VERSION}" "${wl}"
}

run_ycsb_sweep_for_variant_plain() {
  echo "[*] YCSB: native Redis (TCP)"
  local dir_vm1="/tmp/cxl-sec-dsm-sim-redis-plain-ycsb-sweep-${ts}"
  ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_plain_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "rm -rf '${dir_vm1}' >/dev/null 2>&1 || true; mkdir -p '${dir_vm1}'"
  ssh_vm1 "tmux new-session -d -s redis_plain_ycsb_sweep \"redis-server /mnt/hostshare/gramine/redis.conf --dir '${dir_vm1}' --dbfilename dump.rdb >/tmp/redis_plain_ycsb_sweep.log 2>&1\""
  ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_plain_ycsb_sweep.log >&2 || true; exit 1"
  wait_tcp_ready_vm2 "${VMNET_VM1_IP}" 6379

  local wl
  for wl in a b c d; do
    local wfile
    wfile="$(workload_file_for_letter "${wl}")"
    local out_csv
    out_csv="$(csv_for_workload_letter "${wl}")"
    local n
    for n in ${SWEEP_VALUES}; do
      local tag="wl${wl}_c${n}_t${n}_${ts}"
      local load_log="${RESULTS_DIR}/sgxvm_ycsb_plain_tcp_load_${tag}.log"
      local run_log="${RESULTS_DIR}/sgxvm_ycsb_plain_tcp_run_${tag}.log"
      ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
      run_ycsb_redis "${wfile}" "${n}" "${VMNET_VM1_IP}" 6379 "${load_log}" "${run_log}"
      local tp
      tp="$(tp_from_ycsb_log "${run_log}")"
      echo "    workload=${wl} clients=${n} threads=${n} tp=${tp}"
      append_ycsb_row "${wl}" "${n}" "${n}" "SGXVMNativeTCP" "${tp}" "${out_csv}"
    done
  done

  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_plain_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "rm -rf '${dir_vm1}' >/dev/null 2>&1 || true"
}

run_ycsb_sweep_for_variant_gramine_tcp() {
  echo "[*] YCSB: Gramine SGX Redis (TCP)"
  ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_native_ycsb_sweep \"cd /mnt/hostshare/gramine && sudo gramine-sgx ./redis-native /repo/gramine/redis.conf >/tmp/redis_native_ycsb_sweep.log 2>&1\""
  ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_ycsb_sweep.log >&2 || true; exit 1"
  wait_tcp_ready_vm2 "${VMNET_VM1_IP}" 6379

  local wl
  for wl in a b c d; do
    local wfile
    wfile="$(workload_file_for_letter "${wl}")"
    local out_csv
    out_csv="$(csv_for_workload_letter "${wl}")"
    local n
    for n in ${SWEEP_VALUES}; do
      local tag="wl${wl}_c${n}_t${n}_${ts}"
      local load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_tcp_load_${tag}.log"
      local run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_tcp_run_${tag}.log"
      ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
      run_ycsb_redis "${wfile}" "${n}" "${VMNET_VM1_IP}" 6379 "${load_log}" "${run_log}"
      local tp
      tp="$(tp_from_ycsb_log "${run_log}")"
      echo "    workload=${wl} clients=${n} threads=${n} tp=${tp}"
      append_ycsb_row "${wl}" "${n}" "${n}" "GramineSGXVMNativeTCP" "${tp}" "${out_csv}"
    done
  done

  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_ycsb_sweep_for_variant_sodium() {
  echo "[*] YCSB: Gramine SGX Redis over libsodium-encrypted TCP (tunnel)"
  ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_ycsb_sweep_sodium >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_native_ycsb_sweep_sodium \"cd /mnt/hostshare/gramine && sudo gramine-sgx ./redis-native /repo/gramine/redis.conf >/tmp/redis_native_ycsb_sweep_sodium.log 2>&1\""
  ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_ycsb_sweep_sodium.log >&2 || true; exit 1"

  ssh_vm1 "tmux kill-session -t sodium_server_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm2 "tmux kill-session -t sodium_client_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s sodium_server_ycsb_sweep \"/tmp/cxl_sodium_tunnel --mode server --listen 0.0.0.0:${SODIUM_PORT} --backend 127.0.0.1:6379 --key ${SODIUM_KEY_HEX} >/tmp/sodium_server_ycsb_sweep_${ts}.log 2>&1\""
  ssh_vm2 "tmux new-session -d -s sodium_client_ycsb_sweep \"/tmp/cxl_sodium_tunnel --mode client --listen 127.0.0.1:${SODIUM_LOCAL_PORT} --connect ${VMNET_VM1_IP}:${SODIUM_PORT} --key ${SODIUM_KEY_HEX} >/tmp/sodium_client_ycsb_sweep_${ts}.log 2>&1\""
  ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tunnel not ready' >&2; exit 1"

  local wl
  for wl in a b c d; do
    local wfile
    wfile="$(workload_file_for_letter "${wl}")"
    local out_csv
    out_csv="$(csv_for_workload_letter "${wl}")"
    local n
    for n in ${SWEEP_VALUES}; do
      local tag="wl${wl}_c${n}_t${n}_${ts}"
      local load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_sodium_load_${tag}.log"
      local run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_sodium_run_${tag}.log"
      ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
      run_ycsb_redis "${wfile}" "${n}" "127.0.0.1" "${SODIUM_LOCAL_PORT}" "${load_log}" "${run_log}"
      local tp
      tp="$(tp_from_ycsb_log "${run_log}")"
      echo "    workload=${wl} clients=${n} threads=${n} tp=${tp}"
      append_ycsb_row "${wl}" "${n}" "${n}" "GramineSGXVMSodiumTCP" "${tp}" "${out_csv}"
    done
  done

  ssh_vm2 "tmux kill-session -t sodium_client_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t sodium_server_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_native_ycsb_sweep_sodium >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_ycsb_sweep_for_variant_ring() {
  echo "[*] YCSB: ring Redis under Gramine SGX (BAR2) via JNI binding"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_ring_ycsb_sweep \"cd /mnt/hostshare/gramine && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} gramine-sgx ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_ycsb_sweep.log 2>&1\""
  wait_ring_ready_vm2 0

  local wl
  for wl in a b c d; do
    local wfile
    wfile="$(workload_file_for_letter "${wl}")"
    local out_csv
    out_csv="$(csv_for_workload_letter "${wl}")"
    local n
    for n in ${SWEEP_VALUES}; do
      local tag="wl${wl}_c${n}_t${n}_${ts}"
      local load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_load_${tag}.log"
      local run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_run_${tag}.log"
      ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
      run_ycsb_ring "${wfile}" "${n}" 0 "${load_log}" "${run_log}"
      local tp
      tp="$(tp_from_ycsb_log "${run_log}")"
      echo "    workload=${wl} clients=${n} threads=${n} tp=${tp}"
      append_ycsb_row "${wl}" "${n}" "${n}" "GramineSGXVMRing" "${tp}" "${out_csv}"
    done
  done

  ssh_vm1 "tmux kill-session -t redis_ring_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

run_ycsb_sweep_for_variant_ring_secure() {
  echo "[*] YCSB: secure ring Redis under Gramine SGX (ACL + software crypto) via JNI binding"
  ssh_vm1 "tmux kill-session -t cxl_sec_mgr_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_ycsb_sweep_secure >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s cxl_sec_mgr_ycsb_sweep \"sudo /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >/tmp/cxl_sec_mgr_ycsb_sweep_${ts}.log 2>&1\""
  ssh_vm1 "tmux new-session -d -s redis_ring_ycsb_sweep_secure \"cd /mnt/hostshare/gramine && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_SEC_ENABLE=1 CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 gramine-sgx ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_ycsb_sweep_secure.log 2>&1\""
  wait_ring_ready_vm2 1

  local wl
  for wl in a b c d; do
    local wfile
    wfile="$(workload_file_for_letter "${wl}")"
    local out_csv
    out_csv="$(csv_for_workload_letter "${wl}")"
    local n
    for n in ${SWEEP_VALUES}; do
      local tag="wl${wl}_c${n}_t${n}_${ts}"
      local load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_secure_load_${tag}.log"
      local run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_secure_run_${tag}.log"
      ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
      run_ycsb_ring "${wfile}" "${n}" 1 "${load_log}" "${run_log}"
      local tp
      tp="$(tp_from_ycsb_log "${run_log}")"
      echo "    workload=${wl} clients=${n} threads=${n} tp=${tp}"
      append_ycsb_row "${wl}" "${n}" "${n}" "GramineSGXVMRingSecure" "${tp}" "${out_csv}"
    done
  done

  ssh_vm1 "tmux kill-session -t redis_ring_ycsb_sweep_secure >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t cxl_sec_mgr_ycsb_sweep >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
}

echo "[*] Running default benchmark sweep (clients=threads in {${SWEEP_VALUES}}) ..."
run_default_bench_plain
run_default_bench_gramine_tcp
run_default_bench_sodium
run_default_bench_ring
run_default_bench_ring_secure

echo "[*] Running YCSB sweep (workloads a/b/c/d; clients=threads in {${SWEEP_VALUES}}) ..."
run_ycsb_sweep_for_variant_plain
run_ycsb_sweep_for_variant_gramine_tcp
run_ycsb_sweep_for_variant_sodium
run_ycsb_sweep_for_variant_ring
run_ycsb_sweep_for_variant_ring_secure

echo "[+] Done."
echo "    ${bench_csv}"
echo "    ${ycsb_csv_a}"
echo "    ${ycsb_csv_b}"
echo "    ${ycsb_csv_c}"
echo "    ${ycsb_csv_d}"
