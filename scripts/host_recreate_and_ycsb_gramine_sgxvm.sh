#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 from a fresh Ubuntu cloud image, enable SGX virtualization in VM1,
# then run YCSB against five Redis variants with Redis running under Gramine SGX
# *inside the guest*:
# 1) Native Redis (no Gramine) over TCP (VM2 -> VM1 over internal NIC).
# 2) Native Redis under gramine-sgx over TCP (VM2 -> VM1 over internal NIC).
# 3) Native Redis under gramine-sgx over libsodium-encrypted TCP (VM2 -> VM1 via user-space tunnel).
# 4) Ring-enabled Redis under gramine-sgx (VM2 -> VM1 over shared ivshmem BAR2) via JNI binding.
# 5) Secure ring Redis under gramine-sgx (ACL + software crypto in shared memory) via JNI binding.
#
# Usage:
#   sudo -E bash scripts/host_recreate_and_ycsb_gramine_sgxvm.sh
#
# Tunables (env):
#   BASE_IMG             : ubuntu cloud image path (optional; if unset, host_quickstart downloads 24.04 by default)
#   VM1_SSH/VM2_SSH      : forwarded SSH ports (default: 2222/2223)
#   VM1_CPUS/VM2_CPUS    : vCPUs per VM (default: 8)
#   VMNET_VM1_IP         : VM1 internal IP on cxl0 (default: 192.168.100.1)
#   RING_MAP_SIZE        : BAR2 mmap size (default: 134217728 = 128MB)
#   SODIUM_KEY_HEX       : pre-shared key for libsodium tunnel (hex64)
#   SODIUM_PORT          : vm1 tunnel listen port on cxl0 (default: 6380)
#   SODIUM_LOCAL_PORT    : vm2 local tunnel listen port (default: 6380)
#   SEC_MGR_PORT         : TCP port for cxl_sec_mgr inside vm1 (default: 19001)
#
# YCSB knobs:
#   YCSB_VERSION         : YCSB release version (default: 0.17.0)
#   YCSB_THREADS         : YCSB client threads (default: 4; must be <=8 for ring modes)
#   YCSB_RECORDCOUNT     : YCSB recordcount (default: 10000)
#   YCSB_OPERATIONCOUNT  : YCSB operationcount (default: 10000)
#   YCSB_WORKLOAD        : workload file path inside guest (default: /mnt/hostshare/ycsb/workloads/workload_cxl_crudscan)
#   YCSB_TIMEOUT_MS      : ring JNI timeout per op (default: 5000)
#
# SGX-in-guest knobs:
#   VM1_SGX_EPC_SIZE      : EPC section size for VM1 (default: 512M)
#   SGX_TOKEN_MODE        : auto|require|skip (default: auto)

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

RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}" # 128MB

SODIUM_KEY_HEX="${SODIUM_KEY_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
SODIUM_PORT="${SODIUM_PORT:-6380}"
SODIUM_LOCAL_PORT="${SODIUM_LOCAL_PORT:-6380}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19001}"

YCSB_VERSION="${YCSB_VERSION:-0.17.0}"
YCSB_THREADS="${YCSB_THREADS:-4}"
YCSB_RECORDCOUNT="${YCSB_RECORDCOUNT:-10000}"
YCSB_OPERATIONCOUNT="${YCSB_OPERATIONCOUNT:-10000}"
YCSB_WORKLOAD="${YCSB_WORKLOAD:-/mnt/hostshare/ycsb/workloads/workload_cxl_crudscan}"
YCSB_TIMEOUT_MS="${YCSB_TIMEOUT_MS:-5000}"

if [[ "${YCSB_THREADS}" -gt 8 ]]; then
  echo "[!] YCSB_THREADS=${YCSB_THREADS} exceeds MAX_RINGS=8; reduce thread count for ring modes." >&2
  exit 1
fi

VM1_SGX_EPC_SIZE="${VM1_SGX_EPC_SIZE:-512M}"
SGX_TOKEN_MODE="${SGX_TOKEN_MODE:-auto}"

BASE_IMG="${BASE_IMG:-}"

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-ycsb-sgxvm.XXXXXX)"
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
ssh_vm1 "cd /mnt/hostshare/gramine && sudo make clean && sudo make links native ring USE_RUNTIME_GLIBC=1 CXL_RING_PATH='${RING_PATH_VM1}' CXL_RING_MAP_SIZE='${RING_MAP_SIZE}' CXL_RING_COUNT='${YCSB_THREADS}'"
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

ts="$(date +%Y%m%d_%H%M%S)"
plain_load_log="${RESULTS_DIR}/sgxvm_ycsb_plain_tcp_load_${ts}.log"
plain_run_log="${RESULTS_DIR}/sgxvm_ycsb_plain_tcp_run_${ts}.log"
native_load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_tcp_load_${ts}.log"
native_run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_tcp_run_${ts}.log"
sodium_load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_sodium_load_${ts}.log"
sodium_run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_sodium_run_${ts}.log"
ring_load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_load_${ts}.log"
ring_run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_run_${ts}.log"
ring_secure_load_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_secure_load_${ts}.log"
ring_secure_run_log="${RESULTS_DIR}/sgxvm_ycsb_gramine_ring_secure_run_${ts}.log"
compare_csv="${RESULTS_DIR}/sgxvm_ycsb_compare_${ts}.csv"

echo "[*] Internal VM network (cxl0):"
ssh_vm1 "ip -brief addr show cxl0 2>/dev/null || true"
ssh_vm2 "ip -brief addr show cxl0 2>/dev/null || true"

run_ycsb_redis() {
  local host="$1"
  local port="$2"
  local out_load="$3"
  local out_run="$4"

  local cp="/tmp/ycsb-${YCSB_VERSION}/conf:/tmp/ycsb-${YCSB_VERSION}/lib/*:/tmp/ycsb-${YCSB_VERSION}/redis-binding/conf:/tmp/ycsb-${YCSB_VERSION}/redis-binding/lib/*"

  ssh_vm2 "java -cp '${cp}' site.ycsb.Client -db site.ycsb.db.RedisClient -s -P ${YCSB_WORKLOAD} -threads ${YCSB_THREADS} -p redis.host=${host} -p redis.port=${port} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -load" | tee "${out_load}"
  ssh_vm2 "java -cp '${cp}' site.ycsb.Client -db site.ycsb.db.RedisClient -s -P ${YCSB_WORKLOAD} -threads ${YCSB_THREADS} -p redis.host=${host} -p redis.port=${port} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -t" | tee "${out_run}"
}

run_ycsb_ring() {
  local secure="$1"
  local out_load="$2"
  local out_run="$3"

  local java_opts="-Dcxl.ring.jni.path=/tmp/cxl-ycsb/libcxlringjni.so"
  local cp="/tmp/ycsb-${YCSB_VERSION}/conf:/tmp/ycsb-${YCSB_VERSION}/lib/*"
  local props="-p cxl.ring.path=${RING_PATH_VM2} -p cxl.ring.map_size=${RING_MAP_SIZE} -p cxl.ring.count=${YCSB_THREADS} -p cxl.ring.timeout_ms=${YCSB_TIMEOUT_MS}"
  if [[ "${secure}" == "1" ]]; then
    props="${props} -p cxl.ring.secure=true -p cxl.sec.mgr=${VMNET_VM1_IP}:${SEC_MGR_PORT} -p cxl.sec.node_id=2"
  else
    props="${props} -p cxl.ring.secure=false"
  fi

  ssh_vm2 "sudo -E java ${java_opts} -cp '${cp}' site.ycsb.Client -db site.ycsb.db.CxlRingClient -s -P ${YCSB_WORKLOAD} -threads ${YCSB_THREADS} ${props} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -load" | tee "${out_load}"
  ssh_vm2 "sudo -E java ${java_opts} -cp '${cp}' site.ycsb.Client -db site.ycsb.db.CxlRingClient -s -P ${YCSB_WORKLOAD} -threads ${YCSB_THREADS} ${props} -p recordcount=${YCSB_RECORDCOUNT} -p operationcount=${YCSB_OPERATIONCOUNT} -t" | tee "${out_run}"
}

echo "[*] YCSB 1/5: native Redis (no Gramine) (TCP via cxl0)"
plain_dir_vm1="/tmp/cxl-sec-dsm-sim-redis-plain-ycsb-${ts}"
ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_plain_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "rm -rf '${plain_dir_vm1}' >/dev/null 2>&1 || true; mkdir -p '${plain_dir_vm1}'"
ssh_vm1 "tmux new-session -d -s redis_plain_ycsb \"redis-server /mnt/hostshare/gramine/redis.conf --dir '${plain_dir_vm1}' --dbfilename dump.rdb >/tmp/redis_plain_ycsb.log 2>&1\""
ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_plain_ycsb.log >&2 || true; exit 1"
ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h ${VMNET_VM1_IP} -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"
ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
run_ycsb_redis "${VMNET_VM1_IP}" 6379 "${plain_load_log}" "${plain_run_log}"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_plain_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "rm -rf '${plain_dir_vm1}' >/dev/null 2>&1 || true"

echo "[*] YCSB 2/5: native Redis under Gramine SGX (TCP via cxl0)"
ssh_vm1 "sudo systemctl stop redis-server >/dev/null 2>&1 || true"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_native_ycsb \"cd /mnt/hostshare/gramine && sudo gramine-sgx ./redis-native /repo/gramine/redis.conf >/tmp/redis_native_ycsb.log 2>&1\""
ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_ycsb.log >&2 || true; exit 1"
ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h ${VMNET_VM1_IP} -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"
ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
run_ycsb_redis "${VMNET_VM1_IP}" 6379 "${native_load_log}" "${native_run_log}"

echo "[*] YCSB 3/5: native Redis over libsodium-encrypted TCP (tunnel)"
ssh_vm1 "tmux kill-session -t sodium_server_ycsb >/dev/null 2>&1 || true"
ssh_vm2 "tmux kill-session -t sodium_client_ycsb >/dev/null 2>&1 || true"

ssh_vm1 "tmux new-session -d -s sodium_server_ycsb \"/tmp/cxl_sodium_tunnel --mode server --listen 0.0.0.0:${SODIUM_PORT} --backend 127.0.0.1:6379 --key ${SODIUM_KEY_HEX} >/tmp/sodium_server_ycsb_${ts}.log 2>&1\""
ssh_vm2 "tmux new-session -d -s sodium_client_ycsb \"/tmp/cxl_sodium_tunnel --mode client --listen 127.0.0.1:${SODIUM_LOCAL_PORT} --connect ${VMNET_VM1_IP}:${SODIUM_PORT} --key ${SODIUM_KEY_HEX} >/tmp/sodium_client_ycsb_${ts}.log 2>&1\""

ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tunnel not ready' >&2; exit 1"
ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
run_ycsb_redis "127.0.0.1" "${SODIUM_LOCAL_PORT}" "${sodium_load_log}" "${sodium_run_log}"

ssh_vm1 "tmux kill-session -t sodium_server_ycsb >/dev/null 2>&1 || true"
ssh_vm2 "tmux kill-session -t sodium_client_ycsb >/dev/null 2>&1 || true"

ssh_vm1 "tmux kill-session -t redis_native_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

echo "[*] YCSB 4/5: ring Redis under Gramine SGX (BAR2) via JNI binding"
ssh_vm1 "tmux kill-session -t redis_ring_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_ring_ycsb \"cd /mnt/hostshare/gramine && sudo gramine-sgx ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_ycsb.log 2>&1\""
ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; exit 1" >/dev/null 2>&1 || true
ssh_vm2 "for i in \$(seq 1 200); do sudo timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'ring not ready' >&2; exit 1"
ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
run_ycsb_ring 0 "${ring_load_log}" "${ring_run_log}"
ssh_vm1 "tmux kill-session -t redis_ring_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

echo "[*] YCSB 5/5: secure ring Redis under Gramine SGX (ACL + software crypto) via JNI binding"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_ycsb_secure >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s cxl_sec_mgr_ycsb \"sudo /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >/tmp/cxl_sec_mgr_ycsb_${ts}.log 2>&1\""
ssh_vm1 "tmux new-session -d -s redis_ring_ycsb_secure \"cd /mnt/hostshare/gramine && sudo env CXL_SEC_ENABLE=1 CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 gramine-sgx ./redis-ring /repo/gramine/redis.conf >/tmp/redis_ring_ycsb_secure.log 2>&1\""
ssh_vm2 "for i in \$(seq 1 200); do sudo timeout 5 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'secure ring not ready' >&2; exit 1"
ssh_vm1 "redis-cli -p 6379 flushall >/dev/null 2>&1 || true"
run_ycsb_ring 1 "${ring_secure_load_log}" "${ring_secure_run_log}"
ssh_vm1 "tmux kill-session -t redis_ring_ycsb_secure >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr_ycsb >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

tp_from_log() {
  awk -F', ' '/\[OVERALL\], Throughput\(ops\/sec\),/ {print $3; exit}' "$1" 2>/dev/null || true
}

plain_tp="$(tp_from_log "${plain_run_log}")"
native_tp="$(tp_from_log "${native_run_log}")"
sodium_tp="$(tp_from_log "${sodium_run_log}")"
ring_tp="$(tp_from_log "${ring_run_log}")"
ring_secure_tp="$(tp_from_log "${ring_secure_run_log}")"

{
  echo "label,throughput_ops_sec"
  echo "SGXVMNativeTCP,${plain_tp}"
  echo "GramineSGXVMNativeTCP,${native_tp}"
  echo "GramineSGXVMSodiumTCP,${sodium_tp}"
  echo "GramineSGXVMRing,${ring_tp}"
  echo "GramineSGXVMRingSecure,${ring_secure_tp}"
} > "${compare_csv}"

echo "[+] Done."
echo "    ${plain_load_log}"
echo "    ${plain_run_log}"
echo "    ${native_load_log}"
echo "    ${native_run_log}"
echo "    ${sodium_load_log}"
echo "    ${sodium_run_log}"
echo "    ${ring_load_log}"
echo "    ${ring_run_log}"
echo "    ${ring_secure_load_log}"
echo "    ${ring_secure_run_log}"
echo "    ${compare_csv}"
