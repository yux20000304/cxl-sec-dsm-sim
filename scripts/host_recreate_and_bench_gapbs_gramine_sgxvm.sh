#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 from a fresh Ubuntu cloud image, enable SGX virtualization,
# then run GAPBS benchmarks with Gramine SGX inside the guests (two VMs + ivshmem).
#
# Benchmarks (mirrors the GAPBS multihost matrix):
# 1) Native:                    GAPBS native binary (no Gramine, no shared memory)
# 2) MultihostRing:             ring binary over shared memory (no Gramine)
# 3) GramineSGXVMRing:          ring binary over shared memory (under gramine-sgx)
# 4) GramineSGXVMCrypto:        ring-secure + libsodium crypto (per-VM key + common key; no mgr)
# 5) GramineSGXVMSecure:        ring-secure + cxl_sec_mgr ACL/key table (permission-managed crypto)
#
# Requirements on host:
# - SGX-capable hardware with SGX enabled in BIOS (host /proc/cpuinfo exposes 'sgx').
# - KVM acceleration available (/dev/kvm) and nested virtualization enabled if needed.
# - QEMU built with SGX virtualization support (must accept `-object memory-backend-epc,...`).
#
# Usage:
#   sudo -E bash scripts/host_recreate_and_bench_gapbs_gramine_sgxvm.sh
#
# Tunables (env):
#   BASE_IMG       : ubuntu cloud image path (optional; host_quickstart auto-detects noble)
#   VM1_SSH/VM2_SSH: forwarded SSH ports (default: 2222/2223)
#   SKIP_RECREATE  : 1 to reuse existing SGX-enabled VMs (default: 0)
#   SSH_KEY        : optional ssh private key path (used when SKIP_RECREATE=1)
#   GAPBS_KERNEL   : bfs|cc|pr|... (default: bfs)
#   SCALE          : -g scale for Kronecker graph (default: 18)
#   DEGREE         : -k degree for synthetic graph (default: 16)
#   TRIALS         : -n trials (default: 3)
#   OMP_THREADS    : OMP_NUM_THREADS (default: 4)
#   RING_PATH      : BAR2 sysfs resource file (default: /sys/bus/pci/devices/0000:00:02.0/resource2)
#   RING_MAP_SIZE  : mmap size in bytes (default: 134217728 = 128MB)
#   SEC_MGR_PORT   : TCP port for cxl_sec_mgr inside vm1 (default: 19002)
#
# SGX-in-guest knobs:
#   VM1_SGX_EPC_SIZE: EPC section size for VM1 (default: 256M)
#   VM2_SGX_EPC_SIZE: EPC section size for VM2 (default: 256M)
#   SGX_EPC_PREALLOC: auto|on|off EPC preallocation mode (default: auto)
#   SGX_TOKEN_MODE  : auto|require|skip (default: auto)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

SKIP_RECREATE="${SKIP_RECREATE:-0}"
SSH_KEY="${SSH_KEY:-}"

if [[ "${SKIP_RECREATE}" != "1" && "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"

GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
SCALE="${SCALE:-18}"
DEGREE="${DEGREE:-16}"
TRIALS="${TRIALS:-3}"
OMP_THREADS="${OMP_THREADS:-4}"

RING_PATH="${RING_PATH:-/sys/bus/pci/devices/0000:00:02.0/resource2}"
RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19002}"

VM1_SGX_EPC_SIZE="${VM1_SGX_EPC_SIZE:-256M}"
VM2_SGX_EPC_SIZE="${VM2_SGX_EPC_SIZE:-256M}"
SGX_EPC_PREALLOC="${SGX_EPC_PREALLOC:-auto}"
SGX_TOKEN_MODE="${SGX_TOKEN_MODE:-auto}"

BASE_IMG="${BASE_IMG:-}"

tmpdir=""
sshkey=""
sec_mgr_pid=""

cleanup() {
  local rc=$?
  if [[ -n "${sec_mgr_pid}" ]] && declare -F ssh_vm1 >/dev/null 2>&1; then
    ssh_vm1 "sudo -n bash -lc 'kill ${sec_mgr_pid} >/dev/null 2>&1 || true'" || true
  fi
  [[ -n "${tmpdir}" ]] && rm -rf "${tmpdir}"
  return "${rc}"
}
trap cleanup EXIT

ssh_opts=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

if [[ "${SKIP_RECREATE}" != "1" ]]; then
  tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-gapbs-sgxvm.XXXXXX)"
  sshkey="${tmpdir}/vm_sshkey"
  ssh-keygen -t ed25519 -N "" -f "${sshkey}" -q
  ssh_opts+=( -i "${sshkey}" )
elif [[ -n "${SSH_KEY}" ]]; then
  ssh_opts+=( -i "${SSH_KEY}" )
fi

ssh_vm1() { ssh "${ssh_opts[@]}" -p "${VM1_SSH}" ubuntu@127.0.0.1 "$@"; }
ssh_vm2() { ssh "${ssh_opts[@]}" -p "${VM2_SSH}" ubuntu@127.0.0.1 "$@"; }
# Gramine SGX may fail to initialize stdio when SSH doesn't allocate a PTY on
# some guest images. Force a TTY for `gramine-sgx` runs.
ssh_vm1_tty() { ssh -tt "${ssh_opts[@]}" -p "${VM1_SSH}" ubuntu@127.0.0.1 "$@"; }
ssh_vm2_tty() { ssh -tt "${ssh_opts[@]}" -p "${VM2_SSH}" ubuntu@127.0.0.1 "$@"; }

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

    if printf '%s' "${out}" | grep -qiE 'could not get lock|unable to lock directory|unable to acquire the dpkg frontend lock|could not open lock file'; then
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

if [[ "${SKIP_RECREATE}" != "1" ]]; then
  base_desc="${BASE_IMG:-auto (prefer noble 24.04 if present)}"
  echo "[*] Recreating SGX VMs (BASE_IMG=${base_desc})"
  STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${BASE_IMG}" \
    VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
    VM_SGX_ENABLE=1 VM1_SGX_ENABLE=1 VM2_SGX_ENABLE=1 \
    VM1_SGX_EPC_SIZE="${VM1_SGX_EPC_SIZE}" VM2_SGX_EPC_SIZE="${VM2_SGX_EPC_SIZE}" \
    SGX_EPC_PREALLOC="${SGX_EPC_PREALLOC}" \
    CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
    bash "${ROOT}/scripts/host_quickstart.sh"
else
  echo "[*] SKIP_RECREATE=1: reusing existing VMs (vm1=${VM1_SSH}, vm2=${VM2_SSH})"
fi

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

echo "[*] Checking SGX availability in guests ..."
for vm in ssh_vm1 ssh_vm2; do
  "${vm}" "grep -m1 -w sgx /proc/cpuinfo >/dev/null 2>&1 || (echo '[!] guest: SGX flag missing in /proc/cpuinfo' >&2; exit 1)"
  "${vm}" "sudo modprobe intel_sgx >/dev/null 2>&1 || true"
  "${vm}" "ls -l /dev/sgx_enclave /dev/sgx/enclave /dev/isgx 2>/dev/null | head -n 5 || (echo '[!] guest: no SGX device node found' >&2; exit 1)"
done

echo "[*] Installing dependencies in guests ..."
for vm in ssh_vm1 ssh_vm2; do
  ssh_retry_lock "${vm}" "${vm} apt-get update" "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update"
  ssh_retry_lock "${vm}" "${vm} apt-get install deps" "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config libsodium-dev ca-certificates curl lsb-release tmux net-tools"
done

echo "[*] Installing Gramine (SGX) in guests ..."
for vm in ssh_vm1 ssh_vm2; do
  "${vm}" '
set -e
sudo -n mkdir -p /etc/apt/keyrings
sc="$(lsb_release -sc)"
key="/etc/apt/keyrings/gramine-keyring-${sc}.gpg"
list="/etc/apt/sources.list.d/gramine.list"
if [[ ! -f "${key}" ]]; then
  sudo -n curl -fsSLo "${key}" "https://packages.gramineproject.io/gramine-keyring-${sc}.gpg"
fi
if [[ ! -f "${list}" ]]; then
  echo "deb [arch=amd64 signed-by=${key}] https://packages.gramineproject.io/ ${sc} main" | sudo -n tee "${list}" >/dev/null
fi
'
  ssh_retry_lock "${vm}" "${vm} apt-get update (gramine repo)" "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update"
  ssh_retry_lock "${vm}" "${vm} apt-get install gramine" "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y gramine"
done

echo "[*] Building GAPBS (native + ring + ring-secure) in vm1 ..."
ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n make clean && sudo -n make -j2 all ring ring-secure"

echo "[*] Building cxl_sec_mgr in vm1 (/tmp/cxl_sec_mgr) ..."
ssh_vm1 "cd /mnt/hostshare/cxl_sec_mgr && sudo -n make clean && sudo -n make -j2 && sudo -n cp -f cxl_sec_mgr /tmp/cxl_sec_mgr"

echo "[*] Building Gramine manifests + SGX artifacts for GAPBS in vm1 ..."
ssh_vm1 "cd /mnt/hostshare/gramine && sudo -n make links gapbs-native.manifest gapbs-ring.manifest gapbs-ring-secure.manifest GAPBS_KERNEL='${GAPBS_KERNEL}' CXL_RING_PATH='${RING_PATH}' CXL_RING_MAP_SIZE='${RING_MAP_SIZE}' USE_RUNTIME_GLIBC=1"
ssh_vm1 "cd /mnt/hostshare/gramine && sudo -n make sgx-sign-gapbs USE_RUNTIME_GLIBC=1"

set +e
token_out="$(ssh_vm1 "cd /mnt/hostshare/gramine && sudo -n make sgx-token-gapbs" 2>&1)"
token_rc=$?
set -e
if [[ "${token_rc}" -ne 0 ]]; then
  msg="[!] Failed to fetch SGX launch token in vm1 (sgx-token-gapbs)."
  if [[ "${SGX_TOKEN_MODE}" == "require" ]]; then
    echo "${msg}" >&2
    printf '%s\n' "${token_out}" >&2
    exit 1
  fi
  if [[ "${SGX_TOKEN_MODE}" != "skip" ]]; then
    echo "${msg} Continuing (SGX_TOKEN_MODE=${SGX_TOKEN_MODE})." >&2
    printf '%s\n' "${token_out}" >&2
  fi
fi

vm1_ip="$(ssh_vm1 "ip -4 -o addr show dev cxl0 | awk '{print \$4}' | cut -d/ -f1")"
vm2_ip="$(ssh_vm2 "ip -4 -o addr show dev cxl0 | awk '{print \$4}' | cut -d/ -f1")"
if [[ -z "${vm1_ip}" || -z "${vm2_ip}" ]]; then
  echo "[!] Failed to detect cxl0 IPs in guests (expected internal NIC via VMNET_ENABLE=1)" >&2
  exit 1
fi
echo "[*] Internal VM network (cxl0): vm1=${vm1_ip} vm2=${vm2_ip}"

ts="$(date +%Y%m%d_%H%M%S)"

native_vm1_log="${RESULTS_DIR}/gapbs_sgxvm_native_vm1_${GAPBS_KERNEL}_${ts}.log"
native_vm2_log="${RESULTS_DIR}/gapbs_sgxvm_native_vm2_${GAPBS_KERNEL}_${ts}.log"

plain_ring_pub_log="${RESULTS_DIR}/gapbs_sgxvm_multihost_ring_publish_${GAPBS_KERNEL}_${ts}.log"
plain_ring_vm1_log="${RESULTS_DIR}/gapbs_sgxvm_multihost_ring_vm1_${GAPBS_KERNEL}_${ts}.log"
plain_ring_vm2_log="${RESULTS_DIR}/gapbs_sgxvm_multihost_ring_vm2_${GAPBS_KERNEL}_${ts}.log"

sgx_ring_pub_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_ring_publish_${GAPBS_KERNEL}_${ts}.log"
sgx_ring_vm1_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_ring_vm1_${GAPBS_KERNEL}_${ts}.log"
sgx_ring_vm2_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_ring_vm2_${GAPBS_KERNEL}_${ts}.log"

sgx_crypto_pub_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_crypto_publish_${GAPBS_KERNEL}_${ts}.log"
sgx_crypto_vm1_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_crypto_vm1_${GAPBS_KERNEL}_${ts}.log"
sgx_crypto_vm2_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_crypto_vm2_${GAPBS_KERNEL}_${ts}.log"

sec_mgr_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_secure_mgr_${GAPBS_KERNEL}_${ts}.log"
sgx_secure_pub_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_secure_publish_${GAPBS_KERNEL}_${ts}.log"
sgx_secure_vm1_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_secure_vm1_${GAPBS_KERNEL}_${ts}.log"
sgx_secure_vm2_log="${RESULTS_DIR}/gapbs_sgxvm_gramine_sgx_secure_vm2_${GAPBS_KERNEL}_${ts}.log"

compare_csv="${RESULTS_DIR}/gapbs_sgxvm_compare_${GAPBS_KERNEL}_${ts}.csv"

echo "[*] Benchmark 1/5: Native (no Gramine) in vm1"
ssh_vm1 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' ./'${GAPBS_KERNEL}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
  | tee "${native_vm1_log}"

echo "[*] Benchmark 1/5: Native (no Gramine) in vm2"
ssh_vm2 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' ./'${GAPBS_KERNEL}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
  | tee "${native_vm2_log}"

echo "[*] Benchmark 2/5: MultihostRing (no Gramine) publish in vm1"
ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_PATH='${RING_PATH}' GAPBS_CXL_MAP_SIZE='${RING_MAP_SIZE}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 ./'${GAPBS_KERNEL}-ring' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${plain_ring_pub_log}"

echo "[*] Benchmark 2/5: MultihostRing (no Gramine) attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_PATH='${RING_PATH}' GAPBS_CXL_MAP_SIZE='${RING_MAP_SIZE}' GAPBS_CXL_MODE=attach ./'${GAPBS_KERNEL}-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${plain_ring_vm1_log}" 2>&1
) &
pid_plain_ring_vm1=$!

(
  ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_PATH='${RING_PATH}' GAPBS_CXL_MAP_SIZE='${RING_MAP_SIZE}' GAPBS_CXL_MODE=attach ./'${GAPBS_KERNEL}-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${plain_ring_vm2_log}" 2>&1
) &
pid_plain_ring_vm2=$!

wait "${pid_plain_ring_vm1}"
wait "${pid_plain_ring_vm2}"

echo "[*] Benchmark 3/5: GramineSGXVMRing publish in vm1"
ssh_vm1_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 gramine-sgx ./'gapbs-ring' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${sgx_ring_pub_log}"

echo "[*] Benchmark 3/5: GramineSGXVMRing attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=attach gramine-sgx ./'gapbs-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${sgx_ring_vm1_log}" 2>&1
) &
pid_sgx_ring_vm1=$!

(
  ssh_vm2_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=attach gramine-sgx ./'gapbs-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${sgx_ring_vm2_log}" 2>&1
) &
pid_sgx_ring_vm2=$!

wait "${pid_sgx_ring_vm1}"
wait "${pid_sgx_ring_vm2}"

crypto_key_vm1_hex="$(openssl rand -hex 32)"
crypto_key_vm2_hex="$(openssl rand -hex 32)"
crypto_key_common_hex="$(openssl rand -hex 32)"

echo "[*] Benchmark 4/5: GramineSGXVMCrypto publish in vm1 (libsodium; per-VM key + common key; no mgr)"
ssh_vm1_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX='${crypto_key_vm1_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' gramine-sgx ./'gapbs-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${sgx_crypto_pub_log}"

echo "[*] Benchmark 4/5: GramineSGXVMCrypto attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX='${crypto_key_vm1_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' gramine-sgx ./'gapbs-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${sgx_crypto_vm1_log}" 2>&1
) &
pid_sgx_crypto_vm1=$!

(
  ssh_vm2_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX='${crypto_key_vm2_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' gramine-sgx ./'gapbs-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${sgx_crypto_vm2_log}" 2>&1
) &
pid_sgx_crypto_vm2=$!

wait "${pid_sgx_crypto_vm1}"
wait "${pid_sgx_crypto_vm2}"

echo "[*] Benchmark 5/5: GramineSGXVMSecure publish in vm1 (ACL/key table via cxl_sec_mgr)"
# Ensure the security manager doesn't latch onto an older valid header (resource2 may reject write(2); use mmap).
ssh_vm1 "sudo -n python3 -c 'import mmap, os; fd=os.open(\"${RING_PATH}\", os.O_RDWR); m=mmap.mmap(fd, 4096, access=mmap.ACCESS_WRITE); m[:] = b\"\\0\"*4096; m.flush(); m.close(); os.close(fd)'"

sec_mgr_remote="/tmp/gapbs_cxl_sec_mgr_${ts}.log"
sec_mgr_pid="$(ssh_vm1 "sudo -n bash -lc 'nohup /tmp/cxl_sec_mgr --ring ${RING_PATH} --listen ${vm1_ip}:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >${sec_mgr_remote} 2>&1 & echo \$!'")"

ssh_vm1_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 CXL_SEC_ENABLE=1 CXL_SEC_MGR='${vm1_ip}:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=1 gramine-sgx ./'gapbs-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${sgx_secure_pub_log}"

echo "[*] Benchmark 5/5: GramineSGXVMSecure attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_MGR='${vm1_ip}:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=1 gramine-sgx ./'gapbs-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${sgx_secure_vm1_log}" 2>&1
) &
pid_sgx_secure_vm1=$!

(
  ssh_vm2_tty "cd /mnt/hostshare/gramine && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_MGR='${vm1_ip}:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=2 gramine-sgx ./'gapbs-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${sgx_secure_vm2_log}" 2>&1
) &
pid_sgx_secure_vm2=$!

wait "${pid_sgx_secure_vm1}"
wait "${pid_sgx_secure_vm2}"

ssh_vm1 "sudo -n cat '${sec_mgr_remote}'" | tee "${sec_mgr_log}" || true

avg_from_log() {
  local log="$1"
  awk '/^Average Time:/{print $3; exit}' "${log}" | tr -d '\r' || true
}

edges_for_teps_from_log() {
  local log="$1"
  awk '
    /^Graph has/ {
      e=$6; kind=$7;
      if (e ~ /^[0-9]+$/) {
        if (kind == "undirected") e = e * 2;
        print e;
        exit;
      }
    }
    /^\[gapbs\] CXL graph published:/ {
      for (i = 1; i <= NF; i++) {
        if (index($i, "out_entries=") == 1) {
          v = $i;
          sub("out_entries=", "", v);
          if (v ~ /^[0-9]+$/) {
            print v;
            exit;
          }
        }
      }
    }
  ' "${log}" | tr -d '\r' || true
}

teps_from_edges_time() {
  local edges="$1"
  local t="$2"
  awk -v e="${edges}" -v tt="${t}" 'BEGIN{
    if (e == "" || tt == "" || tt == 0) { print ""; exit }
    printf "%.0f", (e / tt)
  }'
}

native_vm1_avg="$(avg_from_log "${native_vm1_log}")"
native_vm2_avg="$(avg_from_log "${native_vm2_log}")"
plain_ring_vm1_avg="$(avg_from_log "${plain_ring_vm1_log}")"
plain_ring_vm2_avg="$(avg_from_log "${plain_ring_vm2_log}")"
sgx_ring_vm1_avg="$(avg_from_log "${sgx_ring_vm1_log}")"
sgx_ring_vm2_avg="$(avg_from_log "${sgx_ring_vm2_log}")"
sgx_crypto_vm1_avg="$(avg_from_log "${sgx_crypto_vm1_log}")"
sgx_crypto_vm2_avg="$(avg_from_log "${sgx_crypto_vm2_log}")"
sgx_secure_vm1_avg="$(avg_from_log "${sgx_secure_vm1_log}")"
sgx_secure_vm2_avg="$(avg_from_log "${sgx_secure_vm2_log}")"

native_vm1_edges="$(edges_for_teps_from_log "${native_vm1_log}")"
native_vm2_edges="$(edges_for_teps_from_log "${native_vm2_log}")"
plain_ring_vm1_edges="$(edges_for_teps_from_log "${plain_ring_vm1_log}")"
plain_ring_vm2_edges="$(edges_for_teps_from_log "${plain_ring_vm2_log}")"
sgx_ring_vm1_edges="$(edges_for_teps_from_log "${sgx_ring_vm1_log}")"
sgx_ring_vm2_edges="$(edges_for_teps_from_log "${sgx_ring_vm2_log}")"
sgx_crypto_vm1_edges="$(edges_for_teps_from_log "${sgx_crypto_vm1_log}")"
sgx_crypto_vm2_edges="$(edges_for_teps_from_log "${sgx_crypto_vm2_log}")"
sgx_secure_vm1_edges="$(edges_for_teps_from_log "${sgx_secure_vm1_log}")"
sgx_secure_vm2_edges="$(edges_for_teps_from_log "${sgx_secure_vm2_log}")"

native_vm1_teps="$(teps_from_edges_time "${native_vm1_edges}" "${native_vm1_avg}")"
native_vm2_teps="$(teps_from_edges_time "${native_vm2_edges}" "${native_vm2_avg}")"
plain_ring_vm1_teps="$(teps_from_edges_time "${plain_ring_vm1_edges}" "${plain_ring_vm1_avg}")"
plain_ring_vm2_teps="$(teps_from_edges_time "${plain_ring_vm2_edges}" "${plain_ring_vm2_avg}")"
sgx_ring_vm1_teps="$(teps_from_edges_time "${sgx_ring_vm1_edges}" "${sgx_ring_vm1_avg}")"
sgx_ring_vm2_teps="$(teps_from_edges_time "${sgx_ring_vm2_edges}" "${sgx_ring_vm2_avg}")"
sgx_crypto_vm1_teps="$(teps_from_edges_time "${sgx_crypto_vm1_edges}" "${sgx_crypto_vm1_avg}")"
sgx_crypto_vm2_teps="$(teps_from_edges_time "${sgx_crypto_vm2_edges}" "${sgx_crypto_vm2_avg}")"
sgx_secure_vm1_teps="$(teps_from_edges_time "${sgx_secure_vm1_edges}" "${sgx_secure_vm1_avg}")"
sgx_secure_vm2_teps="$(teps_from_edges_time "${sgx_secure_vm2_edges}" "${sgx_secure_vm2_avg}")"

{
  echo "label,vm,kernel,scale,degree,trials,omp_threads,edge_traversals,avg_time_s,throughput_teps"
  echo "Native,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${native_vm1_edges},${native_vm1_avg},${native_vm1_teps}"
  echo "Native,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${native_vm2_edges},${native_vm2_avg},${native_vm2_teps}"
  echo "MultihostRing,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${plain_ring_vm1_edges},${plain_ring_vm1_avg},${plain_ring_vm1_teps}"
  echo "MultihostRing,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${plain_ring_vm2_edges},${plain_ring_vm2_avg},${plain_ring_vm2_teps}"
  echo "GramineSGXVMRing,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_ring_vm1_edges},${sgx_ring_vm1_avg},${sgx_ring_vm1_teps}"
  echo "GramineSGXVMRing,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_ring_vm2_edges},${sgx_ring_vm2_avg},${sgx_ring_vm2_teps}"
  echo "GramineSGXVMCrypto,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_crypto_vm1_edges},${sgx_crypto_vm1_avg},${sgx_crypto_vm1_teps}"
  echo "GramineSGXVMCrypto,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_crypto_vm2_edges},${sgx_crypto_vm2_avg},${sgx_crypto_vm2_teps}"
  echo "GramineSGXVMSecure,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_secure_vm1_edges},${sgx_secure_vm1_avg},${sgx_secure_vm1_teps}"
  echo "GramineSGXVMSecure,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_secure_vm2_edges},${sgx_secure_vm2_avg},${sgx_secure_vm2_teps}"
} > "${compare_csv}"

echo "[+] Done."
echo "[+] Throughput (TEPS; higher is better):"
echo "    Native(vm1/vm2)=${native_vm1_teps}/${native_vm2_teps}"
echo "    MultihostRing(vm1/vm2)=${plain_ring_vm1_teps}/${plain_ring_vm2_teps}"
echo "    GramineSGXVMRing(vm1/vm2)=${sgx_ring_vm1_teps}/${sgx_ring_vm2_teps}"
echo "    GramineSGXVMCrypto(vm1/vm2)=${sgx_crypto_vm1_teps}/${sgx_crypto_vm2_teps}"
echo "    GramineSGXVMSecure(vm1/vm2)=${sgx_secure_vm1_teps}/${sgx_secure_vm2_teps}"
echo "    ${compare_csv}"

