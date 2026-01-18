#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 as Intel TDX confidential guests (2 VMs + ivshmem),
# then run Redis + GAPBS benchmarks inside the guests.
#
# Redis:
# 1) TDXNativeTCP:      native Redis (TCP/RESP) baseline (VM2 -> VM1 via internal NIC cxl0).
# 2) TDXRing:           ring-enabled Redis (shared-memory ring, no RESP) (VM2 -> VM1 via ivshmem BAR2).
# 3) TDXRingSecure:     ring-enabled Redis + ACL + software crypto (cxl_sec_mgr + libsodium).
#
# GAPBS:
# 4) TDXGapbsNative:           native GAPBS binary (vm1 + vm2).
# 5) TDXGapbsMultihostRing:    GAPBS ring binary over shared memory (no Gramine) (vm1 + vm2).
# 6) TDXGapbsMultihostCrypto:  GAPBS ring-secure + libsodium crypto (per-VM key + common key; no mgr) (vm1 + vm2).
# 7) TDXGapbsMultihostSecure:  GAPBS ring-secure + cxl_sec_mgr ACL/key table (permission-managed crypto) (vm1 + vm2).
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
#   QEMU_BIN       : path to qemu-system-x86_64 (default: qemu-system-x86_64)
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
#
# GAPBS tunables:
#   GAPBS_KERNEL      : bfs|cc|pr|... (default: bfs)
#   SCALE             : -g scale for Kronecker graph (default: 22)
#   DEGREE            : -k degree for synthetic graph (default: 16)
#   TRIALS            : -n trials (default: 3)
#   OMP_THREADS       : OMP_NUM_THREADS (default: 4)
#   GAPBS_CXL_MAP_SIZE: mmap size in bytes for the GAPBS graph region (default: 2147483648 = 2GB)
#   SEC_MGR_TIMEOUT_MS: cxl_sec_mgr wait timeout for graph header (default: 600000)
#
# Shared-memory (CXL) latency simulation:
#   CXL_SHM_DELAY_NS: inject artificial latency on each shared-memory ring access (ns). If unset and host has <2 NUMA nodes, auto-defaults to CXL_SHM_DELAY_NS_DEFAULT.
#   CXL_SHM_DELAY_NS_DEFAULT: default delay to use on 1-NUMA hosts when CXL_SHM_DELAY_NS is unset (default: 150).
#
# Host dependency helpers:
#   INSTALL_HOST_DEPS: auto-install host packages via apt-get when missing (default: 1)
#   INSTALL_TDX_QEMU : auto|0|1. If 'auto', builds a TDX-enabled QEMU only when the current QEMU lacks 'tdx-guest' (default: auto).
#   TDX_QEMU_REPO    : git repo for TDX-enabled QEMU (default: https://github.com/intel/qemu-tdx.git)
#   TDX_QEMU_REF     : git ref to build (default: tdx)
#   TDX_QEMU_PREFIX  : install prefix for built QEMU (default: /opt/qemu-tdx)
#   TDX_QEMU_SRC_DIR : source checkout dir (default: /opt/qemu-tdx-src)
#   TDX_QEMU_BUILD_DIR: build dir (default: /opt/qemu-tdx-build)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
INSTALL_HOST_DEPS="${INSTALL_HOST_DEPS:-1}"
INSTALL_TDX_QEMU="${INSTALL_TDX_QEMU:-auto}"
TDX_QEMU_REPO="${TDX_QEMU_REPO:-https://github.com/intel/qemu-tdx.git}"
# NOTE: intel/qemu-tdx has a lightweight "tdx" branch that is NOT a QEMU source
# tree. Use a branch that contains the full QEMU sources (and thus has
# ./configure), e.g. "tdx-qemu-upstream".
TDX_QEMU_REF="${TDX_QEMU_REF:-tdx-qemu-upstream}"
TDX_QEMU_PREFIX="${TDX_QEMU_PREFIX:-/opt/qemu-tdx}"
TDX_QEMU_SRC_DIR="${TDX_QEMU_SRC_DIR:-/opt/qemu-tdx-src}"
TDX_QEMU_BUILD_DIR="${TDX_QEMU_BUILD_DIR:-/opt/qemu-tdx-build}"

REQ_N="${REQ_N:-200000}"
CLIENTS="${CLIENTS:-4}"
THREADS="${THREADS:-4}"
PIPELINE="${PIPELINE:-256}"
VMNET_VM1_IP="${VMNET_VM1_IP:-192.168.100.1}"

RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}" # 128MB
RING_COUNT="${RING_COUNT:-4}"
MAX_INFLIGHT="${MAX_INFLIGHT:-512}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19001}"
SEC_MGR_TIMEOUT_MS="${SEC_MGR_TIMEOUT_MS:-600000}"

GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
SCALE="${SCALE:-22}"
DEGREE="${DEGREE:-16}"
TRIALS="${TRIALS:-3}"
OMP_THREADS="${OMP_THREADS:-4}"
GAPBS_CXL_MAP_SIZE="${GAPBS_CXL_MAP_SIZE:-2147483648}"

BASE_IMG="${BASE_IMG:-}"
TDX_BIOS="${TDX_BIOS:-}"

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

need_cmd() {
  local cmd="$1"
  if command -v "${cmd}" >/dev/null 2>&1; then
    return 0
  fi
  echo "[!] Missing command: ${cmd}" >&2
  return 1
}

apt_retry_lock() {
  local desc="$1"
  shift
  local out=""
  local rc=0

  for _ in $(seq 1 180); do
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
      [[ -n "${out}" ]] && printf '%s\n' "${out}"
      return 0
    fi

    if printf '%s' "${out}" | grep -qiE 'could not get lock|unable to acquire the dpkg frontend lock|could not open lock file|unable to lock directory'; then
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

install_host_apt_deps() {
  if [[ "${INSTALL_HOST_DEPS}" != "1" ]]; then
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[*] INSTALL_HOST_DEPS=1 but apt-get is unavailable; skipping host auto-install." >&2
    return 0
  fi

  echo "[*] Installing host dependencies (apt-get) ..."
  apt_retry_lock "apt-get update" apt-get update
  apt_retry_lock "apt-get install host deps" apt-get install -y \
    ca-certificates \
    cloud-image-utils \
    curl \
    openssh-client \
    openssl \
    ovmf \
    qemu-system-x86 \
    qemu-utils
}

install_tdx_qemu() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] INSTALL_TDX_QEMU requested but apt-get is unavailable; install a TDX-enabled QEMU manually." >&2
    return 1
  fi
  if [[ -e "${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64" ]]; then
    if "${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64" -object help 2>/dev/null | grep -q 'tdx-guest'; then
      QEMU_BIN="${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64"
      return 0
    fi
  fi

  echo "[*] Building a TDX-enabled QEMU (this may take a while) ..."
  apt_retry_lock "apt-get update" apt-get update
  apt_retry_lock "apt-get install QEMU build deps" apt-get install -y \
    build-essential \
    bison \
    flex \
    git \
    ninja-build \
    meson \
    pkg-config \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-venv \
    libglib2.0-dev \
    libpixman-1-dev \
    libslirp-dev \
    zlib1g-dev \
    libfdt-dev \
    libcap-ng-dev \
    libattr1-dev

  mkdir -p "${TDX_QEMU_SRC_DIR}" "${TDX_QEMU_BUILD_DIR}" "${TDX_QEMU_PREFIX}"

  if [[ ! -d "${TDX_QEMU_SRC_DIR}/.git" ]]; then
    rm -rf "${TDX_QEMU_SRC_DIR}"
    git clone --depth 1 --branch "${TDX_QEMU_REF}" "${TDX_QEMU_REPO}" "${TDX_QEMU_SRC_DIR}"
  else
    git -C "${TDX_QEMU_SRC_DIR}" fetch --all --prune
    git -C "${TDX_QEMU_SRC_DIR}" checkout "${TDX_QEMU_REF}"
    git -C "${TDX_QEMU_SRC_DIR}" pull --ff-only || true
  fi

  if [[ ! -f "${TDX_QEMU_SRC_DIR}/configure" ]]; then
    echo "[!] ${TDX_QEMU_REPO}@${TDX_QEMU_REF} does not look like a QEMU source tree (missing 'configure')." >&2
    echo "    Hint: use a full QEMU branch such as: TDX_QEMU_REF=tdx-qemu-upstream" >&2
    if [[ "${TDX_QEMU_REF}" == "tdx" ]]; then
      echo "[*] Retrying with TDX_QEMU_REF=tdx-qemu-upstream ..." >&2
      rm -rf "${TDX_QEMU_SRC_DIR}"
      TDX_QEMU_REF="tdx-qemu-upstream"
      git clone --depth 1 --branch "${TDX_QEMU_REF}" "${TDX_QEMU_REPO}" "${TDX_QEMU_SRC_DIR}"
      if [[ ! -f "${TDX_QEMU_SRC_DIR}/configure" ]]; then
        echo "[!] Still missing 'configure' after retry; install a TDX-enabled QEMU manually and set QEMU_BIN=..." >&2
        return 1
      fi
    else
      return 1
    fi
  fi

  rm -rf "${TDX_QEMU_BUILD_DIR:?}/"*
  (
    cd "${TDX_QEMU_BUILD_DIR}"
    "${TDX_QEMU_SRC_DIR}/configure" \
      --prefix="${TDX_QEMU_PREFIX}" \
      --target-list=x86_64-softmmu \
      --enable-kvm \
      --disable-werror \
      --disable-docs
    make -j"$(nproc)"
    make install
  )

  if [[ ! -x "${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64" ]]; then
    echo "[!] QEMU build finished but binary is missing: ${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64" >&2
    return 1
  fi
  if ! "${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64" -object help 2>/dev/null | grep -q 'tdx-guest'; then
    echo "[!] Built QEMU still does not expose 'tdx-guest'." >&2
    echo "    Binary: ${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64" >&2
    return 1
  fi

  QEMU_BIN="${TDX_QEMU_PREFIX}/bin/qemu-system-x86_64"
  echo "[+] TDX-enabled QEMU ready: ${QEMU_BIN}"
}

install_host_apt_deps

need_cmd ssh
need_cmd ssh-keygen
need_cmd bash
need_cmd openssl

if [[ "${QEMU_BIN}" == */* ]]; then
  if [[ ! -x "${QEMU_BIN}" ]]; then
    echo "[!] QEMU_BIN not found/executable: ${QEMU_BIN}" >&2
    exit 1
  fi
elif ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
  echo "[!] Missing command: ${QEMU_BIN}" >&2
  echo "    Install on Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y qemu-system-x86" >&2
  exit 1
fi
if ! "${QEMU_BIN}" -object help 2>/dev/null | grep -q 'tdx-guest'; then
  qemu_ver="$("${QEMU_BIN}" -version 2>/dev/null | head -n 1 || true)"
  echo "[!] QEMU does not support TDX guests (missing 'tdx-guest' object)." >&2
  echo "    QEMU_BIN: ${QEMU_BIN}" >&2
  [[ -n "${qemu_ver}" ]] && echo "    Detected: ${qemu_ver}" >&2
  echo "    Check: ${QEMU_BIN} -object help | grep tdx-guest" >&2

  if [[ "${INSTALL_TDX_QEMU}" == "1" || ( "${INSTALL_TDX_QEMU}" == "auto" && "${QEMU_BIN}" == "qemu-system-x86_64" ) ]]; then
    install_tdx_qemu
  else
    echo "    Fix options:" >&2
    echo "      - Install/use a TDX-enabled QEMU build and rerun with QEMU_BIN=/path/to/qemu-system-x86_64" >&2
    echo "      - Or let this script build one: INSTALL_TDX_QEMU=1" >&2
    exit 1
  fi
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
QEMU_BIN="${QEMU_BIN}" \
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

echo "[*] Building GAPBS (native + ring + ring-secure) in vm1 ..."
ssh_vm1 "cd /mnt/hostshare/gapbs && sudo make clean && sudo make -j2 all ring ring-secure"

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

gapbs_native_vm1_log="${RESULTS_DIR}/tdx_gapbs_native_vm1_${GAPBS_KERNEL}_${ts}.log"
gapbs_native_vm2_log="${RESULTS_DIR}/tdx_gapbs_native_vm2_${GAPBS_KERNEL}_${ts}.log"

gapbs_ring_pub_log="${RESULTS_DIR}/tdx_gapbs_ring_publish_${GAPBS_KERNEL}_${ts}.log"
gapbs_ring_vm1_log="${RESULTS_DIR}/tdx_gapbs_ring_vm1_${GAPBS_KERNEL}_${ts}.log"
gapbs_ring_vm2_log="${RESULTS_DIR}/tdx_gapbs_ring_vm2_${GAPBS_KERNEL}_${ts}.log"

gapbs_crypto_pub_log="${RESULTS_DIR}/tdx_gapbs_crypto_publish_${GAPBS_KERNEL}_${ts}.log"
gapbs_crypto_vm1_log="${RESULTS_DIR}/tdx_gapbs_crypto_vm1_${GAPBS_KERNEL}_${ts}.log"
gapbs_crypto_vm2_log="${RESULTS_DIR}/tdx_gapbs_crypto_vm2_${GAPBS_KERNEL}_${ts}.log"

gapbs_secure_mgr_log="${RESULTS_DIR}/tdx_gapbs_secure_mgr_${GAPBS_KERNEL}_${ts}.log"
gapbs_secure_pub_log="${RESULTS_DIR}/tdx_gapbs_secure_publish_${GAPBS_KERNEL}_${ts}.log"
gapbs_secure_vm1_log="${RESULTS_DIR}/tdx_gapbs_secure_vm1_${GAPBS_KERNEL}_${ts}.log"
gapbs_secure_vm2_log="${RESULTS_DIR}/tdx_gapbs_secure_vm2_${GAPBS_KERNEL}_${ts}.log"

gapbs_compare_csv="${RESULTS_DIR}/tdx_gapbs_compare_${GAPBS_KERNEL}_${ts}.csv"

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
ssh_vm1 "tmux new-session -d -s redis_ring_tdx \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_COUNT=${RING_COUNT} ./redis-server --port 7379 --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx.log 2>&1\""

for _ in $(seq 1 200); do
  if ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
    break
  fi
  sleep 0.25
done
if ! ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
  echo "[!] ring transport not ready. Dumping diagnostics..." >&2
  ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx.log" >&2 || true
  exit 1
fi

ring_label="tdx_ring_${ts}"
ring_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_n_per_thread} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_label}.csv --label ${ring_label}" | tee "${ring_log}"
ssh_vm2 "cat /tmp/${ring_label}.csv" > "${ring_csv}"

ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

echo "[*] Benchmark 3/3: secure ring Redis inside TDX guests (ACL + software crypto)"
ssh_vm1 "tmux kill-session -t cxl_sec_mgr_tdx >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_tdx_secure >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

ssh_vm1 "tmux new-session -d -s cxl_sec_mgr_tdx \"sudo /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} >/tmp/cxl_sec_mgr_tdx_${ts}.log 2>&1\""
ssh_vm1 "tmux new-session -d -s redis_ring_tdx_secure \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_COUNT=${RING_COUNT} CXL_SEC_ENABLE=1 CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 ./redis-server --port 7379 --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx_secure.log 2>&1\""

for _ in $(seq 1 200); do
  if ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 2 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
    break
  fi
  sleep 0.25
done
if ! ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} timeout 2 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
  echo "[!] secure ring transport not ready. Dumping diagnostics..." >&2
  ssh_vm1 "tail -n 200 /tmp/cxl_sec_mgr_tdx_${ts}.log" >&2 || true
  ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx_secure.log" >&2 || true
  exit 1
fi

ring_secure_label="tdx_ring_secure_${ts}"
ring_secure_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_secure_n_per_thread} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_secure_label}.csv --label ${ring_secure_label}" | tee "${ring_secure_log}"
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

echo "[*] Benchmark 4/7: GAPBS native in vm1"
ssh_vm1 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' ./'${GAPBS_KERNEL}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
  | tee "${gapbs_native_vm1_log}"

echo "[*] Benchmark 4/7: GAPBS native in vm2"
ssh_vm2 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' ./'${GAPBS_KERNEL}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
  | tee "${gapbs_native_vm2_log}"

echo "[*] Benchmark 5/7: GAPBS multihost ring publish in vm1"
ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 ./'${GAPBS_KERNEL}-ring' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${gapbs_ring_pub_log}"

echo "[*] Benchmark 5/7: GAPBS multihost ring attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=attach ./'${GAPBS_KERNEL}-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${gapbs_ring_vm1_log}" 2>&1
) &
pid_gapbs_ring_vm1=$!

(
  ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM2}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=attach ./'${GAPBS_KERNEL}-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${gapbs_ring_vm2_log}" 2>&1
) &
pid_gapbs_ring_vm2=$!

wait "${pid_gapbs_ring_vm1}"
wait "${pid_gapbs_ring_vm2}"

crypto_key_vm1_hex="$(openssl rand -hex 32)"
crypto_key_vm2_hex="$(openssl rand -hex 32)"
crypto_key_common_hex="$(openssl rand -hex 32)"

echo "[*] Benchmark 6/7: GAPBS multihost crypto publish in vm1 (libsodium; per-VM key + common key; no mgr)"
ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX='${crypto_key_vm1_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' ./'${GAPBS_KERNEL}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${gapbs_crypto_pub_log}"

echo "[*] Benchmark 6/7: GAPBS multihost crypto attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX='${crypto_key_vm1_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' ./'${GAPBS_KERNEL}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${gapbs_crypto_vm1_log}" 2>&1
) &
pid_gapbs_crypto_vm1=$!

(
  ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM2}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX='${crypto_key_vm2_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' ./'${GAPBS_KERNEL}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${gapbs_crypto_vm2_log}" 2>&1
) &
pid_gapbs_crypto_vm2=$!

wait "${pid_gapbs_crypto_vm1}"
wait "${pid_gapbs_crypto_vm2}"

echo "[*] Benchmark 7/7: GAPBS multihost secure publish in vm1 (ACL/key table via cxl_sec_mgr)"
# Ensure the security manager doesn't latch onto an older valid header (resource2 may reject write(2); use mmap).
ssh_vm1 "sudo -n python3 -c 'import mmap, os; fd=os.open(\"${RING_PATH_VM1}\", os.O_RDWR); m=mmap.mmap(fd, 4096, access=mmap.ACCESS_WRITE); m[:] = b\"\\0\"*4096; m.flush(); m.close(); os.close(fd)'"

gapbs_sec_mgr_remote="/tmp/cxl_sec_mgr_gapbs_tdx_${ts}.log"
gapbs_sec_mgr_pid="$(ssh_vm1 "sudo -n bash -lc 'nohup /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${GAPBS_CXL_MAP_SIZE} --timeout-ms ${SEC_MGR_TIMEOUT_MS} >${gapbs_sec_mgr_remote} 2>&1 & echo \$!'" | tr -d '\r')"
if [[ -z "${gapbs_sec_mgr_pid}" || ! "${gapbs_sec_mgr_pid}" =~ ^[0-9]+$ ]]; then
  echo "[!] Failed to start cxl_sec_mgr (GAPBS) in vm1 (pid='${gapbs_sec_mgr_pid}')." >&2
  ssh_vm1 "sudo -n tail -n 200 '${gapbs_sec_mgr_remote}'" >&2 || true
  exit 1
fi

echo "[*] Waiting for cxl_sec_mgr (GAPBS) on vm1 to accept connections (port ${SEC_MGR_PORT}) ..."
ssh_vm1 "sudo -n bash -lc '
set -e
for _ in {1..300}; do
  if ! kill -0 \"${gapbs_sec_mgr_pid}\" 2>/dev/null; then
    echo \"[!] cxl_sec_mgr exited (pid=${gapbs_sec_mgr_pid})\" >&2
    tail -n 200 \"${gapbs_sec_mgr_remote}\" >&2 || true
    exit 1
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn sport = :${SEC_MGR_PORT} 2>/dev/null | grep -q . && exit 0
  elif (echo > /dev/tcp/127.0.0.1/${SEC_MGR_PORT}) >/dev/null 2>&1; then
    exit 0
  fi
  sleep 0.1
done
echo \"[!] timeout waiting for cxl_sec_mgr on :${SEC_MGR_PORT}\" >&2
tail -n 200 \"${gapbs_sec_mgr_remote}\" >&2 || true
exit 1
'"

ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS='${SEC_MGR_TIMEOUT_MS}' CXL_SEC_MGR='127.0.0.1:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=1 ./'${GAPBS_KERNEL}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n 1" \
  | tee "${gapbs_secure_pub_log}"

echo "[*] Benchmark 7/7: GAPBS multihost secure attach+run in vm1+vm2 (concurrent)"
(
  ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS='${SEC_MGR_TIMEOUT_MS}' CXL_SEC_MGR='127.0.0.1:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=1 ./'${GAPBS_KERNEL}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${gapbs_secure_vm1_log}" 2>&1
) &
pid_gapbs_secure_vm1=$!

(
  ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM2}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS='${SEC_MGR_TIMEOUT_MS}' CXL_SEC_MGR='${VMNET_VM1_IP}:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=2 ./'${GAPBS_KERNEL}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    >"${gapbs_secure_vm2_log}" 2>&1
) &
pid_gapbs_secure_vm2=$!

wait "${pid_gapbs_secure_vm1}"
wait "${pid_gapbs_secure_vm2}"

ssh_vm1 "sudo -n cat '${gapbs_sec_mgr_remote}'" | tee "${gapbs_secure_mgr_log}" || true
ssh_vm1 "sudo -n kill ${gapbs_sec_mgr_pid} >/dev/null 2>&1 || true"

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

pick_nonempty() {
  local a="$1"
  local b="$2"
  if [[ -n "${a}" ]]; then
    echo "${a}"
  else
    echo "${b}"
  fi
}

avg2_float() {
  local a="$1"
  local b="$2"
  awk -v aa="${a}" -v bb="${b}" 'BEGIN{
    if (aa == "" || bb == "") { print ""; exit }
    printf "%.5f", ((aa + bb) / 2.0)
  }'
}

avg2_int() {
  local a="$1"
  local b="$2"
  awk -v aa="${a}" -v bb="${b}" 'BEGIN{
    if (aa == "" || bb == "") { print ""; exit }
    printf "%.0f", ((aa + bb) / 2.0)
  }'
}

gapbs_native_vm1_avg="$(avg_from_log "${gapbs_native_vm1_log}")"
gapbs_native_vm2_avg="$(avg_from_log "${gapbs_native_vm2_log}")"
gapbs_ring_vm1_avg="$(avg_from_log "${gapbs_ring_vm1_log}")"
gapbs_ring_vm2_avg="$(avg_from_log "${gapbs_ring_vm2_log}")"
gapbs_crypto_vm1_avg="$(avg_from_log "${gapbs_crypto_vm1_log}")"
gapbs_crypto_vm2_avg="$(avg_from_log "${gapbs_crypto_vm2_log}")"
gapbs_secure_vm1_avg="$(avg_from_log "${gapbs_secure_vm1_log}")"
gapbs_secure_vm2_avg="$(avg_from_log "${gapbs_secure_vm2_log}")"

gapbs_native_vm1_edges="$(edges_for_teps_from_log "${gapbs_native_vm1_log}")"
gapbs_native_vm2_edges="$(edges_for_teps_from_log "${gapbs_native_vm2_log}")"
gapbs_ring_vm1_edges="$(edges_for_teps_from_log "${gapbs_ring_vm1_log}")"
gapbs_ring_vm2_edges="$(edges_for_teps_from_log "${gapbs_ring_vm2_log}")"
gapbs_crypto_vm1_edges="$(edges_for_teps_from_log "${gapbs_crypto_vm1_log}")"
gapbs_crypto_vm2_edges="$(edges_for_teps_from_log "${gapbs_crypto_vm2_log}")"
gapbs_secure_vm1_edges="$(edges_for_teps_from_log "${gapbs_secure_vm1_log}")"
gapbs_secure_vm2_edges="$(edges_for_teps_from_log "${gapbs_secure_vm2_log}")"

gapbs_native_vm1_teps="$(teps_from_edges_time "${gapbs_native_vm1_edges}" "${gapbs_native_vm1_avg}")"
gapbs_native_vm2_teps="$(teps_from_edges_time "${gapbs_native_vm2_edges}" "${gapbs_native_vm2_avg}")"
gapbs_ring_vm1_teps="$(teps_from_edges_time "${gapbs_ring_vm1_edges}" "${gapbs_ring_vm1_avg}")"
gapbs_ring_vm2_teps="$(teps_from_edges_time "${gapbs_ring_vm2_edges}" "${gapbs_ring_vm2_avg}")"
gapbs_crypto_vm1_teps="$(teps_from_edges_time "${gapbs_crypto_vm1_edges}" "${gapbs_crypto_vm1_avg}")"
gapbs_crypto_vm2_teps="$(teps_from_edges_time "${gapbs_crypto_vm2_edges}" "${gapbs_crypto_vm2_avg}")"
gapbs_secure_vm1_teps="$(teps_from_edges_time "${gapbs_secure_vm1_edges}" "${gapbs_secure_vm1_avg}")"
gapbs_secure_vm2_teps="$(teps_from_edges_time "${gapbs_secure_vm2_edges}" "${gapbs_secure_vm2_avg}")"

gapbs_native_avg_edges="$(pick_nonempty "${gapbs_native_vm1_edges}" "${gapbs_native_vm2_edges}")"
gapbs_ring_avg_edges="$(pick_nonempty "${gapbs_ring_vm1_edges}" "${gapbs_ring_vm2_edges}")"
gapbs_crypto_avg_edges="$(pick_nonempty "${gapbs_crypto_vm1_edges}" "${gapbs_crypto_vm2_edges}")"
gapbs_secure_avg_edges="$(pick_nonempty "${gapbs_secure_vm1_edges}" "${gapbs_secure_vm2_edges}")"

gapbs_native_avg_time="$(avg2_float "${gapbs_native_vm1_avg}" "${gapbs_native_vm2_avg}")"
gapbs_ring_avg_time="$(avg2_float "${gapbs_ring_vm1_avg}" "${gapbs_ring_vm2_avg}")"
gapbs_crypto_avg_time="$(avg2_float "${gapbs_crypto_vm1_avg}" "${gapbs_crypto_vm2_avg}")"
gapbs_secure_avg_time="$(avg2_float "${gapbs_secure_vm1_avg}" "${gapbs_secure_vm2_avg}")"

gapbs_native_avg_teps="$(avg2_int "${gapbs_native_vm1_teps}" "${gapbs_native_vm2_teps}")"
gapbs_ring_avg_teps="$(avg2_int "${gapbs_ring_vm1_teps}" "${gapbs_ring_vm2_teps}")"
gapbs_crypto_avg_teps="$(avg2_int "${gapbs_crypto_vm1_teps}" "${gapbs_crypto_vm2_teps}")"
gapbs_secure_avg_teps="$(avg2_int "${gapbs_secure_vm1_teps}" "${gapbs_secure_vm2_teps}")"

{
  echo "label,vm,kernel,scale,degree,trials,omp_threads,edge_traversals,avg_time_s,throughput_teps"
  echo "TDXGapbsNative,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_native_vm1_edges},${gapbs_native_vm1_avg},${gapbs_native_vm1_teps}"
  echo "TDXGapbsNative,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_native_vm2_edges},${gapbs_native_vm2_avg},${gapbs_native_vm2_teps}"
  echo "TDXGapbsNative,avg,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_native_avg_edges},${gapbs_native_avg_time},${gapbs_native_avg_teps}"
  echo "TDXGapbsMultihostRing,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_vm1_edges},${gapbs_ring_vm1_avg},${gapbs_ring_vm1_teps}"
  echo "TDXGapbsMultihostRing,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_vm2_edges},${gapbs_ring_vm2_avg},${gapbs_ring_vm2_teps}"
  echo "TDXGapbsMultihostRing,avg,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_avg_edges},${gapbs_ring_avg_time},${gapbs_ring_avg_teps}"
  echo "TDXGapbsMultihostCrypto,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_vm1_edges},${gapbs_crypto_vm1_avg},${gapbs_crypto_vm1_teps}"
  echo "TDXGapbsMultihostCrypto,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_vm2_edges},${gapbs_crypto_vm2_avg},${gapbs_crypto_vm2_teps}"
  echo "TDXGapbsMultihostCrypto,avg,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_avg_edges},${gapbs_crypto_avg_time},${gapbs_crypto_avg_teps}"
  echo "TDXGapbsMultihostSecure,vm1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_vm1_edges},${gapbs_secure_vm1_avg},${gapbs_secure_vm1_teps}"
  echo "TDXGapbsMultihostSecure,vm2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_vm2_edges},${gapbs_secure_vm2_avg},${gapbs_secure_vm2_teps}"
  echo "TDXGapbsMultihostSecure,avg,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_avg_edges},${gapbs_secure_avg_time},${gapbs_secure_avg_teps}"
} > "${gapbs_compare_csv}"

echo "[+] Done."
echo "    ${native_log}"
echo "    ${ring_log}"
echo "    ${ring_csv}"
echo "    ${ring_secure_log}"
echo "    ${ring_secure_csv}"
echo "    ${compare_csv}"
echo "    ${gapbs_native_vm1_log}"
echo "    ${gapbs_native_vm2_log}"
echo "    ${gapbs_ring_pub_log}"
echo "    ${gapbs_ring_vm1_log}"
echo "    ${gapbs_ring_vm2_log}"
echo "    ${gapbs_crypto_pub_log}"
echo "    ${gapbs_crypto_vm1_log}"
echo "    ${gapbs_crypto_vm2_log}"
echo "    ${gapbs_secure_mgr_log}"
echo "    ${gapbs_secure_pub_log}"
echo "    ${gapbs_secure_vm1_log}"
echo "    ${gapbs_secure_vm2_log}"
echo "    ${gapbs_compare_csv}"
