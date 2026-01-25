#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 as Intel TDX confidential guests (2 VMs + ivshmem),
# then run Redis + GAPBS benchmarks inside the guests.
#
# Redis:
# 1) TDXNativeTCP:      native Redis (TCP/RESP) baseline (VM2 -> VM1 via internal NIC cxl0).
# 2) TDXSodiumTCP:      native Redis over libsodium-encrypted TCP (user-space tunnel) (VM2 -> VM1 via cxl0).
# 3) TDXRing:           ring-enabled Redis (shared-memory ring, no RESP) (VM2 -> VM1 via ivshmem BAR2).
# 4) TDXRingCrypto:     ring-enabled Redis + software crypto (per-VM key + common key; no mgr).
# 5) TDXRingSecure:     ring-enabled Redis + ACL + software crypto (cxl_sec_mgr + libsodium).
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
#   REDIS_BENCH_DATASIZE: redis-benchmark value size in bytes (-d) (default: 3)
#   VMNET_VM1_IP   : VM1 internal IP on cxl0 (default: 192.168.100.1)
#   VM1_MEM/VM2_MEM: guest memory (default: 4G)
#   VM1_CPUS/VM2_CPUS: guest vCPUs (default: 4)
#   RING_MAP_SIZE  : BAR2 mmap size (default: 4294967296 = 4GB)
#   CXL_SIZE       : ivshmem backing file size (default: RING_MAP_SIZE)
#   RING_PATH_OVERRIDE: use this path inside guests for ring mmap (skip BAR2/UIO detection)
#   RING_COUNT     : number of rings (default: 4)
#   RING_REGION_SIZE: bytes per TDX SHM ring region (default: 16M)
#   RING_REGION_BASE: base offset within BAR2 mmap (default: 4096; keeps page 0 unused for fair ring vs ring-secure)
#   MAX_INFLIGHT   : ring client inflight limit (default: 512)
#   RING_BENCH_KEY_SIZE  : ring benchmark fixed key size (bytes; 0=use k%d; optional K/M/G suffix) (default: 0)
#   RING_BENCH_VALUE_SIZE: ring benchmark fixed value size (bytes; 0=use v%d; optional K/M/G suffix) (default: 0)
#   CXL_RING_POLL_SPIN_NS : cxl_ring_direct spin before sleep (default: 5000)
#   CXL_RING_POLL_SLEEP_NS: cxl_ring_direct sleep after spin (default: 50000)
#   SEC_MGR_PORT   : TCP port for cxl_sec_mgr inside vm1 (default: 19001)
#   SODIUM_KEY_HEX : pre-shared key for libsodium tunnel (hex64, default: deterministic test key)
#   SODIUM_PORT    : vm1 tunnel listen port on cxl0 (default: 6380)
#   SODIUM_LOCAL_PORT: vm2 local tunnel listen port (default: 6380)
#   TDX_BIOS       : firmware file passed to QEMU `-bios` (default auto-detected)
#   RING_ONLY      : 1 to run a ring-only quick validation and exit (default: 0)
#   RING_ONLY_BENCH_N : total ops for ring-only bench (default: 10000)
#   RING_ONLY_THREADS : threads for ring-only bench (default: 2)
#   RING_ONLY_MAX_INFLIGHT : max inflight for ring-only bench (default: 256)
#   RING_ONLY_PIPELINE : 1 to enable pipelined ring-only bench (default: 1)
#   RING_ONLY_PING_TIMEOUT_MS : ping timeout for ring-only (default: 5000)
#   RING_REDIS_PORT : TCP port for ring-enabled redis-server (default: 0 to disable TCP)
#   RING_SECURE_REGION_BASE: base offset for secure ring regions (default: 4096; keeps first page for CXLSEC table)
#   CXL_CRYPTO_PRIV_REGION_SIZE: per-node private region size for ring-crypto (default: 1G)
#   SSH_ALLOW_FALLBACK   : 1 to try multiple users during SSH probe (default: 1)
#   SSH_PROBE_INITIAL_DELAY : initial wait between SSH probe attempts (seconds, default: 2)
#   SSH_PROBE_MAX_DELAY  : max wait between SSH probe attempts (seconds, default: 10)
#   SSH_PROBE_BACKOFF_FACTOR : backoff multiplier between attempts (default: 2)
#
# GAPBS tunables:
#   GAPBS_KERNEL      : bfs|cc|pr|... (default: bfs)
#   GAPBS_KERNEL_LIST : comma-separated kernels to run (overrides GAPBS_KERNEL), e.g. "bfs,sssp,pr,cc,bc,tc"
#   SCALE             : -g scale for Kronecker graph (default: 22)
#   DEGREE            : -k degree for synthetic graph (default: 16)
#   TRIALS            : -n trials (default: 5)
#   OMP_THREADS       : OMP_NUM_THREADS (default: 4)
#   OMP_PROC_BIND     : OpenMP thread pinning (default: true)
#   OMP_PLACES        : OpenMP place list (default: cores)
#   GAPBS_DROP_FIRST_TRIAL : drop the first Trial Time when computing avg_time_s (default: 1)
#   GAPBS_CXL_PRETOUCH_RING : enable GAPBS_CXL_PRETOUCH for ring attach runs (default: 1)
#   GAPBS_CXL_MAP_SIZE: mmap size in bytes for the GAPBS graph region (default: 4294967296 = 4GB)
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
#   TDX_QEMU_REF     : git ref to build (default: tdx-qemu-upstream)
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
REDIS_BENCH_DATASIZE="${REDIS_BENCH_DATASIZE:-3}"
VMNET_VM1_IP="${VMNET_VM1_IP:-192.168.100.1}"
VM1_MEM="${VM1_MEM:-16G}"
VM2_MEM="${VM2_MEM:-16G}"
VM1_CPUS="${VM1_CPUS:-18}"
VM2_CPUS="${VM2_CPUS:-18}"
SKIP_SEED="${SKIP_SEED:-0}"
SSH_ALLOW_FALLBACK="${SSH_ALLOW_FALLBACK:-}"
SSH_PROBE_INITIAL_DELAY="${SSH_PROBE_INITIAL_DELAY:-2}"
SSH_PROBE_MAX_DELAY="${SSH_PROBE_MAX_DELAY:-10}"
SSH_PROBE_BACKOFF_FACTOR="${SSH_PROBE_BACKOFF_FACTOR:-2}"

RING_MAP_SIZE="${RING_MAP_SIZE:-4294967296}" # 4GB
RING_COUNT="${RING_COUNT:-4}"
RING_REGION_SIZE="${RING_REGION_SIZE:-16M}"
RING_REGION_BASE="${RING_REGION_BASE:-4096}"
MAX_INFLIGHT="${MAX_INFLIGHT:-512}"
RING_BENCH_KEY_SIZE="${RING_BENCH_KEY_SIZE:-8}"
RING_BENCH_VALUE_SIZE="${RING_BENCH_VALUE_SIZE:-1024}"
CXL_RING_POLL_SPIN_NS="${CXL_RING_POLL_SPIN_NS:-100}"
CXL_RING_POLL_SLEEP_NS="${CXL_RING_POLL_SLEEP_NS:-100}"
RING_MAP_OFFSET_VM1="${RING_MAP_OFFSET_VM1:-0}"
RING_MAP_OFFSET_VM2="${RING_MAP_OFFSET_VM2:-0}"
CXL_SIZE="${CXL_SIZE:-${RING_MAP_SIZE}}"
RING_PATH_OVERRIDE="${RING_PATH_OVERRIDE:-}"
RING_ONLY="${RING_ONLY:-0}"
RING_ONLY_BENCH_N="${RING_ONLY_BENCH_N:-10000}"
RING_ONLY_THREADS="${RING_ONLY_THREADS:-2}"
RING_ONLY_MAX_INFLIGHT="${RING_ONLY_MAX_INFLIGHT:-256}"
RING_ONLY_PIPELINE="${RING_ONLY_PIPELINE:-1}"
RING_ONLY_PING_TIMEOUT_MS="${RING_ONLY_PING_TIMEOUT_MS:-5000}"
RING_REDIS_PORT="${RING_REDIS_PORT:-0}"
REDIS_MAKE_JOBS="${REDIS_MAKE_JOBS:-2}"
ULIMIT_NOFILE="${ULIMIT_NOFILE:-65535}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19001}"
SEC_MGR_TIMEOUT_MS="${SEC_MGR_TIMEOUT_MS:-600000}"
ENABLE_SECURE="${ENABLE_SECURE:-1}"
ENABLE_CRYPTO="${ENABLE_CRYPTO:-1}"
CXL_CRYPTO_PRIV_REGION_SIZE="${CXL_CRYPTO_PRIV_REGION_SIZE:-1G}"
SODIUM_KEY_HEX="${SODIUM_KEY_HEX:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
SODIUM_PORT="${SODIUM_PORT:-6380}"
SODIUM_LOCAL_PORT="${SODIUM_LOCAL_PORT:-6380}"
RING_SECURE_REGION_BASE="${RING_SECURE_REGION_BASE:-4096}"

# YCSB (optional; runs inside VM2 against TCP endpoints)
YCSB_ENABLE="${YCSB_ENABLE:-0}"
YCSB_RECORDS="${YCSB_RECORDS:-100000}"
YCSB_OPS="${YCSB_OPS:-100000}"
YCSB_THREADS="${YCSB_THREADS:-4}"
YCSB_TARGET="${YCSB_TARGET:-}"
YCSB_WORKLOADS="${YCSB_WORKLOADS:-workloada}"
YCSB_PASSWORD="${YCSB_PASSWORD:-}"
YCSB_CLUSTER="${YCSB_CLUSTER:-false}"

GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
GAPBS_KERNEL_LIST="${GAPBS_KERNEL_LIST:-}"
SCALE="${SCALE:-22}"
DEGREE="${DEGREE:-16}"
TRIALS="${TRIALS:-3}"
OMP_THREADS="${OMP_THREADS:-4}"
OMP_PROC_BIND="${OMP_PROC_BIND:-true}"
OMP_PLACES="${OMP_PLACES:-cores}"
GAPBS_DROP_FIRST_TRIAL="${GAPBS_DROP_FIRST_TRIAL:-1}"
GAPBS_CXL_PRETOUCH_RING="${GAPBS_CXL_PRETOUCH_RING:-1}"
GAPBS_CXL_MAP_SIZE="${GAPBS_CXL_MAP_SIZE:-4294967296}"
GAPBS_CXL_MAP_OFFSET_VM1="${GAPBS_CXL_MAP_OFFSET_VM1:-0}"
GAPBS_CXL_MAP_OFFSET_VM2="${GAPBS_CXL_MAP_OFFSET_VM2:-0}"

BASE_IMG="${BASE_IMG:-}"
TDX_BIOS="${TDX_BIOS:-}"

# If TDX_BIOS is not explicitly set, prefer the system-provided TDX firmware.
pick_default_tdx_bios() {
  local c
  # On Canonical TDX stacks, /usr/share/ovmf/OVMF.fd is TDX-capable and tends
  # to have fewer early-boot quirks than some OVMF.tdx.fd builds.
  for c in \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/OVMF/OVMF.fd \
    /usr/share/ovmf/OVMF.tdx.fd \
    /usr/share/OVMF/OVMF.tdx.fd; do
    [[ -f "${c}" ]] && { echo "${c}"; return; }
  done
  for c in \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/qemu/OVMF.fd \
    /usr/share/OVMF/OVMF.fd; do
    [[ -f "${c}" ]] && { echo "${c}"; return; }
  done
}
if [[ -z "${TDX_BIOS}" ]]; then
  TDX_BIOS="$(pick_default_tdx_bios || true)"
fi

CXL_SHM_DELAY_NS="${CXL_SHM_DELAY_NS:-70}"
CXL_SHM_DELAY_NS_DEFAULT="${CXL_SHM_DELAY_NS_DEFAULT:-70}"

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

size_to_bytes() {
  local v="$1"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --from=iec "${v}" 2>/dev/null && return 0
  fi
  if [[ "${v}" =~ ^([0-9]+)([KkMmGgTt])?$ ]]; then
    local n="${BASH_REMATCH[1]}"
    local s="${BASH_REMATCH[2]}"
    case "${s}" in
      K|k) echo $((n * 1024)) ;;
      M|m) echo $((n * 1024 * 1024)) ;;
      G|g) echo $((n * 1024 * 1024 * 1024)) ;;
      T|t) echo $((n * 1024 * 1024 * 1024 * 1024)) ;;
      "") echo "${n}" ;;
      *) return 1 ;;
    esac
    return 0
  fi
  return 1
}

# Normalize size-like inputs early so the rest of the script can safely use
# numeric comparisons and pass byte counts to ring clients.
if ! RING_MAP_SIZE_BYTES="$(size_to_bytes "${RING_MAP_SIZE}")"; then
  echo "[!] Invalid RING_MAP_SIZE='${RING_MAP_SIZE}' (expected bytes or IEC like 4G)." >&2
  exit 1
fi
RING_MAP_SIZE="${RING_MAP_SIZE_BYTES}"

if [[ -n "${CXL_SIZE}" ]]; then
  if ! CXL_SIZE_BYTES="$(size_to_bytes "${CXL_SIZE}")"; then
    echo "[!] Invalid CXL_SIZE='${CXL_SIZE}' (expected bytes or IEC like 4G)." >&2
    exit 1
  fi
  if [[ "${CXL_SIZE_BYTES}" -lt "${RING_MAP_SIZE}" ]]; then
    echo "[!] Invalid config: CXL_SIZE(${CXL_SIZE}) < RING_MAP_SIZE(${RING_MAP_SIZE})." >&2
    exit 1
  fi
else
  CXL_SIZE="${RING_MAP_SIZE}"
fi

need_cmd() {
  local cmd="$1"
  if command -v "${cmd}" >/dev/null 2>&1; then
    return 0
  fi
  echo "[!] Missing command: ${cmd}" >&2
  return 1
}

ensure_kvm_for_tdx() {
  local vendor=""
  vendor="$(awk -F: '/^vendor_id/{gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
  if [[ -n "${vendor}" && "${vendor}" != "GenuineIntel" ]]; then
    echo "[!] TDX is Intel-only. Detected CPU vendor_id='${vendor}'." >&2
    exit 1
  fi

  local has_vtx=0
  if grep -q -m1 -E '\b(vmx|svm)\b' /proc/cpuinfo 2>/dev/null; then
    has_vtx=1
  fi

  if [[ ! -c /dev/kvm ]]; then
    modprobe kvm >/dev/null 2>&1 || true
    modprobe kvm_intel >/dev/null 2>&1 || true
    modprobe kvm_amd >/dev/null 2>&1 || true
  fi

  local has_kvm=0
  local has_kvm_access=0
  if [[ -c /dev/kvm ]]; then
    has_kvm=1
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then
      has_kvm_access=1
    fi
  fi

  if [[ "${has_kvm_access}" != "1" ]]; then
    echo "[!] TDX guests require KVM acceleration (/dev/kvm) and CPU virtualization flags (vmx/svm)." >&2
    if [[ "${has_kvm}" == "1" ]]; then
      echo "    /dev/kvm exists but is not accessible (run with sudo or add your user to group 'kvm')." >&2
    else
      echo "    /dev/kvm is missing." >&2
    fi
    if [[ "${has_vtx}" != "1" ]]; then
      echo "    CPU virtualization flags (vmx/svm) are not visible; nested virtualization is likely disabled." >&2
    fi
    echo "    Fix:" >&2
    echo "      - Bare metal: enable VT-x/AMD-V in BIOS and ensure KVM modules are available." >&2
    echo "      - VM/cloud: enable nested virtualization in your hypervisor/provider, or run on bare metal." >&2
    exit 1
  fi

  # Best-effort: detect whether the host KVM stack even has TDX host support.
  # Without this, QEMU will fail with "vm-type tdx not supported by KVM".
  if [[ -r /sys/module/kvm_intel/parameters/tdx ]]; then
    local tdx_param
    tdx_param="$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || true)"
    if [[ -n "${tdx_param}" && "${tdx_param}" != "Y" && "${tdx_param}" != "y" && "${tdx_param}" != "1" ]]; then
      echo "[!] kvm_intel TDX support appears disabled (kvm_intel.tdx='${tdx_param}')." >&2
      echo "    Try: sudo modprobe -r kvm_intel && sudo modprobe kvm_intel tdx=1 (requires a TDX-capable host kernel + BIOS)." >&2
      exit 1
    fi
  else
    echo "[!] Host kernel/KVM does not expose kvm_intel.tdx; likely missing TDX host support." >&2
    echo "    This will fail with: qemu-system-x86_64: vm-type tdx not supported by KVM" >&2
    echo "    Fix: boot a TDX-enabled host kernel + enable TDX in BIOS/firmware (cloud: use a TDX host image/bare metal)." >&2
    exit 1
  fi
}

ensure_kvm_for_tdx

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
    libguestfs-tools \
    openssh-client \
    openssl \
    sshpass \
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
    # Shallow clones created with --depth default to single-branch and won't be
    # able to switch to another ref unless we widen the fetch refspec.
    git -C "${TDX_QEMU_SRC_DIR}" remote set-url origin "${TDX_QEMU_REPO}" >/dev/null 2>&1 || true
    git -C "${TDX_QEMU_SRC_DIR}" config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
    git -C "${TDX_QEMU_SRC_DIR}" fetch origin --prune

    set +e
    if git -C "${TDX_QEMU_SRC_DIR}" show-ref --verify --quiet "refs/remotes/origin/${TDX_QEMU_REF}"; then
      git -C "${TDX_QEMU_SRC_DIR}" checkout -B "${TDX_QEMU_REF}" "origin/${TDX_QEMU_REF}"
      rc=$?
    else
      git -C "${TDX_QEMU_SRC_DIR}" checkout -f "${TDX_QEMU_REF}"
      rc=$?
    fi
    set -e

    if [[ "${rc}" -ne 0 ]]; then
      echo "[!] Existing QEMU checkout cannot switch to ref '${TDX_QEMU_REF}'. Re-cloning..." >&2
      rm -rf "${TDX_QEMU_SRC_DIR}"
      git clone --depth 1 --branch "${TDX_QEMU_REF}" "${TDX_QEMU_REPO}" "${TDX_QEMU_SRC_DIR}"
    fi
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
if [[ "${INSTALL_TDX_QEMU}" == "1" ]]; then
  echo "[*] INSTALL_TDX_QEMU=1: forcing build of TDX-enabled QEMU ..."
  install_tdx_qemu
elif ! "${QEMU_BIN}" -object help 2>/dev/null | grep -q 'tdx-guest'; then
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

tdx_preflight_or_exit() {
  # Quick minimal TDX init probe to avoid long SSH waits.
  # Try to create a TDX guest (no disk). If kernel/QEMU/TDVF mismatch,
  # it should fail immediately:
  #  - "vm-type tdx not supported by KVM"
  #  - "KVM_TDX_INIT_VM failed: Invalid argument"
  #  - or an early e0000091 exit
  local bios="${TDX_BIOS}"
  if [[ -z "${bios}" || ! -f "${bios}" ]]; then
    echo "[!] TDX preflight: TDX_BIOS is not set or does not exist." >&2
    return 1
  fi
  echo "[*] TDX preflight: using QEMU='${QEMU_BIN}' BIOS='${bios}' ..."
  local log
  log="$(mktemp /tmp/tdx-preflight.XXXX.log)"
  set +e
  timeout 5s "${QEMU_BIN}" -enable-kvm -cpu host \
    -object tdx-guest,id=tdx \
    -bios "${bios}" \
    -machine q35,kernel-irqchip=split,confidential-guest-support=tdx,smm=off \
    -m 512 -display none -nodefaults -nographic -no-reboot \
    >"${log}" 2>&1
  local rc=$?
  set -e
  if grep -qiE 'vm-type tdx not supported by KVM|KVM_TDX_INIT_VM failed|unknown exit|Failed to get registers' "${log}"; then
    echo "[!] TDX preflight failed: host TDX stack is incompatible with QEMU/TDVF." >&2
    tail -n 50 "${log}" >&2 || true
    rm -f "${log}" || true
    exit 1
  fi
  rm -f "${log}" || true
}

if [[ "${INSTALL_TDX_QEMU}" == "1" ]]; then
  echo "[*] INSTALL_TDX_QEMU=1: forcing build of TDX-enabled QEMU ..."
  install_tdx_qemu
elif ! "${QEMU_BIN}" -object help 2>/dev/null | grep -q 'tdx-guest'; then
  qemu_ver="$("${QEMU_BIN}" -version 2>/dev/null | head -n 1 || true)"
  echo "[!] QEMU does not support TDX guests (missing 'tdx-guest' object)." >&2
  echo "    QEMU_BIN: ${QEMU_BIN}" >&2
  [[ -n "${qemu_ver}" ]] && echo "    Detected: ${qemu_ver}" >&2
  echo "    Check: ${QEMU_BIN} -object help | grep tdx-guest" >&2

  if [[ "${INSTALL_TDX_QEMU}" == "1" || ( "${INSTALL_TDX_QEMU}" == "auto" && "${QEMU_BIN}" == "qemu-system-x86_64" ) ]]; then
    install_tdx_qemu
  else
    echo "    Fix options:" >&2
    echo "      - Install/use a TDX-enabled QEMU and set QEMU_BIN=..." >&2
    echo "      - Or let this script build one: INSTALL_TDX_QEMU=1" >&2
    exit 1
  fi
fi

# Run a TDX preflight before creating/waiting for guests to fail fast.
tdx_preflight_or_exit

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-tdx.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

sshkey="${tmpdir}/vm_sshkey"
ssh-keygen -t ed25519 -N "" -f "${sshkey}" -q

# Default to key-based SSH for ubuntu; if a TDX image is detected or key auth
# fails, fall back to tdx/123456 password login.
SSH_USER="${SSH_USER:-}"
SSH_AUTH_MODE="key"   # key|pass
SSH_PASS="${SSH_PASS:-}"
VM1_SSH_USER="${VM1_SSH_USER:-}"
VM1_SSH_PASS="${VM1_SSH_PASS:-}"
VM1_SSH_AUTH_MODE="${VM1_SSH_AUTH_MODE:-}"
VM2_SSH_USER="${VM2_SSH_USER:-}"
VM2_SSH_PASS="${VM2_SSH_PASS:-}"
VM2_SSH_AUTH_MODE="${VM2_SSH_AUTH_MODE:-}"

ssh_key_opts=(
  -i "${sshkey}"
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o ConnectionAttempts=1
  -o ConnectTimeout=5
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_pass_opts=(
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectionAttempts=1
  -o ConnectTimeout=5
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_do() {
  local port="$1"; shift
  if [[ "${SSH_AUTH_MODE}" == "pass" ]]; then
    sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "$@"
  else
    ssh "${ssh_key_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "$@"
  fi
}

SSH_CMD_RETRIES="${SSH_CMD_RETRIES:-20}"
SSH_CMD_RETRY_DELAY_SECS="${SSH_CMD_RETRY_DELAY_SECS:-2}"

ssh_do_retry() {
  local port="$1"; shift
  local out=""
  local rc=0
  for i in $(seq 1 "${SSH_CMD_RETRIES}"); do
    set +e
    out="$(ssh_do "${port}" "$@" 2>&1)"
    rc=$?
    set -e
    if [[ "${rc}" -eq 0 ]]; then
      [[ -n "${out}" ]] && printf '%s\n' "${out}"
      return 0
    fi
    # SSH transport errors return 255; retry those (guest can be temporarily busy).
    if [[ "${rc}" -eq 255 ]]; then
      echo "[*] SSH transient failure on port ${port} (attempt ${i}/${SSH_CMD_RETRIES}), retrying..." >&2
      sleep "${SSH_CMD_RETRY_DELAY_SECS}"
      continue
    fi
    printf '%s\n' "${out}" >&2
    return "${rc}"
  done
  printf '%s\n' "${out}" >&2
  return "${rc}"
}

ssh_vm1() {
  local saved_user="${SSH_USER}"
  local saved_pass="${SSH_PASS}"
  local saved_mode="${SSH_AUTH_MODE}"
  if [[ -n "${VM1_SSH_USER}" ]]; then
    SSH_USER="${VM1_SSH_USER}"
    SSH_PASS="${VM1_SSH_PASS}"
    SSH_AUTH_MODE="${VM1_SSH_AUTH_MODE:-${SSH_AUTH_MODE}}"
  fi
  ssh_do_retry "${VM1_SSH}" "$@"
  local rc=$?
  SSH_USER="${saved_user}"
  SSH_PASS="${saved_pass}"
  SSH_AUTH_MODE="${saved_mode}"
  return "${rc}"
}

ssh_vm2() {
  local saved_user="${SSH_USER}"
  local saved_pass="${SSH_PASS}"
  local saved_mode="${SSH_AUTH_MODE}"
  if [[ -n "${VM2_SSH_USER}" ]]; then
    SSH_USER="${VM2_SSH_USER}"
    SSH_PASS="${VM2_SSH_PASS}"
    SSH_AUTH_MODE="${VM2_SSH_AUTH_MODE:-${SSH_AUTH_MODE}}"
  fi
  ssh_do_retry "${VM2_SSH}" "$@"
  local rc=$?
  SSH_USER="${saved_user}"
  SSH_PASS="${saved_pass}"
  SSH_AUTH_MODE="${saved_mode}"
  return "${rc}"
}

# TDX guests can be slow to boot (especially with first-boot cloud-init).
# Use a conservative default; override via environment variables as needed.
WAIT_SSH_SECS="${WAIT_SSH_SECS:-600}"
WAIT_CLOUD_INIT_SECS="${WAIT_CLOUD_INIT_SECS:-120}"

# Detect whether this is a TD image built by TDX tools (different login defaults).
is_tdx_image_path=0
if [[ -n "${BASE_IMG}" ]]; then
  case "${BASE_IMG}" in
    *tdx-guest-ubuntu-*.qcow2) is_tdx_image_path=1 ;;
  esac
fi

# For TDX images without cloud-init seed, default to root/123456 if no SSH user was provided.
if [[ "${is_tdx_image_path}" -eq 1 && -z "${SSH_USER}" && "${SKIP_SEED}" == "1" ]]; then
  SSH_USER="root"
  if [[ -z "${SSH_PASS}" ]]; then
    SSH_PASS="123456"
  fi
  SSH_AUTH_MODE="pass"
fi
if [[ -z "${SSH_USER}" && "${SKIP_SEED}" != "1" ]]; then
  SSH_USER="ubuntu"
fi
if [[ -z "${SSH_ALLOW_FALLBACK}" ]]; then
  # Even with our cloud-init seed, SSH key injection can be flaky in some
  # environments. Default to allowing fallback probes (ubuntu password, etc.)
  # to avoid hard failures during bring-up.
  SSH_ALLOW_FALLBACK="1"
fi

# Auto-pick SSH user/auth: try configured user first; fallback only if enabled.
pick_ssh_auth() {
  local port="$1"
  # If SSH_USER and/or SSH_PASS are explicitly set, try that first.
  if [[ -n "${SSH_USER}" ]]; then
    if [[ -n "${SSH_PASS}" ]]; then
      SSH_AUTH_MODE="pass"
      if sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "true" >/dev/null 2>&1; then
        return 0
      fi
    else
      SSH_AUTH_MODE="key"
      if ssh "${ssh_key_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "true" >/dev/null 2>&1; then
        return 0
      fi
    fi
    if [[ "${SSH_ALLOW_FALLBACK}" != "1" ]]; then
      return 1
    fi
  fi

  # Option A: ubuntu + key
  SSH_USER="ubuntu"; SSH_AUTH_MODE="key"; SSH_PASS=""
  if ssh "${ssh_key_opts[@]}" -p "${port}" ubuntu@127.0.0.1 "true" >/dev/null 2>&1; then
    return 0
  fi

  # Option A2: ubuntu + password (matches create_cloud_init.sh default)
  # Only attempt if sshpass is available; default password is 'ubuntu' unless overridden
  if command -v sshpass >/dev/null 2>&1; then
    SSH_USER="ubuntu"; SSH_PASS="${SSH_UBUNTU_PASS:-ubuntu}"; SSH_AUTH_MODE="pass"
    if sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" ubuntu@127.0.0.1 "true" >/dev/null 2>&1; then
      return 0
    fi
  fi

  # Option B: tdx/123456 password login (official TDX image)
  SSH_USER="tdx"; SSH_PASS="123456"; SSH_AUTH_MODE="pass"
  if command -v sshpass >/dev/null 2>&1; then
    if sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" tdx@127.0.0.1 "true" >/dev/null 2>&1; then
      return 0
    fi
  fi

  # Option C: root/123456 password login (common in TDX images)
  SSH_USER="root"; SSH_PASS="123456"; SSH_AUTH_MODE="pass"
  if command -v sshpass >/dev/null 2>&1; then
    if sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" root@127.0.0.1 "true" >/dev/null 2>&1; then
      return 0
    fi
  fi

  return 1
}

wait_ssh() {
  local name="$1"
  local port="$2"
  local delay="${SSH_PROBE_INITIAL_DELAY}"
  echo "[*] Waiting for ${name} SSH on 127.0.0.1:${port} (timeout=${WAIT_SSH_SECS}s) ..."
  local end=$(( $(date +%s) + WAIT_SSH_SECS ))
  while (( $(date +%s) < end )); do
    if pick_ssh_auth "${port}"; then
      echo "    ${name} SSH ready (user=${SSH_USER}, mode=${SSH_AUTH_MODE})."
      case "${name}" in
        vm1)
          VM1_SSH_USER="${SSH_USER}"
          VM1_SSH_PASS="${SSH_PASS}"
          VM1_SSH_AUTH_MODE="${SSH_AUTH_MODE}"
          ;;
        vm2)
          VM2_SSH_USER="${SSH_USER}"
          VM2_SSH_PASS="${SSH_PASS}"
          VM2_SSH_AUTH_MODE="${SSH_AUTH_MODE}"
          ;;
      esac
      return 0
    fi
    sleep "${delay}"
    if [[ "${delay}" -lt "${SSH_PROBE_MAX_DELAY}" ]]; then
      delay=$((delay * SSH_PROBE_BACKOFF_FACTOR))
      if [[ "${delay}" -gt "${SSH_PROBE_MAX_DELAY}" ]]; then
        delay="${SSH_PROBE_MAX_DELAY}"
      fi
    fi
  done
  echo "[!] Timeout waiting for ${name} SSH after ${WAIT_SSH_SECS}s." >&2
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
if [[ -n "${BASE_IMG}" && -f "${BASE_IMG}" ]]; then
  # Attach cloud-init seed even for TDX-built images to ensure ssh + netplan
  # are consistently configured for our dual-VM topology.
  SKIP_SEED=0
  STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${BASE_IMG}" \
  VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
  VM1_MEM="${VM1_MEM}" VM2_MEM="${VM2_MEM}" \
  VM1_CPUS="${VM1_CPUS}" VM2_CPUS="${VM2_CPUS}" \
  CXL_SIZE="${CXL_SIZE}" \
  VM_TDX_ENABLE=1 TDX_BIOS="${TDX_BIOS}" TDX_ATTACH_IVSHMEM=1 \
  SKIP_SEED="${SKIP_SEED}" FULL_CLONE="${is_tdx_image_path}" \
  CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
  QEMU_BIN="${QEMU_BIN}" \
  bash "${ROOT}/scripts/host_quickstart.sh"
else
  echo "[*] No BASE_IMG provided; building a TD guest image (qcow2) via tdx tools ..."
  UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
  OUTPUT="${ROOT}/infra/images/tdx-guest-ubuntu-${UBUNTU_VERSION}-generic.qcow2"
  UBUNTU_VERSION="${UBUNTU_VERSION}" OUTPUT="${OUTPUT}" \
  bash "${ROOT}/scripts/tdx_build_guest_image.sh"
  STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${OUTPUT}" \
  VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
  VM1_MEM="${VM1_MEM}" VM2_MEM="${VM2_MEM}" \
  VM1_CPUS="${VM1_CPUS}" VM2_CPUS="${VM2_CPUS}" \
  CXL_SIZE="${CXL_SIZE}" \
  VM_TDX_ENABLE=1 TDX_BIOS="${TDX_BIOS}" TDX_ATTACH_IVSHMEM=1 \
  SKIP_SEED=0 FULL_CLONE=1 \
  CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
  QEMU_BIN="${QEMU_BIN}" \
  bash "${ROOT}/scripts/host_quickstart.sh"
  is_tdx_image_path=1
fi

wait_ssh "vm1" "${VM1_SSH}"
wait_ssh "vm2" "${VM2_SSH}"

echo "[*] Guest OS versions:"
ssh_vm1 "lsb_release -sd || true"
ssh_vm2 "lsb_release -sd || true"

# TDX images do not rely on our seed; avoid unnecessary waits.
if [[ "${is_tdx_image_path}" -ne 1 ]]; then
  echo "[*] Waiting for cloud-init to finish (timeout=${WAIT_CLOUD_INIT_SECS}s) ..."
  ssh_vm1 "sudo timeout ${WAIT_CLOUD_INIT_SECS} cloud-init status --wait >/dev/null 2>&1 || true"
  ssh_vm2 "sudo timeout ${WAIT_CLOUD_INIT_SECS} cloud-init status --wait >/dev/null 2>&1 || true"
fi

ssh_vm1 "sudo mkdir -p /mnt/hostshare"
ssh_vm1 "if ! mountpoint -q /mnt/hostshare; then sudo mount -t 9p -o trans=virtio,access=any,cache=none,msize=262144 hostshare /mnt/hostshare; fi"
ssh_vm2 "sudo mkdir -p /mnt/hostshare"
ssh_vm2 "if ! mountpoint -q /mnt/hostshare; then sudo mount -t 9p -o trans=virtio,access=any,cache=none,msize=262144 hostshare /mnt/hostshare; fi"

echo "[*] TDX guest hints (best-effort):"
ssh_vm1 "dmesg | grep -i tdx | tail -n 20 || true"
ssh_vm2 "dmesg | grep -i tdx | tail -n 20 || true"

echo "[*] Installing dependencies in guests ..."
ssh_retry_lock ssh_vm1 "vm1 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release redis-server redis-tools net-tools tmux pciutils libsodium-dev pkg-config"

ssh_retry_lock ssh_vm2 "vm2 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm2 "vm2 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release redis-tools net-tools tmux pciutils libsodium-dev pkg-config"
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  ssh_retry_lock ssh_vm2 "vm2 apt-get install openjdk" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-11-jre-headless || sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jre-headless"
fi

echo "[*] Ensuring SSH service is running in guests ..."
ssh_vm1 "sudo systemctl enable --now ssh.service >/dev/null 2>&1 || sudo systemctl enable --now sshd.service >/dev/null 2>&1 || true"
ssh_vm2 "sudo systemctl enable --now ssh.service >/dev/null 2>&1 || sudo systemctl enable --now sshd.service >/dev/null 2>&1 || true"

echo "[*] Building Redis (ring version) in vm1 ..."
ssh_vm1 "sudo systemctl disable --now redis-server >/dev/null 2>&1 || true"
# Build inside /tmp to avoid virtio-9p open-file limitations, then copy artifacts back
ssh_vm1 "sudo -n bash -lc 'set -euo pipefail; \
  rm -rf /tmp/tdx_shm && cp -a /mnt/hostshare/tdx_shm /tmp/tdx_shm; \
  tmp=/tmp/redis_ring_build; \
  rm -rf \"\$tmp\" && mkdir -p \"\$tmp\"; \
  cp -a /mnt/hostshare/redis/. \"\$tmp\"/; \
  cd \"\$tmp/src\"; \
  ulimit -n ${ULIMIT_NOFILE} 2>/dev/null || ulimit -n 8192 2>/dev/null || true; \
  make -j${REDIS_MAKE_JOBS} MALLOC=libc USE_LTO=no CFLAGS=\"-O2 -fno-lto\" LDFLAGS=\"-fno-lto\"; \
  cp -a \"\$tmp\"/. /mnt/hostshare/redis/ \
'"

echo "[*] Building ring client in vm2 (/tmp/cxl_ring_direct) ..."
ssh_vm2 "cd /mnt/hostshare/ring_client && gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct cxl_ring_direct.c -lsodium"

if [[ "${RING_ONLY}" != "1" ]]; then
  echo "[*] Building libsodium tunnel in guests (/tmp/cxl_sodium_tunnel) ..."
  ssh_vm1 "make -C /mnt/hostshare/sodium_tunnel BIN=/tmp/cxl_sodium_tunnel"
  ssh_vm2 "make -C /mnt/hostshare/sodium_tunnel BIN=/tmp/cxl_sodium_tunnel"
fi

echo "[*] Re-checking SSH connectivity after builds ..."
wait_ssh "vm1" "${VM1_SSH}"
wait_ssh "vm2" "${VM2_SSH}"

if [[ "${RING_ONLY}" != "1" ]]; then
  echo "[*] Building cxl_sec_mgr in vm1 (/tmp/cxl_sec_mgr) ..."
  ssh_vm1 "make -C /mnt/hostshare/cxl_sec_mgr BIN=/tmp/cxl_sec_mgr"

  echo "[*] Building GAPBS (native + ring + ring-secure) in vm1 ..."
  ssh_vm1 "cd /mnt/hostshare/gapbs && sudo make clean && sudo make -j2 all ring ring-secure"
else
  echo "[*] RING_ONLY=1: skipping cxl_sec_mgr and GAPBS builds."
fi

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

detect_ring_path_vm() {
  local name="$1"
  local port="$2"
  local ssh_func="$3"
  local out rc
  for _ in $(seq 1 10); do
    set +e
    out="$(${ssh_func} "${detect_ring_path}" 2>&1)"
    rc=$?
    set -e
    if [[ "${rc}" -eq 0 && -n "${out}" ]]; then
      printf '%s\n' "${out}"
      return 0
    fi
    if printf '%s' "${out}" | grep -qiE 'kex_exchange_identification|connection reset|connection timed out|broken pipe|connection closed'; then
      echo "[*] ${name}: SSH hiccup during BAR2 detection; reconnecting ..."
      wait_ssh "${name}" "${port}"
      sleep 1
      continue
    fi
    sleep 1
  done
  return 1
}

if [[ -n "${RING_PATH_OVERRIDE}" ]]; then
  echo "[*] Using RING_PATH_OVERRIDE=${RING_PATH_OVERRIDE} (skip ivshmem BAR2 detection)."
  RING_PATH_VM1="${RING_PATH_OVERRIDE}"
  RING_PATH_VM2="${RING_PATH_OVERRIDE}"
else
  echo "[*] Detecting ivshmem BAR2 path in guests ..."
  RING_PATH_VM1="$(detect_ring_path_vm "vm1" "${VM1_SSH}" ssh_vm1 | tr -d '\r' || true)"
  RING_PATH_VM2="$(detect_ring_path_vm "vm2" "${VM2_SSH}" ssh_vm2 | tr -d '\r' || true)"
  if [[ -z "${RING_PATH_VM1}" || -z "${RING_PATH_VM2}" ]]; then
    echo "[!] Failed to detect ivshmem BAR2 path inside guests." >&2
    echo "    Check: lspci -nn | grep 1af4:1110, and /sys/bus/pci/devices/*/resource2" >&2
    exit 1
  fi
  echo "    vm1 BAR2: ${RING_PATH_VM1}"
  echo "    vm2 BAR2: ${RING_PATH_VM2}"
fi

# Fallback: use UIO mapping when BAR2 mmap is blocked (TDX lockdown).
bind_ivshmem_uio() {
  echo "[*] Binding ivshmem to uio_pci_generic inside guests ..."
  ssh_vm1 "sudo bash /mnt/hostshare/guest/bind_ivshmem_uio.sh"
  ssh_vm2 "sudo bash /mnt/hostshare/guest/bind_ivshmem_uio.sh"

  local uio1 uio2 uio1_name uio2_name map_info1 map_info2 idx1 size1 idx2 size2
  uio1="$(ssh_vm1 'ls -1 /dev/uio* 2>/dev/null | head -n 1' | tr -d '\r')"
  uio2="$(ssh_vm2 'ls -1 /dev/uio* 2>/dev/null | head -n 1' | tr -d '\r')"
  if [[ -z "${uio1}" || -z "${uio2}" ]]; then
    echo "[!] Failed to detect /dev/uioX after binding ivshmem." >&2
    exit 1
  fi
  RING_PATH_VM1="${uio1}"
  RING_PATH_VM2="${uio2}"

  uio1_name="$(basename "${uio1}")"
  uio2_name="$(basename "${uio2}")"

  map_info1="$(ssh_vm1 "set -euo pipefail; shopt -s nullglob; best_idx=-1; best_size=0; \
    for m in /sys/class/uio/${uio1_name}/maps/map*; do idx=\${m##*/map}; size=\$(cat \"\${m}/size\"); dec=\$((size)); \
    if (( dec > best_size )); then best_size=\${dec}; best_idx=\${idx}; fi; done; \
    if (( best_idx < 0 )); then echo 'no uio maps' >&2; exit 1; fi; echo \"\${best_idx} \${best_size}\"" | tr -d '\r')"
  map_info2="$(ssh_vm2 "set -euo pipefail; shopt -s nullglob; best_idx=-1; best_size=0; \
    for m in /sys/class/uio/${uio2_name}/maps/map*; do idx=\${m##*/map}; size=\$(cat \"\${m}/size\"); dec=\$((size)); \
    if (( dec > best_size )); then best_size=\${dec}; best_idx=\${idx}; fi; done; \
    if (( best_idx < 0 )); then echo 'no uio maps' >&2; exit 1; fi; echo \"\${best_idx} \${best_size}\"" | tr -d '\r')"

  read -r idx1 size1 <<<"${map_info1}"
  read -r idx2 size2 <<<"${map_info2}"
  if [[ -z "${idx1}" || -z "${size1}" || -z "${idx2}" || -z "${size2}" ]]; then
    echo "[!] Failed to detect UIO map sizes after binding ivshmem." >&2
    exit 1
  fi

  local page_size=4096
  RING_MAP_OFFSET_VM1=$((idx1 * page_size))
  RING_MAP_OFFSET_VM2=$((idx2 * page_size))
  GAPBS_CXL_MAP_OFFSET_VM1="${RING_MAP_OFFSET_VM1}"
  GAPBS_CXL_MAP_OFFSET_VM2="${RING_MAP_OFFSET_VM2}"

  local min_size="${size1}"
  if [[ "${size2}" -lt "${min_size}" ]]; then
    min_size="${size2}"
  fi
  local region_size_bytes=""
  region_size_bytes="$(size_to_bytes "${RING_REGION_SIZE}" 2>/dev/null || true)"
  local region_base_bytes=""
  region_base_bytes="$(size_to_bytes "${RING_REGION_BASE}" 2>/dev/null || true)"
  if [[ -z "${region_size_bytes}" || -z "${region_base_bytes}" ]]; then
    echo "[!] Failed to parse RING_REGION_SIZE='${RING_REGION_SIZE}' or RING_REGION_BASE='${RING_REGION_BASE}'" >&2
    exit 1
  fi
  local min_needed=$((region_base_bytes + RING_COUNT * region_size_bytes))
  if [[ "${min_size}" -lt "${min_needed}" ]]; then
    echo "[!] UIO map is too small (${min_size} bytes); need at least ${min_needed} bytes for TDX SHM ring regions." >&2
    echo "    This usually means the ivshmem shared-memory BAR isn't exposed via UIO." >&2
    echo "    Try kernel module uio_ivshmem or disable guest lockdown to mmap resource2." >&2
    exit 1
  fi
  if [[ "${RING_MAP_SIZE}" -gt "${min_size}" ]]; then
    echo "[*] Adjusting RING_MAP_SIZE to ${min_size} (uio map size)"
    RING_MAP_SIZE="${min_size}"
  fi
  if [[ "${GAPBS_CXL_MAP_SIZE}" -gt "${min_size}" ]]; then
    echo "[*] Adjusting GAPBS_CXL_MAP_SIZE to ${min_size} (uio map size)"
    GAPBS_CXL_MAP_SIZE="${min_size}"
  fi

  echo "[*] UIO map selected: vm1 map${idx1} size=${size1} offset=${RING_MAP_OFFSET_VM1}; vm2 map${idx2} size=${size2} offset=${RING_MAP_OFFSET_VM2}"
}

ts="$(date +%Y%m%d_%H%M%S)"
native_log="${RESULTS_DIR}/tdx_native_tcp_${ts}.log"
sodium_log="${RESULTS_DIR}/tdx_sodium_tcp_${ts}.log"
ring_log="${RESULTS_DIR}/tdx_ring_${ts}.log"
ring_csv="${RESULTS_DIR}/tdx_ring_${ts}.csv"
ring_crypto_log="${RESULTS_DIR}/tdx_ring_crypto_${ts}.log"
ring_crypto_csv="${RESULTS_DIR}/tdx_ring_crypto_${ts}.csv"
ring_secure_log="${RESULTS_DIR}/tdx_ring_secure_${ts}.log"
ring_secure_csv="${RESULTS_DIR}/tdx_ring_secure_${ts}.csv"
compare_csv="${RESULTS_DIR}/tdx_compare_${ts}.csv"

redis_crypto_key_vm1_hex="$(openssl rand -hex 32)"
redis_crypto_key_vm2_hex="$(openssl rand -hex 32)"
redis_crypto_key_common_hex="$(openssl rand -hex 32)"

echo "[*] Internal VM network (cxl0):"
ssh_vm1 "ip -brief addr show cxl0 2>/dev/null || true"
ssh_vm2 "ip -brief addr show cxl0 2>/dev/null || true"

ring_redis_sock_args=""
if [[ "${RING_REDIS_PORT}" == "0" ]]; then
  # Redis refuses to start when configured to listen nowhere. Keep TCP disabled
  # but bind a local unix socket so the process stays alive to serve the ring.
  ring_redis_sock_args="--unixsocket /tmp/redis_ring.sock --unixsocketperm 777"
fi

if ! [[ "${REDIS_BENCH_DATASIZE}" =~ ^[0-9]+$ ]] || (( REDIS_BENCH_DATASIZE < 1 )); then
  echo "[!] REDIS_BENCH_DATASIZE must be a positive integer (bytes): '${REDIS_BENCH_DATASIZE}'" >&2
  exit 1
fi
if ! [[ "${RING_BENCH_KEY_SIZE}" =~ ^[0-9]+([KkMmGg])?$ ]]; then
  echo "[!] RING_BENCH_KEY_SIZE must be bytes (0=auto), optional K/M/G suffix: '${RING_BENCH_KEY_SIZE}'" >&2
  exit 1
fi
if ! [[ "${RING_BENCH_VALUE_SIZE}" =~ ^[0-9]+([KkMmGg])?$ ]]; then
  echo "[!] RING_BENCH_VALUE_SIZE must be bytes (0=auto), optional K/M/G suffix: '${RING_BENCH_VALUE_SIZE}'" >&2
  exit 1
fi

ring_bench_kv_args=()
if [[ "${RING_BENCH_KEY_SIZE}" != "0" ]]; then ring_bench_kv_args+=("--key-size" "${RING_BENCH_KEY_SIZE}"); fi
if [[ "${RING_BENCH_VALUE_SIZE}" != "0" ]]; then ring_bench_kv_args+=("--val-size" "${RING_BENCH_VALUE_SIZE}"); fi
ring_bench_kv_args_str="${ring_bench_kv_args[*]}"

if [[ "${RING_ONLY}" == "1" ]]; then
  echo "[*] RING_ONLY=1: running ring-only quick validation."
  ring_only_log="${RESULTS_DIR}/tdx_ring_only_${ts}.log"
  ring_only_csv="${RESULTS_DIR}/tdx_ring_only_${ts}.csv"
  ring_only_label="tdx_ring_only_${ts}"
  ring_only_n_per_thread=$(( (RING_ONLY_BENCH_N + RING_ONLY_THREADS - 1) / RING_ONLY_THREADS ))
  ring_only_pipeline_flag=""
  if [[ "${RING_ONLY_PIPELINE}" == "1" ]]; then
    ring_only_pipeline_flag="--pipeline"
  fi

  echo "[*] Ring-only: starting Redis ring in vm1 ..."
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_ring_tdx \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} ./redis-server --port ${RING_REDIS_PORT} ${ring_redis_sock_args} --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx.log 2>&1\""

  for _ in $(seq 1 200); do
	    if ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --ping-timeout-ms ${RING_ONLY_PING_TIMEOUT_MS} >/dev/null 2>&1"; then
	      break
	    fi
    sleep 0.25
  done
	  if ! ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --ping-timeout-ms ${RING_ONLY_PING_TIMEOUT_MS} >/dev/null 2>&1"; then
	    echo "[!] ring transport not ready. Dumping diagnostics..." >&2
	    ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx.log" >&2 || true
    if [[ -n "${RING_PATH_OVERRIDE}" ]]; then
      echo "[!] ring transport not ready with RING_PATH_OVERRIDE; skipping UIO fallback." >&2
      exit 1
    fi
    echo "    Trying UIO-backed ivshmem mapping ..."
    bind_ivshmem_uio
    ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
    ssh_vm1 "tmux new-session -d -s redis_ring_tdx \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} ./redis-server --port ${RING_REDIS_PORT} ${ring_redis_sock_args} --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx.log 2>&1\""
    for _ in $(seq 1 200); do
	      if ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --ping-timeout-ms ${RING_ONLY_PING_TIMEOUT_MS} >/dev/null 2>&1"; then
	        break
	      fi
      sleep 0.25
    done
	    if ! ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --ping-timeout-ms ${RING_ONLY_PING_TIMEOUT_MS} >/dev/null 2>&1"; then
	      echo "[!] ring transport still not ready after UIO fallback." >&2
	      ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx.log" >&2 || true
      exit 1
    fi
  fi

  echo "[*] Ring-only: tiny bench (n=${RING_ONLY_BENCH_N}, threads=${RING_ONLY_THREADS}) ..."
	  ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_only_n_per_thread} ${ring_bench_kv_args_str} ${ring_only_pipeline_flag} --threads ${RING_ONLY_THREADS} --max-inflight ${RING_ONLY_MAX_INFLIGHT} --csv /tmp/${ring_only_label}.csv --label ${ring_only_label}" | tee "${ring_only_log}"
	  ssh_vm2 "cat /tmp/${ring_only_label}.csv" > "${ring_only_csv}"

  ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

  echo "[+] Ring-only quick validation done."
  echo "    log: ${ring_only_log}"
  echo "    csv: ${ring_only_csv}"
  exit 0
fi

echo "[*] Benchmark 1/8: native Redis (TCP/RESP) inside TDX guests"
ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_tdx >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_native_tdx \"/usr/bin/redis-server --port 6379 --protected-mode no --save '' --appendonly no >/tmp/redis_native_tdx.log 2>&1\""
ssh_vm1 "for i in \$(seq 1 200); do redis-cli -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'redis-server not ready' >&2; tail -n 200 /tmp/redis_native_tdx.log >&2 || true; exit 1"

ssh_vm2 "for i in \$(seq 1 200); do redis-cli -h ${VMNET_VM1_IP} -p 6379 ping >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'tcp path not ready' >&2; exit 1"
ssh_vm2 "redis-benchmark -h ${VMNET_VM1_IP} -p 6379 -t set,get -n ${REQ_N} -c ${CLIENTS} --threads ${THREADS} -P ${PIPELINE} -d ${REDIS_BENCH_DATASIZE}" | tee "${native_log}"

# Optional: run YCSB against native TCP endpoint
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: native TCP (VM2 -> VM1:${VMNET_VM1_IP}:6379)"
  ycsb_args=("--host" "${VMNET_VM1_IP}" "--port" "6379" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
  ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
  ssh_vm2 "bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

echo "[*] Benchmark 2/8: native Redis over libsodium-encrypted TCP (tunnel)"
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

ssh_vm2 "redis-benchmark -h 127.0.0.1 -p ${SODIUM_LOCAL_PORT} -t set,get -n ${REQ_N} -c ${CLIENTS} --threads ${THREADS} -P ${PIPELINE} -d ${REDIS_BENCH_DATASIZE}" | tee "${sodium_log}"

# Optional: run YCSB against libsodium-encrypted TCP tunnel
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: sodium TCP (VM2 127.0.0.1:${SODIUM_LOCAL_PORT} -> VM1 ${VMNET_VM1_IP}:${SODIUM_PORT})"
  ycsb_args=("--host" "127.0.0.1" "--port" "${SODIUM_LOCAL_PORT}" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
  ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
  ssh_vm2 "bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

ssh_vm2 "tmux kill-session -t sodium_client >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t sodium_server >/dev/null 2>&1 || true"

ssh_vm1 "redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_native_tdx >/dev/null 2>&1 || true"

echo "[*] Benchmark 3/8: ring Redis (shared-memory) inside TDX guests"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
ssh_vm1 "tmux new-session -d -s redis_ring_tdx \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} ./redis-server --port ${RING_REDIS_PORT} ${ring_redis_sock_args} --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx.log 2>&1\""

for _ in $(seq 1 200); do
  if ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
    break
  fi
  sleep 0.25
done
if ! ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
  echo "[!] ring transport not ready. Dumping diagnostics..." >&2
  ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx.log" >&2 || true
  if [[ -n "${RING_PATH_OVERRIDE}" ]]; then
    echo "[!] ring transport not ready with RING_PATH_OVERRIDE; skipping UIO fallback." >&2
    exit 1
  fi
  echo "    Trying UIO-backed ivshmem mapping ..."
  bind_ivshmem_uio
  ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_ring_tdx \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} ./redis-server --port ${RING_REDIS_PORT} ${ring_redis_sock_args} --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx.log 2>&1\""
  # Re-check with fallback
  for _ in $(seq 1 200); do
    if ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
      break
    fi
    sleep 0.25
  done
  if ! ssh_vm2 "sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} timeout 2 /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} >/dev/null 2>&1"; then
    echo "[!] ring transport still not ready after UIO fallback." >&2
    ssh_vm1 "tail -n 200 /tmp/redis_ring_tdx.log" >&2 || true
    exit 1
  fi
fi

ring_label="tdx_ring_${ts}"
ring_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} /tmp/cxl_ring_direct --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_n_per_thread} ${ring_bench_kv_args_str} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_label}.csv --label ${ring_label}" | tee "${ring_log}"
ssh_vm2 "cat /tmp/${ring_label}.csv" > "${ring_csv}"

# Optional: run YCSB against ring via local RESP proxy inside VM2
if [[ "${YCSB_ENABLE}" == "1" ]]; then
  echo "[*] YCSB: ring via RESP proxy (VM2 127.0.0.1:6381 -> ring BAR2)"
  ycsb_args=("--host" "127.0.0.1" "--port" "6381" "--workloads" "${YCSB_WORKLOADS}" \
             "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
             "--threads" "${YCSB_THREADS}")
  if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
  if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
  ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
  ssh_vm2 "RING_RESP_PROXY=1 RING_PATH=${RING_PATH_VM2} RING_MAP_SIZE=${RING_MAP_SIZE} RING_MAP_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} RING_RESP_LISTEN=127.0.0.1:6381 bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
fi

ssh_vm1 "tmux kill-session -t redis_ring_tdx >/dev/null 2>&1 || true"
ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

RUN_CRYPTO=0
if [[ "${ENABLE_CRYPTO}" == "1" ]]; then
  echo "[*] Benchmark 4/8: crypto ring Redis (software crypto, no manager)"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_tdx_crypto >/dev/null 2>&1 || true"
  ssh_vm1 "tmux new-session -d -s redis_ring_tdx_crypto \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX=${redis_crypto_key_vm1_hex} CXL_SEC_COMMON_KEY_HEX=${redis_crypto_key_common_hex} CXL_CRYPTO_PRIV_REGION_SIZE=${CXL_CRYPTO_PRIV_REGION_SIZE} ./redis-server --port ${RING_REDIS_PORT} ${ring_redis_sock_args} --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx_crypto.log 2>&1\""

  ssh_vm2 "for i in \$(seq 1 200); do sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX=${redis_crypto_key_vm2_hex} CXL_SEC_COMMON_KEY_HEX=${redis_crypto_key_common_hex} CXL_CRYPTO_PRIV_REGION_SIZE=${CXL_CRYPTO_PRIV_REGION_SIZE} timeout 5 /tmp/cxl_ring_direct --crypto --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --ping-timeout-ms 5000 >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'crypto ring not ready' >&2; exit 1"

  ring_crypto_label="tdx_ring_crypto_${ts}"
  ring_crypto_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
  ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX=${redis_crypto_key_vm2_hex} CXL_SEC_COMMON_KEY_HEX=${redis_crypto_key_common_hex} CXL_CRYPTO_PRIV_REGION_SIZE=${CXL_CRYPTO_PRIV_REGION_SIZE} /tmp/cxl_ring_direct --crypto --sec-node-id 2 --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_crypto_n_per_thread} ${ring_bench_kv_args_str} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_crypto_label}.csv --label ${ring_crypto_label}" | tee "${ring_crypto_log}"
  ssh_vm2 "cat /tmp/${ring_crypto_label}.csv" > "${ring_crypto_csv}"

  # Optional: run YCSB against crypto ring via local RESP proxy inside VM2
  if [[ "${YCSB_ENABLE}" == "1" ]]; then
    echo "[*] YCSB: crypto ring via RESP proxy (VM2 127.0.0.1:6383 -> ring BAR2)"
    ycsb_args=("--host" "127.0.0.1" "--port" "6383" "--workloads" "${YCSB_WORKLOADS}" \
               "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
               "--threads" "${YCSB_THREADS}")
    if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
    if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
    ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
    ssh_vm2 "RING_RESP_PROXY=1 RING_RESP_CRYPTO=1 RING_PATH=${RING_PATH_VM2} RING_MAP_SIZE=${RING_MAP_SIZE} RING_MAP_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_REGION_BASE} CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX=${redis_crypto_key_vm2_hex} CXL_SEC_COMMON_KEY_HEX=${redis_crypto_key_common_hex} CXL_CRYPTO_PRIV_REGION_SIZE=${CXL_CRYPTO_PRIV_REGION_SIZE} RING_RESP_LISTEN=127.0.0.1:6383 bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
  fi

  ssh_vm1 "tmux kill-session -t redis_ring_tdx_crypto >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  RUN_CRYPTO=1
else
  echo "[*] Skipping crypto ring Redis (ENABLE_CRYPTO=0)"
fi

RUN_SECURE=0
if [[ "${ENABLE_SECURE}" == "1" ]]; then
  echo "[*] Benchmark 5/8: secure ring Redis (ACL + software crypto via cxl_sec_mgr)"

  echo "[*] Secure ring: clearing first page for CXLSEC table ..."
  ssh_vm1 "sudo -n env CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} python3 -c 'import mmap, os; off=int(os.environ.get(\"CXL_RING_OFFSET\", \"0\"), 0); fd=os.open(\"${RING_PATH_VM1}\", os.O_RDWR); m=mmap.mmap(fd, 4096, access=mmap.ACCESS_WRITE, offset=off); m[:] = b\"\\0\"*4096; m.flush(); m.close(); os.close(fd)'"

  ssh_vm1 "tmux kill-session -t cxl_sec_mgr_ring_tdx >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t redis_ring_tdx_secure >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"

  ssh_vm1 "tmux new-session -d -s cxl_sec_mgr_ring_tdx \"sudo -n /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${RING_MAP_SIZE} --map-offset ${RING_MAP_OFFSET_VM1} --tdx-ring --ring-count ${RING_COUNT} --ring-region-size ${RING_REGION_SIZE} --ring-region-base ${RING_SECURE_REGION_BASE} >/tmp/cxl_sec_mgr_ring_tdx_${ts}.log 2>&1\""
  ssh_vm1 "tmux new-session -d -s redis_ring_tdx_secure \"cd /mnt/hostshare/redis/src && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_PATH=${RING_PATH_VM1} CXL_RING_MAP_SIZE=${RING_MAP_SIZE} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_SECURE_REGION_BASE} CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS=${SEC_MGR_TIMEOUT_MS} CXL_SEC_MGR=127.0.0.1:${SEC_MGR_PORT} CXL_SEC_NODE_ID=1 ./redis-server --port ${RING_REDIS_PORT} ${ring_redis_sock_args} --protected-mode no --save '' --appendonly no >/tmp/redis_ring_tdx_secure.log 2>&1\""

  ssh_vm2 "for i in \$(seq 1 200); do sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_SECURE_REGION_BASE} CXL_SEC_TIMEOUT_MS=${SEC_MGR_TIMEOUT_MS} timeout 5 /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --sec-timeout-ms ${SEC_MGR_TIMEOUT_MS} --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --ping-timeout-ms 5000 >/dev/null 2>&1 && exit 0; sleep 0.25; done; echo 'secure ring not ready' >&2; exit 1"

  ring_secure_label="tdx_ring_secure_${ts}"
  ring_secure_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
  ssh_vm2 "cd /tmp && sudo env CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_POLL_SPIN_NS=${CXL_RING_POLL_SPIN_NS} CXL_RING_POLL_SLEEP_NS=${CXL_RING_POLL_SLEEP_NS} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_SECURE_REGION_BASE} CXL_SEC_TIMEOUT_MS=${SEC_MGR_TIMEOUT_MS} /tmp/cxl_ring_direct --secure --sec-mgr ${VMNET_VM1_IP}:${SEC_MGR_PORT} --sec-node-id 2 --sec-timeout-ms ${SEC_MGR_TIMEOUT_MS} --path ${RING_PATH_VM2} --map-size ${RING_MAP_SIZE} --bench ${ring_secure_n_per_thread} ${ring_bench_kv_args_str} --pipeline --threads ${THREADS} --max-inflight ${MAX_INFLIGHT} --latency --cost --csv /tmp/${ring_secure_label}.csv --label ${ring_secure_label}" | tee "${ring_secure_log}"
  ssh_vm2 "cat /tmp/${ring_secure_label}.csv" > "${ring_secure_csv}"

  # Optional: run YCSB against secure ring via local RESP proxy inside VM2
  if [[ "${YCSB_ENABLE}" == "1" ]]; then
    echo "[*] YCSB: secure ring via RESP proxy (VM2 127.0.0.1:6382 -> ring BAR2)"
    ycsb_args=("--host" "127.0.0.1" "--port" "6382" "--workloads" "${YCSB_WORKLOADS}" \
               "--recordcount" "${YCSB_RECORDS}" "--operationcount" "${YCSB_OPS}" \
               "--threads" "${YCSB_THREADS}")
    if [[ -n "${YCSB_TARGET}" ]]; then ycsb_args+=("--target" "${YCSB_TARGET}"); fi
    if [[ -n "${YCSB_PASSWORD}" ]]; then ycsb_args+=("--password" "${YCSB_PASSWORD}"); fi
    ycsb_args+=("--cluster" "${YCSB_CLUSTER}")
    ssh_vm2 "RING_RESP_PROXY=1 RING_RESP_SECURE=1 RING_RESP_SEC_MGR=${VMNET_VM1_IP}:${SEC_MGR_PORT} RING_RESP_SEC_NODE_ID=2 RING_RESP_SEC_TIMEOUT_MS=${SEC_MGR_TIMEOUT_MS} RING_PATH=${RING_PATH_VM2} RING_MAP_SIZE=${RING_MAP_SIZE} RING_MAP_OFFSET=${RING_MAP_OFFSET_VM2} CXL_RING_OFFSET=${RING_MAP_OFFSET_VM2} CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS} CXL_RING_COUNT=${RING_COUNT} CXL_RING_REGION_SIZE=${RING_REGION_SIZE} CXL_RING_REGION_BASE=${RING_SECURE_REGION_BASE} CXL_SEC_TIMEOUT_MS=${SEC_MGR_TIMEOUT_MS} RING_RESP_LISTEN=127.0.0.1:6382 bash /mnt/hostshare/scripts/run_ycsb.sh ${ycsb_args[*]}"
  fi

  ssh_vm1 "tmux kill-session -t redis_ring_tdx_secure >/dev/null 2>&1 || true"
  ssh_vm1 "tmux kill-session -t cxl_sec_mgr_ring_tdx >/dev/null 2>&1 || true"
  ssh_vm1 "sudo pkill -x redis-server >/dev/null 2>&1 || true"
  RUN_SECURE=1
else
  echo "[*] Skipping secure ring Redis (ENABLE_SECURE=0)"
fi

native_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
native_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
sodium_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${sodium_log}" || true)"
sodium_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${sodium_log}" || true)"
ring_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_csv}" || true)"
ring_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_csv}" || true)"
ring_crypto_set=""
ring_crypto_get=""
if [[ "${RUN_CRYPTO}" == "1" ]]; then
  ring_crypto_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_crypto_csv}" || true)"
  ring_crypto_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_crypto_csv}" || true)"
fi
ring_secure_set=""
ring_secure_get=""
if [[ "${RUN_SECURE}" == "1" ]]; then
  ring_secure_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_secure_csv}" || true)"
  ring_secure_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_secure_csv}" || true)"
fi

{
  echo "label,op,throughput_rps"
  echo "TDXNativeTCP,SET,${native_set}"
  echo "TDXNativeTCP,GET,${native_get}"
  echo "TDXSodiumTCP,SET,${sodium_set}"
  echo "TDXSodiumTCP,GET,${sodium_get}"
  echo "TDXRing,SET,${ring_set}"
  echo "TDXRing,GET,${ring_get}"
  if [[ "${RUN_CRYPTO}" == "1" ]]; then
    echo "TDXRingCrypto,SET,${ring_crypto_set}"
    echo "TDXRingCrypto,GET,${ring_crypto_get}"
  fi
  if [[ "${RUN_SECURE}" == "1" ]]; then
    echo "TDXRingSecure,SET,${ring_secure_set}"
    echo "TDXRingSecure,GET,${ring_secure_get}"
  fi
} > "${compare_csv}"

avg_from_log() {
  local log="$1"
  if [[ ! -f "${log}" ]]; then
    echo ""
    return 0
  fi
  if [[ "${GAPBS_DROP_FIRST_TRIAL}" == "1" ]]; then
    awk '
      /^Trial Time:/ { t[n++] = $3; next }
      END {
        if (n == 0) exit
        start = (n > 1) ? 1 : 0
        sum = 0
        for (i = start; i < n; i++) sum += t[i]
        cnt = n - start
        if (cnt <= 0) exit
        printf "%.5f", (sum / cnt)
      }
    ' "${log}" | tr -d '\r' || true
  else
    awk '/^Average Time:/{print $3; exit}' "${log}" | tr -d '\r' || true
  fi
}

trials_in_log() {
  local log="$1"
  if [[ ! -f "${log}" ]]; then
    echo ""
    return 0
  fi
  awk 'BEGIN{n=0} /^Trial Time:/{n++} END{if (n>0) print n;}' "${log}" | tr -d '\r' || true
}

trials_used_for_avg_from_log() {
  local log="$1"
  local n
  n="$(trials_in_log "${log}")"
  if [[ -z "${n}" ]]; then
    echo ""
    return 0
  fi
  if [[ "${GAPBS_DROP_FIRST_TRIAL}" == "1" && "${n}" -gt 1 ]]; then
    echo $((n - 1))
  else
    echo "${n}"
  fi
}

e2e_avg_time_s_from_avg_attach_ms() {
  local avg_s="$1"
  local attach_ms="$2"
  local trials_used="$3"
  awk -v avg="${avg_s}" -v ms="${attach_ms}" -v n="${trials_used}" 'BEGIN{
    if (avg == "" || n == "" || n == 0) { print ""; exit }
    if (ms == "") ms = 0
    printf "%.5f", (avg + (ms / 1000.0) / n)
  }'
}

cxl_attach_field_from_log() {
  local log="$1"
  local key="$2"
  if [[ ! -f "${log}" ]]; then
    echo ""
    return 0
  fi
  awk -v k="${key}" '
    /^\[gapbs\] CXL attach:/ {
      for (i = 1; i <= NF; i++) {
        if (index($i, k"=") == 1) {
          v = $i;
          sub(k"=", "", v);
          print v;
          exit;
        }
      }
    }
  ' "${log}" | tr -d '\r' || true
}

edges_for_teps_from_log() {
  local log="$1"
  if [[ ! -f "${log}" ]]; then
    echo ""
    return 0
  fi
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

run_gapbs_kernel() {
  local kernel="$1"
  if [[ -z "${kernel}" ]]; then
    return 0
  fi

  local gapbs_native_vm1_log="${RESULTS_DIR}/tdx_gapbs_native_vm1_${kernel}_${ts}.log"
  local gapbs_native_vm2_log="${RESULTS_DIR}/tdx_gapbs_native_vm2_${kernel}_${ts}.log"

  local gapbs_ring_pub_log="${RESULTS_DIR}/tdx_gapbs_ring_publish_${kernel}_${ts}.log"
  local gapbs_ring_vm1_log="${RESULTS_DIR}/tdx_gapbs_ring_vm1_${kernel}_${ts}.log"
  local gapbs_ring_vm2_log="${RESULTS_DIR}/tdx_gapbs_ring_vm2_${kernel}_${ts}.log"

  local gapbs_crypto_pub_log="${RESULTS_DIR}/tdx_gapbs_crypto_publish_${kernel}_${ts}.log"
  local gapbs_crypto_vm1_log="${RESULTS_DIR}/tdx_gapbs_crypto_vm1_${kernel}_${ts}.log"
  local gapbs_crypto_vm2_log="${RESULTS_DIR}/tdx_gapbs_crypto_vm2_${kernel}_${ts}.log"

  local gapbs_secure_mgr_log="${RESULTS_DIR}/tdx_gapbs_secure_mgr_${kernel}_${ts}.log"
  local gapbs_secure_pub_log="${RESULTS_DIR}/tdx_gapbs_secure_publish_${kernel}_${ts}.log"
  local gapbs_secure_vm1_log="${RESULTS_DIR}/tdx_gapbs_secure_vm1_${kernel}_${ts}.log"
  local gapbs_secure_vm2_log="${RESULTS_DIR}/tdx_gapbs_secure_vm2_${kernel}_${ts}.log"

  local gapbs_compare_csv="${RESULTS_DIR}/tdx_gapbs_compare_${kernel}_${ts}.csv"
  local gapbs_overhead_csv="${RESULTS_DIR}/tdx_gapbs_overhead_${kernel}_${ts}.csv"

  echo "[*] GAPBS kernel=${kernel}: native in vm1"
  ssh_vm1 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' ./'${kernel}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    | tee "${gapbs_native_vm1_log}"

  echo "[*] GAPBS kernel=${kernel}: native in vm2"
  ssh_vm2 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' ./'${kernel}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
    | tee "${gapbs_native_vm2_log}"

  echo "[*] GAPBS kernel=${kernel}: multihost ring publish in vm1"
  ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM1}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 ./'${kernel}-ring' -g '${SCALE}' -k '${DEGREE}' -n 1" \
    | tee "${gapbs_ring_pub_log}"

  echo "[*] GAPBS kernel=${kernel}: multihost ring attach+run in vm1+vm2 (concurrent)"
  (
    ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PRETOUCH='${GAPBS_CXL_PRETOUCH_RING}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM1}' GAPBS_CXL_MODE=attach ./'${kernel}-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
      >"${gapbs_ring_vm1_log}" 2>&1
  ) &
  local pid_gapbs_ring_vm1=$!

  (
    ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PRETOUCH='${GAPBS_CXL_PRETOUCH_RING}' GAPBS_CXL_PATH='${RING_PATH_VM2}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM2}' GAPBS_CXL_MODE=attach ./'${kernel}-ring' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
      >"${gapbs_ring_vm2_log}" 2>&1
  ) &
  local pid_gapbs_ring_vm2=$!

  wait "${pid_gapbs_ring_vm1}"
  wait "${pid_gapbs_ring_vm2}"

  if [[ "${ENABLE_SECURE}" == "1" ]]; then
    local crypto_key_vm1_hex crypto_key_vm2_hex crypto_key_common_hex
    crypto_key_vm1_hex="$(openssl rand -hex 32)"
    crypto_key_vm2_hex="$(openssl rand -hex 32)"
    crypto_key_common_hex="$(openssl rand -hex 32)"

    echo "[*] GAPBS kernel=${kernel}: multihost crypto publish in vm1 (libsodium; no mgr)"
    ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM1}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX='${crypto_key_vm1_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' ./'${kernel}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n 1" \
      | tee "${gapbs_crypto_pub_log}"

    echo "[*] GAPBS kernel=${kernel}: multihost crypto attach+run in vm1+vm2 (concurrent)"
    (
      ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM1}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX='${crypto_key_vm1_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' ./'${kernel}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
        >"${gapbs_crypto_vm1_log}" 2>&1
    ) &
    local pid_gapbs_crypto_vm1=$!

    (
      ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM2}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM2}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX='${crypto_key_vm2_hex}' CXL_SEC_COMMON_KEY_HEX='${crypto_key_common_hex}' ./'${kernel}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
        >"${gapbs_crypto_vm2_log}" 2>&1
    ) &
    local pid_gapbs_crypto_vm2=$!

    wait "${pid_gapbs_crypto_vm1}"
    wait "${pid_gapbs_crypto_vm2}"

    echo "[*] GAPBS kernel=${kernel}: multihost secure publish in vm1 (ACL/key table via cxl_sec_mgr)"
    ssh_vm1 "sudo -n env CXL_RING_OFFSET=${RING_MAP_OFFSET_VM1} python3 -c 'import mmap, os; off=int(os.environ.get(\"CXL_RING_OFFSET\", \"0\"), 0); fd=os.open(\"${RING_PATH_VM1}\", os.O_RDWR); m=mmap.mmap(fd, 4096, access=mmap.ACCESS_WRITE, offset=off); m[:] = b\"\\0\"*4096; m.flush(); m.close(); os.close(fd)'"

    local gapbs_sec_mgr_remote="/tmp/cxl_sec_mgr_gapbs_tdx_${kernel}_${ts}.log"
    local gapbs_sec_mgr_pid
    gapbs_sec_mgr_pid="$(ssh_vm1 "sudo -n bash -lc 'CXL_RING_OFFSET=${GAPBS_CXL_MAP_OFFSET_VM1} nohup /tmp/cxl_sec_mgr --ring ${RING_PATH_VM1} --listen 0.0.0.0:${SEC_MGR_PORT} --map-size ${GAPBS_CXL_MAP_SIZE} --timeout-ms ${SEC_MGR_TIMEOUT_MS} >${gapbs_sec_mgr_remote} 2>&1 & echo \$!'" | tr -d '\r')"
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

    ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM1}' GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS='${SEC_MGR_TIMEOUT_MS}' CXL_SEC_MGR='127.0.0.1:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=1 ./'${kernel}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n 1" \
      | tee "${gapbs_secure_pub_log}"

    echo "[*] GAPBS kernel=${kernel}: multihost secure attach+run in vm1+vm2 (concurrent)"
    (
      ssh_vm1 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM1}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM1}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS='${SEC_MGR_TIMEOUT_MS}' CXL_SEC_MGR='127.0.0.1:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=1 ./'${kernel}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
        >"${gapbs_secure_vm1_log}" 2>&1
    ) &
    local pid_gapbs_secure_vm1=$!

    (
      ssh_vm2 "cd /mnt/hostshare/gapbs && sudo -n env OMP_NUM_THREADS='${OMP_THREADS}' OMP_PROC_BIND='${OMP_PROC_BIND}' OMP_PLACES='${OMP_PLACES}' CXL_SHM_DELAY_NS='${CXL_SHM_DELAY_NS}' GAPBS_CXL_PATH='${RING_PATH_VM2}' GAPBS_CXL_MAP_SIZE='${GAPBS_CXL_MAP_SIZE}' GAPBS_CXL_MAP_OFFSET='${GAPBS_CXL_MAP_OFFSET_VM2}' GAPBS_CXL_MODE=attach CXL_SEC_ENABLE=1 CXL_SEC_TIMEOUT_MS='${SEC_MGR_TIMEOUT_MS}' CXL_SEC_MGR='${VMNET_VM1_IP}:${SEC_MGR_PORT}' CXL_SEC_NODE_ID=2 ./'${kernel}-ring-secure' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" \
        >"${gapbs_secure_vm2_log}" 2>&1
    ) &
    local pid_gapbs_secure_vm2=$!

    wait "${pid_gapbs_secure_vm1}"
    wait "${pid_gapbs_secure_vm2}"

    ssh_vm1 "sudo -n cat '${gapbs_sec_mgr_remote}'" | tee "${gapbs_secure_mgr_log}" || true
    ssh_vm1 "sudo -n kill ${gapbs_sec_mgr_pid} >/dev/null 2>&1 || true"
  fi

  local gapbs_native_vm1_avg gapbs_native_vm2_avg gapbs_ring_vm1_avg gapbs_ring_vm2_avg gapbs_crypto_vm1_avg gapbs_crypto_vm2_avg gapbs_secure_vm1_avg gapbs_secure_vm2_avg
  gapbs_native_vm1_avg="$(avg_from_log "${gapbs_native_vm1_log}")"
  gapbs_native_vm2_avg="$(avg_from_log "${gapbs_native_vm2_log}")"
  gapbs_ring_vm1_avg="$(avg_from_log "${gapbs_ring_vm1_log}")"
  gapbs_ring_vm2_avg="$(avg_from_log "${gapbs_ring_vm2_log}")"
  gapbs_crypto_vm1_avg="$(avg_from_log "${gapbs_crypto_vm1_log}")"
  gapbs_crypto_vm2_avg="$(avg_from_log "${gapbs_crypto_vm2_log}")"
  gapbs_secure_vm1_avg="$(avg_from_log "${gapbs_secure_vm1_log}")"
  gapbs_secure_vm2_avg="$(avg_from_log "${gapbs_secure_vm2_log}")"

  local gapbs_native_vm1_trials_used gapbs_native_vm2_trials_used gapbs_ring_vm1_trials_used gapbs_ring_vm2_trials_used
  local gapbs_crypto_vm1_trials_used gapbs_crypto_vm2_trials_used gapbs_secure_vm1_trials_used gapbs_secure_vm2_trials_used
  gapbs_native_vm1_trials_used="$(trials_used_for_avg_from_log "${gapbs_native_vm1_log}")"
  gapbs_native_vm2_trials_used="$(trials_used_for_avg_from_log "${gapbs_native_vm2_log}")"
  gapbs_ring_vm1_trials_used="$(trials_used_for_avg_from_log "${gapbs_ring_vm1_log}")"
  gapbs_ring_vm2_trials_used="$(trials_used_for_avg_from_log "${gapbs_ring_vm2_log}")"
  gapbs_crypto_vm1_trials_used="$(trials_used_for_avg_from_log "${gapbs_crypto_vm1_log}")"
  gapbs_crypto_vm2_trials_used="$(trials_used_for_avg_from_log "${gapbs_crypto_vm2_log}")"
  gapbs_secure_vm1_trials_used="$(trials_used_for_avg_from_log "${gapbs_secure_vm1_log}")"
  gapbs_secure_vm2_trials_used="$(trials_used_for_avg_from_log "${gapbs_secure_vm2_log}")"

  local gapbs_native_vm1_edges gapbs_native_vm2_edges gapbs_ring_vm1_edges gapbs_ring_vm2_edges gapbs_crypto_vm1_edges gapbs_crypto_vm2_edges gapbs_secure_vm1_edges gapbs_secure_vm2_edges
  gapbs_native_vm1_edges="$(edges_for_teps_from_log "${gapbs_native_vm1_log}")"
  gapbs_native_vm2_edges="$(edges_for_teps_from_log "${gapbs_native_vm2_log}")"
  gapbs_ring_vm1_edges="$(edges_for_teps_from_log "${gapbs_ring_vm1_log}")"
  gapbs_ring_vm2_edges="$(edges_for_teps_from_log "${gapbs_ring_vm2_log}")"
  gapbs_crypto_vm1_edges="$(edges_for_teps_from_log "${gapbs_crypto_vm1_log}")"
  gapbs_crypto_vm2_edges="$(edges_for_teps_from_log "${gapbs_crypto_vm2_log}")"
  gapbs_secure_vm1_edges="$(edges_for_teps_from_log "${gapbs_secure_vm1_log}")"
  gapbs_secure_vm2_edges="$(edges_for_teps_from_log "${gapbs_secure_vm2_log}")"

  local gapbs_native_vm1_teps gapbs_native_vm2_teps gapbs_ring_vm1_teps gapbs_ring_vm2_teps gapbs_crypto_vm1_teps gapbs_crypto_vm2_teps gapbs_secure_vm1_teps gapbs_secure_vm2_teps
  gapbs_native_vm1_teps="$(teps_from_edges_time "${gapbs_native_vm1_edges}" "${gapbs_native_vm1_avg}")"
  gapbs_native_vm2_teps="$(teps_from_edges_time "${gapbs_native_vm2_edges}" "${gapbs_native_vm2_avg}")"
  gapbs_ring_vm1_teps="$(teps_from_edges_time "${gapbs_ring_vm1_edges}" "${gapbs_ring_vm1_avg}")"
  gapbs_ring_vm2_teps="$(teps_from_edges_time "${gapbs_ring_vm2_edges}" "${gapbs_ring_vm2_avg}")"
  gapbs_crypto_vm1_teps="$(teps_from_edges_time "${gapbs_crypto_vm1_edges}" "${gapbs_crypto_vm1_avg}")"
  gapbs_crypto_vm2_teps="$(teps_from_edges_time "${gapbs_crypto_vm2_edges}" "${gapbs_crypto_vm2_avg}")"
  gapbs_secure_vm1_teps="$(teps_from_edges_time "${gapbs_secure_vm1_edges}" "${gapbs_secure_vm1_avg}")"
  gapbs_secure_vm2_teps="$(teps_from_edges_time "${gapbs_secure_vm2_edges}" "${gapbs_secure_vm2_avg}")"

  local gapbs_native_avg_edges gapbs_ring_avg_edges gapbs_crypto_avg_edges gapbs_secure_avg_edges
  gapbs_native_avg_edges="$(pick_nonempty "${gapbs_native_vm1_edges}" "${gapbs_native_vm2_edges}")"
  gapbs_ring_avg_edges="$(pick_nonempty "${gapbs_ring_vm1_edges}" "${gapbs_ring_vm2_edges}")"
  gapbs_crypto_avg_edges="$(pick_nonempty "${gapbs_crypto_vm1_edges}" "${gapbs_crypto_vm2_edges}")"
  gapbs_secure_avg_edges="$(pick_nonempty "${gapbs_secure_vm1_edges}" "${gapbs_secure_vm2_edges}")"

  local gapbs_native_avg_time gapbs_ring_avg_time gapbs_crypto_avg_time gapbs_secure_avg_time
  gapbs_native_avg_time="$(avg2_float "${gapbs_native_vm1_avg}" "${gapbs_native_vm2_avg}")"
  gapbs_ring_avg_time="$(avg2_float "${gapbs_ring_vm1_avg}" "${gapbs_ring_vm2_avg}")"
  gapbs_crypto_avg_time="$(avg2_float "${gapbs_crypto_vm1_avg}" "${gapbs_crypto_vm2_avg}")"
  gapbs_secure_avg_time="$(avg2_float "${gapbs_secure_vm1_avg}" "${gapbs_secure_vm2_avg}")"

  local gapbs_native_avg_teps gapbs_ring_avg_teps gapbs_crypto_avg_teps gapbs_secure_avg_teps
  gapbs_native_avg_teps="$(avg2_int "${gapbs_native_vm1_teps}" "${gapbs_native_vm2_teps}")"
  gapbs_ring_avg_teps="$(avg2_int "${gapbs_ring_vm1_teps}" "${gapbs_ring_vm2_teps}")"
  gapbs_crypto_avg_teps="$(avg2_int "${gapbs_crypto_vm1_teps}" "${gapbs_crypto_vm2_teps}")"
  gapbs_secure_avg_teps="$(avg2_int "${gapbs_secure_vm1_teps}" "${gapbs_secure_vm2_teps}")"

  local gapbs_ring_vm1_attach_total_ms gapbs_ring_vm2_attach_total_ms gapbs_ring_vm1_attach_wait_ms gapbs_ring_vm2_attach_wait_ms
  local gapbs_ring_vm1_attach_decrypt_ms gapbs_ring_vm2_attach_decrypt_ms gapbs_ring_vm1_attach_pretouch_ms gapbs_ring_vm2_attach_pretouch_ms
  gapbs_ring_vm1_attach_total_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm1_log}" total_ms)"
  gapbs_ring_vm2_attach_total_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm2_log}" total_ms)"
  gapbs_ring_vm1_attach_wait_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm1_log}" wait_ms)"
  gapbs_ring_vm2_attach_wait_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm2_log}" wait_ms)"
  gapbs_ring_vm1_attach_decrypt_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm1_log}" decrypt_ms)"
  gapbs_ring_vm2_attach_decrypt_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm2_log}" decrypt_ms)"
  gapbs_ring_vm1_attach_pretouch_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm1_log}" pretouch_ms)"
  gapbs_ring_vm2_attach_pretouch_ms="$(cxl_attach_field_from_log "${gapbs_ring_vm2_log}" pretouch_ms)"

  local gapbs_ring_avg_attach_total_ms gapbs_ring_avg_attach_wait_ms gapbs_ring_avg_attach_decrypt_ms gapbs_ring_avg_attach_pretouch_ms
  gapbs_ring_avg_attach_total_ms="$(avg2_int "${gapbs_ring_vm1_attach_total_ms}" "${gapbs_ring_vm2_attach_total_ms}")"
  gapbs_ring_avg_attach_wait_ms="$(avg2_int "${gapbs_ring_vm1_attach_wait_ms}" "${gapbs_ring_vm2_attach_wait_ms}")"
  gapbs_ring_avg_attach_decrypt_ms="$(avg2_int "${gapbs_ring_vm1_attach_decrypt_ms}" "${gapbs_ring_vm2_attach_decrypt_ms}")"
  gapbs_ring_avg_attach_pretouch_ms="$(avg2_int "${gapbs_ring_vm1_attach_pretouch_ms}" "${gapbs_ring_vm2_attach_pretouch_ms}")"

  local gapbs_native_vm1_e2e_avg gapbs_native_vm2_e2e_avg gapbs_native_avg_e2e_time
  local gapbs_ring_vm1_e2e_avg gapbs_ring_vm2_e2e_avg gapbs_ring_avg_e2e_time
  local gapbs_crypto_vm1_e2e_avg gapbs_crypto_vm2_e2e_avg gapbs_crypto_avg_e2e_time
  local gapbs_secure_vm1_e2e_avg gapbs_secure_vm2_e2e_avg gapbs_secure_avg_e2e_time

  local gapbs_native_vm1_e2e_teps gapbs_native_vm2_e2e_teps gapbs_native_avg_e2e_teps
  local gapbs_ring_vm1_e2e_teps gapbs_ring_vm2_e2e_teps gapbs_ring_avg_e2e_teps
  local gapbs_crypto_vm1_e2e_teps gapbs_crypto_vm2_e2e_teps gapbs_crypto_avg_e2e_teps
  local gapbs_secure_vm1_e2e_teps gapbs_secure_vm2_e2e_teps gapbs_secure_avg_e2e_teps

  gapbs_native_vm1_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_native_vm1_avg}" 0 "${gapbs_native_vm1_trials_used}")"
  gapbs_native_vm2_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_native_vm2_avg}" 0 "${gapbs_native_vm2_trials_used}")"
  gapbs_native_avg_e2e_time="$(avg2_float "${gapbs_native_vm1_e2e_avg}" "${gapbs_native_vm2_e2e_avg}")"
  gapbs_native_vm1_e2e_teps="$(teps_from_edges_time "${gapbs_native_vm1_edges}" "${gapbs_native_vm1_e2e_avg}")"
  gapbs_native_vm2_e2e_teps="$(teps_from_edges_time "${gapbs_native_vm2_edges}" "${gapbs_native_vm2_e2e_avg}")"
  gapbs_native_avg_e2e_teps="$(avg2_int "${gapbs_native_vm1_e2e_teps}" "${gapbs_native_vm2_e2e_teps}")"

  gapbs_ring_vm1_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_ring_vm1_avg}" "${gapbs_ring_vm1_attach_total_ms}" "${gapbs_ring_vm1_trials_used}")"
  gapbs_ring_vm2_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_ring_vm2_avg}" "${gapbs_ring_vm2_attach_total_ms}" "${gapbs_ring_vm2_trials_used}")"
  gapbs_ring_avg_e2e_time="$(avg2_float "${gapbs_ring_vm1_e2e_avg}" "${gapbs_ring_vm2_e2e_avg}")"
  gapbs_ring_vm1_e2e_teps="$(teps_from_edges_time "${gapbs_ring_vm1_edges}" "${gapbs_ring_vm1_e2e_avg}")"
  gapbs_ring_vm2_e2e_teps="$(teps_from_edges_time "${gapbs_ring_vm2_edges}" "${gapbs_ring_vm2_e2e_avg}")"
  gapbs_ring_avg_e2e_teps="$(avg2_int "${gapbs_ring_vm1_e2e_teps}" "${gapbs_ring_vm2_e2e_teps}")"

  local gapbs_crypto_vm1_attach_total_ms gapbs_crypto_vm2_attach_total_ms gapbs_crypto_vm1_attach_wait_ms gapbs_crypto_vm2_attach_wait_ms
  local gapbs_crypto_vm1_attach_decrypt_ms gapbs_crypto_vm2_attach_decrypt_ms gapbs_crypto_vm1_attach_pretouch_ms gapbs_crypto_vm2_attach_pretouch_ms
  local gapbs_crypto_avg_attach_total_ms gapbs_crypto_avg_attach_wait_ms gapbs_crypto_avg_attach_decrypt_ms gapbs_crypto_avg_attach_pretouch_ms

  local gapbs_secure_vm1_attach_total_ms gapbs_secure_vm2_attach_total_ms gapbs_secure_vm1_attach_wait_ms gapbs_secure_vm2_attach_wait_ms
  local gapbs_secure_vm1_attach_decrypt_ms gapbs_secure_vm2_attach_decrypt_ms gapbs_secure_vm1_attach_pretouch_ms gapbs_secure_vm2_attach_pretouch_ms
  local gapbs_secure_avg_attach_total_ms gapbs_secure_avg_attach_wait_ms gapbs_secure_avg_attach_decrypt_ms gapbs_secure_avg_attach_pretouch_ms

  if [[ "${ENABLE_SECURE}" == "1" ]]; then
    gapbs_crypto_vm1_attach_total_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm1_log}" total_ms)"
    gapbs_crypto_vm2_attach_total_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm2_log}" total_ms)"
    gapbs_crypto_vm1_attach_wait_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm1_log}" wait_ms)"
    gapbs_crypto_vm2_attach_wait_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm2_log}" wait_ms)"
    gapbs_crypto_vm1_attach_decrypt_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm1_log}" decrypt_ms)"
    gapbs_crypto_vm2_attach_decrypt_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm2_log}" decrypt_ms)"
    gapbs_crypto_vm1_attach_pretouch_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm1_log}" pretouch_ms)"
    gapbs_crypto_vm2_attach_pretouch_ms="$(cxl_attach_field_from_log "${gapbs_crypto_vm2_log}" pretouch_ms)"

    gapbs_crypto_avg_attach_total_ms="$(avg2_int "${gapbs_crypto_vm1_attach_total_ms}" "${gapbs_crypto_vm2_attach_total_ms}")"
    gapbs_crypto_avg_attach_wait_ms="$(avg2_int "${gapbs_crypto_vm1_attach_wait_ms}" "${gapbs_crypto_vm2_attach_wait_ms}")"
    gapbs_crypto_avg_attach_decrypt_ms="$(avg2_int "${gapbs_crypto_vm1_attach_decrypt_ms}" "${gapbs_crypto_vm2_attach_decrypt_ms}")"
    gapbs_crypto_avg_attach_pretouch_ms="$(avg2_int "${gapbs_crypto_vm1_attach_pretouch_ms}" "${gapbs_crypto_vm2_attach_pretouch_ms}")"

    gapbs_secure_vm1_attach_total_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm1_log}" total_ms)"
    gapbs_secure_vm2_attach_total_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm2_log}" total_ms)"
    gapbs_secure_vm1_attach_wait_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm1_log}" wait_ms)"
    gapbs_secure_vm2_attach_wait_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm2_log}" wait_ms)"
    gapbs_secure_vm1_attach_decrypt_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm1_log}" decrypt_ms)"
    gapbs_secure_vm2_attach_decrypt_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm2_log}" decrypt_ms)"
    gapbs_secure_vm1_attach_pretouch_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm1_log}" pretouch_ms)"
    gapbs_secure_vm2_attach_pretouch_ms="$(cxl_attach_field_from_log "${gapbs_secure_vm2_log}" pretouch_ms)"

    gapbs_secure_avg_attach_total_ms="$(avg2_int "${gapbs_secure_vm1_attach_total_ms}" "${gapbs_secure_vm2_attach_total_ms}")"
    gapbs_secure_avg_attach_wait_ms="$(avg2_int "${gapbs_secure_vm1_attach_wait_ms}" "${gapbs_secure_vm2_attach_wait_ms}")"
    gapbs_secure_avg_attach_decrypt_ms="$(avg2_int "${gapbs_secure_vm1_attach_decrypt_ms}" "${gapbs_secure_vm2_attach_decrypt_ms}")"
    gapbs_secure_avg_attach_pretouch_ms="$(avg2_int "${gapbs_secure_vm1_attach_pretouch_ms}" "${gapbs_secure_vm2_attach_pretouch_ms}")"

    gapbs_crypto_vm1_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_crypto_vm1_avg}" "${gapbs_crypto_vm1_attach_total_ms}" "${gapbs_crypto_vm1_trials_used}")"
    gapbs_crypto_vm2_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_crypto_vm2_avg}" "${gapbs_crypto_vm2_attach_total_ms}" "${gapbs_crypto_vm2_trials_used}")"
    gapbs_crypto_avg_e2e_time="$(avg2_float "${gapbs_crypto_vm1_e2e_avg}" "${gapbs_crypto_vm2_e2e_avg}")"
    gapbs_crypto_vm1_e2e_teps="$(teps_from_edges_time "${gapbs_crypto_vm1_edges}" "${gapbs_crypto_vm1_e2e_avg}")"
    gapbs_crypto_vm2_e2e_teps="$(teps_from_edges_time "${gapbs_crypto_vm2_edges}" "${gapbs_crypto_vm2_e2e_avg}")"
    gapbs_crypto_avg_e2e_teps="$(avg2_int "${gapbs_crypto_vm1_e2e_teps}" "${gapbs_crypto_vm2_e2e_teps}")"

    gapbs_secure_vm1_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_secure_vm1_avg}" "${gapbs_secure_vm1_attach_total_ms}" "${gapbs_secure_vm1_trials_used}")"
    gapbs_secure_vm2_e2e_avg="$(e2e_avg_time_s_from_avg_attach_ms "${gapbs_secure_vm2_avg}" "${gapbs_secure_vm2_attach_total_ms}" "${gapbs_secure_vm2_trials_used}")"
    gapbs_secure_avg_e2e_time="$(avg2_float "${gapbs_secure_vm1_e2e_avg}" "${gapbs_secure_vm2_e2e_avg}")"
    gapbs_secure_vm1_e2e_teps="$(teps_from_edges_time "${gapbs_secure_vm1_edges}" "${gapbs_secure_vm1_e2e_avg}")"
    gapbs_secure_vm2_e2e_teps="$(teps_from_edges_time "${gapbs_secure_vm2_edges}" "${gapbs_secure_vm2_e2e_avg}")"
    gapbs_secure_avg_e2e_teps="$(avg2_int "${gapbs_secure_vm1_e2e_teps}" "${gapbs_secure_vm2_e2e_teps}")"
  fi

  {
    echo "label,vm,kernel,scale,degree,trials,omp_threads,attach_total_ms,attach_wait_ms,attach_decrypt_ms,attach_pretouch_ms"
    echo "TDXGapbsMultihostRing,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_vm1_attach_total_ms},${gapbs_ring_vm1_attach_wait_ms},${gapbs_ring_vm1_attach_decrypt_ms},${gapbs_ring_vm1_attach_pretouch_ms}"
    echo "TDXGapbsMultihostRing,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_vm2_attach_total_ms},${gapbs_ring_vm2_attach_wait_ms},${gapbs_ring_vm2_attach_decrypt_ms},${gapbs_ring_vm2_attach_pretouch_ms}"
    echo "TDXGapbsMultihostRing,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_avg_attach_total_ms},${gapbs_ring_avg_attach_wait_ms},${gapbs_ring_avg_attach_decrypt_ms},${gapbs_ring_avg_attach_pretouch_ms}"
    if [[ "${ENABLE_SECURE}" == "1" ]]; then
      echo "TDXGapbsMultihostCrypto,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_vm1_attach_total_ms},${gapbs_crypto_vm1_attach_wait_ms},${gapbs_crypto_vm1_attach_decrypt_ms},${gapbs_crypto_vm1_attach_pretouch_ms}"
      echo "TDXGapbsMultihostCrypto,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_vm2_attach_total_ms},${gapbs_crypto_vm2_attach_wait_ms},${gapbs_crypto_vm2_attach_decrypt_ms},${gapbs_crypto_vm2_attach_pretouch_ms}"
      echo "TDXGapbsMultihostCrypto,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_avg_attach_total_ms},${gapbs_crypto_avg_attach_wait_ms},${gapbs_crypto_avg_attach_decrypt_ms},${gapbs_crypto_avg_attach_pretouch_ms}"
      echo "TDXGapbsMultihostSecure,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_vm1_attach_total_ms},${gapbs_secure_vm1_attach_wait_ms},${gapbs_secure_vm1_attach_decrypt_ms},${gapbs_secure_vm1_attach_pretouch_ms}"
      echo "TDXGapbsMultihostSecure,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_vm2_attach_total_ms},${gapbs_secure_vm2_attach_wait_ms},${gapbs_secure_vm2_attach_decrypt_ms},${gapbs_secure_vm2_attach_pretouch_ms}"
      echo "TDXGapbsMultihostSecure,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_avg_attach_total_ms},${gapbs_secure_avg_attach_wait_ms},${gapbs_secure_avg_attach_decrypt_ms},${gapbs_secure_avg_attach_pretouch_ms}"
    fi
  } > "${gapbs_overhead_csv}"

  {
    echo "label,vm,kernel,scale,degree,trials,omp_threads,edge_traversals,avg_time_s,throughput_teps"
    echo "TDXGapbsNative,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_native_vm1_edges},${gapbs_native_vm1_e2e_avg},${gapbs_native_vm1_e2e_teps}"
    echo "TDXGapbsNative,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_native_vm2_edges},${gapbs_native_vm2_e2e_avg},${gapbs_native_vm2_e2e_teps}"
    echo "TDXGapbsNative,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_native_avg_edges},${gapbs_native_avg_e2e_time},${gapbs_native_avg_e2e_teps}"
    echo "TDXGapbsMultihostRing,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_vm1_edges},${gapbs_ring_vm1_e2e_avg},${gapbs_ring_vm1_e2e_teps}"
    echo "TDXGapbsMultihostRing,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_vm2_edges},${gapbs_ring_vm2_e2e_avg},${gapbs_ring_vm2_e2e_teps}"
    echo "TDXGapbsMultihostRing,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_ring_avg_edges},${gapbs_ring_avg_e2e_time},${gapbs_ring_avg_e2e_teps}"
    if [[ "${ENABLE_SECURE}" == "1" ]]; then
      echo "TDXGapbsMultihostCrypto,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_vm1_edges},${gapbs_crypto_vm1_e2e_avg},${gapbs_crypto_vm1_e2e_teps}"
      echo "TDXGapbsMultihostCrypto,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_vm2_edges},${gapbs_crypto_vm2_e2e_avg},${gapbs_crypto_vm2_e2e_teps}"
      echo "TDXGapbsMultihostCrypto,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_crypto_avg_edges},${gapbs_crypto_avg_e2e_time},${gapbs_crypto_avg_e2e_teps}"
      echo "TDXGapbsMultihostSecure,vm1,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_vm1_edges},${gapbs_secure_vm1_e2e_avg},${gapbs_secure_vm1_e2e_teps}"
      echo "TDXGapbsMultihostSecure,vm2,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_vm2_edges},${gapbs_secure_vm2_e2e_avg},${gapbs_secure_vm2_e2e_teps}"
      echo "TDXGapbsMultihostSecure,avg,${kernel},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${gapbs_secure_avg_edges},${gapbs_secure_avg_e2e_time},${gapbs_secure_avg_e2e_teps}"
    fi
  } > "${gapbs_compare_csv}"

  echo "[*] GAPBS kernel=${kernel}: saved ${gapbs_compare_csv}"
  echo "[*] GAPBS kernel=${kernel}: saved ${gapbs_overhead_csv}"
}

gapbs_kernels=( )
if [[ -n "${GAPBS_KERNEL_LIST}" ]]; then
  IFS=',' read -r -a gapbs_kernels <<< "${GAPBS_KERNEL_LIST}"
else
  gapbs_kernels=("${GAPBS_KERNEL}")
fi

for k in "${gapbs_kernels[@]}"; do
  run_gapbs_kernel "${k}"
done

echo "[+] Done."
echo "    ${native_log}"
echo "    ${sodium_log}"
echo "    ${ring_log}"
echo "    ${ring_csv}"
echo "    ${ring_secure_log}"
echo "    ${ring_secure_csv}"
echo "    ${compare_csv}"
echo "    GAPBS CSVs: ${RESULTS_DIR}/tdx_gapbs_compare_*_${ts}.csv"
echo "    GAPBS overhead CSVs: ${RESULTS_DIR}/tdx_gapbs_overhead_*_${ts}.csv"
