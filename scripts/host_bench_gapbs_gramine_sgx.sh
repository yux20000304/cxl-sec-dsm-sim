#!/usr/bin/env bash
set -euo pipefail

# GAPBS benchmarks under Gramine SGX (no VMs).
#
# Compares (mirrors the GAPBS multihost matrix):
# 1) Native:                    GAPBS native binary (no Gramine, no shared memory)
# 2) MultihostRing:             ring binary over shared memory (no Gramine)
# 3) GramineSGXMultihostRing:   ring binary over shared memory (under gramine-sgx)
# 4) GramineSGXMultihostCrypto: ring-secure + libsodium crypto (per-host key + common key; no mgr)
# 5) GramineSGXMultihostSecure: ring-secure + cxl_sec_mgr ACL/key table (permission-managed crypto)
#
# This script is meant for SGX-capable machines where SGX works on the host OS
# (i.e., `/dev/sgx_enclave` exists and Gramine SGX tooling is installed).
#
# Usage:
#   sudo -E bash scripts/host_bench_gapbs_gramine_sgx.sh
#
# Tunables (env):
#   GAPBS_KERNEL   : bfs|cc|pr|... (default: bfs)
#   SCALE          : -g scale for Kronecker graph (default: 18)
#   DEGREE         : -k degree for synthetic graph (default: 16)
#   TRIALS         : -n trials (default: 3)
#   OMP_THREADS    : OMP_NUM_THREADS (default: 4)
#   RING_PATH      : shared-memory backing file (default: /dev/shm/gapbs_cxl_shared.raw)
#   RING_MAP_SIZE  : mmap size in bytes (default: 134217728 = 128MB)
#   SEC_MGR_PORT   : TCP port for cxl_sec_mgr (default: 19002)
#
# Gramine/SGX tunables:
#   SGX_SIZE       : manifest sgx.enclave_size (default: 1024M)
#   SGX_THREADS    : manifest sgx.max_threads (default: 64)
#   LOG_LEVEL      : Gramine log level (default: warning)
#   SGX_TOKEN_MODE : auto|require|skip (default: auto)
#   INSTALL_GRAMINE: 1 to auto-install Gramine via apt when missing (default: 1)
#   INSTALL_LIBSODIUM: 1 to auto-install libsodium-dev via apt when missing (default: 1)
#   INSTALL_BUILD_ESSENTIAL: 1 to auto-install build-essential/pkg-config via apt when missing (default: 1)
#   GRAMINE_CODENAME: override distro codename for Gramine repo (default: lsb_release/os-release)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
SCALE="${SCALE:-18}"
DEGREE="${DEGREE:-16}"
TRIALS="${TRIALS:-3}"
OMP_THREADS="${OMP_THREADS:-4}"

RING_PATH="${RING_PATH:-/dev/shm/gapbs_cxl_shared.raw}"
RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}"
SEC_MGR_PORT="${SEC_MGR_PORT:-19002}"

SGX_SIZE="${SGX_SIZE:-1024M}"
SGX_THREADS="${SGX_THREADS:-64}"
LOG_LEVEL="${LOG_LEVEL:-warning}"
SGX_TOKEN_MODE="${SGX_TOKEN_MODE:-auto}"

INSTALL_GRAMINE="${INSTALL_GRAMINE:-1}"
INSTALL_LIBSODIUM="${INSTALL_LIBSODIUM:-1}"
INSTALL_BUILD_ESSENTIAL="${INSTALL_BUILD_ESSENTIAL:-1}"
GRAMINE_CODENAME="${GRAMINE_CODENAME:-}"

sec_mgr_pid=""
cleanup() {
  local rc=$?
  if [[ -n "${sec_mgr_pid}" ]] && kill -0 "${sec_mgr_pid}" 2>/dev/null; then
    kill "${sec_mgr_pid}" >/dev/null 2>&1 || true
  fi
  return "${rc}"
}
trap cleanup EXIT

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

detect_codename() {
  local c=""
  if [[ -n "${GRAMINE_CODENAME}" ]]; then
    echo "${GRAMINE_CODENAME}"
    return 0
  fi
  if command -v lsb_release >/dev/null 2>&1; then
    c="$(lsb_release -sc 2>/dev/null || true)"
  fi
  if [[ -z "${c}" && -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    c="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  fi
  echo "${c}"
}

install_gramine_apt() {
  if command -v gramine-sgx >/dev/null 2>&1 && command -v gramine-manifest >/dev/null 2>&1; then
    return 0
  fi
  if [[ "${INSTALL_GRAMINE}" != "1" ]]; then
    echo "[!] Missing command: gramine-sgx/gramine-manifest (set INSTALL_GRAMINE=1 to auto-install)" >&2
    return 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] Gramine not found and apt-get is unavailable; install Gramine manually." >&2
    return 1
  fi

  local arch=""
  arch="$(dpkg --print-architecture 2>/dev/null || true)"
  if [[ "${arch}" != "amd64" ]]; then
    echo "[!] Unsupported arch for Gramine SGX packages: ${arch} (expected amd64)." >&2
    return 1
  fi

  local codename=""
  codename="$(detect_codename)"
  if [[ -z "${codename}" ]]; then
    echo "[!] Failed to detect distro codename (set GRAMINE_CODENAME=<jammy|noble>)." >&2
    return 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    apt_retry_lock "apt-get update" apt-get update
    apt_retry_lock "apt-get install curl" apt-get install -y curl
  fi

  mkdir -p /etc/apt/keyrings
  local keyring="/etc/apt/keyrings/gramine-keyring-${codename}.gpg"
  local list="/etc/apt/sources.list.d/gramine.list"
  if [[ ! -f "${keyring}" ]]; then
    echo "[*] Fetching Gramine keyring for ${codename} ..."
    curl -fsSLo "${keyring}" "https://packages.gramineproject.io/gramine-keyring-${codename}.gpg"
    chmod 644 "${keyring}" || true
  fi
  echo "deb [arch=amd64 signed-by=${keyring}] https://packages.gramineproject.io/ ${codename} main" > "${list}"

  apt_retry_lock "apt-get update (gramine repo)" apt-get update
  apt_retry_lock "apt-get install gramine" apt-get install -y gramine
}

install_deps_apt() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi

  pkgs=()

  if [[ "${INSTALL_BUILD_ESSENTIAL}" == "1" ]]; then
    command -v make >/dev/null 2>&1 || pkgs+=(build-essential)
    command -v g++ >/dev/null 2>&1 || pkgs+=(build-essential)
    command -v pkg-config >/dev/null 2>&1 || pkgs+=(pkg-config)
  fi

  if [[ "${INSTALL_LIBSODIUM}" == "1" ]]; then
    if ! pkg-config --exists libsodium >/dev/null 2>&1; then
      pkgs+=(libsodium-dev)
    fi
  fi

  if [[ "${#pkgs[@]}" -gt 0 ]]; then
    apt_retry_lock "apt-get update" apt-get update
    apt_retry_lock "apt-get install deps" apt-get install -y "${pkgs[@]}"
  fi
}

sgx_dev=""
if [[ -c /dev/sgx_enclave ]]; then
  sgx_dev="/dev/sgx_enclave"
elif [[ -c /dev/sgx/enclave ]]; then
  sgx_dev="/dev/sgx/enclave"
elif [[ -c /dev/isgx ]]; then
  sgx_dev="/dev/isgx"
fi
if [[ -z "${sgx_dev}" ]]; then
  echo "[!] SGX device node not found (/dev/sgx_enclave or /dev/sgx/enclave or /dev/isgx)." >&2
  echo "    Ensure SGX is enabled in BIOS and the SGX driver is loaded." >&2
  exit 1
fi
if ! grep -q -m1 -w aes /proc/cpuinfo 2>/dev/null; then
  echo "[!] Host CPU doesn't expose AES-NI ('aes' flag). Gramine requires it." >&2
  exit 1
fi

install_deps_apt
install_gramine_apt

for c in gramine-sgx gramine-manifest gramine-sgx-sign; do
  if ! command -v "${c}" >/dev/null 2>&1; then
    echo "[!] Missing command: ${c}" >&2
    exit 1
  fi
done
if [[ "${SGX_TOKEN_MODE}" != "skip" ]] && ! command -v gramine-sgx-get-token >/dev/null 2>&1; then
  echo "[!] Missing command: gramine-sgx-get-token (set SGX_TOKEN_MODE=skip to continue without token)" >&2
  exit 1
fi

echo "[*] Preparing ring backing file: ${RING_PATH} (${RING_MAP_SIZE} bytes)"
mkdir -p "$(dirname "${RING_PATH}")"
truncate -s "${RING_MAP_SIZE}" "${RING_PATH}"
chmod 666 "${RING_PATH}" || true

echo "[*] Building GAPBS (native + ring + ring-secure) ..."
make -C "${ROOT}/gapbs" -j"$(nproc)" all ring ring-secure

echo "[*] Building cxl_sec_mgr (/tmp/cxl_sec_mgr) ..."
make -C "${ROOT}/cxl_sec_mgr" clean
make -C "${ROOT}/cxl_sec_mgr" -j"$(nproc)" BIN=/tmp/cxl_sec_mgr

echo "[*] Building Gramine manifests + SGX artifacts for GAPBS ..."
make -C "${ROOT}/gramine" links \
  gapbs-native.manifest gapbs-ring.manifest gapbs-ring-secure.manifest \
  GAPBS_KERNEL="${GAPBS_KERNEL}" \
  CXL_RING_PATH="${RING_PATH}" CXL_RING_MAP_SIZE="${RING_MAP_SIZE}" \
  USE_RUNTIME_GLIBC=1 SGX_SIZE="${SGX_SIZE}" SGX_THREADS="${SGX_THREADS}" LOG_LEVEL="${LOG_LEVEL}"

make -C "${ROOT}/gramine" sgx-sign-gapbs SGX_SIZE="${SGX_SIZE}" SGX_THREADS="${SGX_THREADS}" LOG_LEVEL="${LOG_LEVEL}"

set +e
token_out="$(make -C "${ROOT}/gramine" sgx-token-gapbs 2>&1)"
token_rc=$?
set -e
if [[ "${token_rc}" -ne 0 ]]; then
  if [[ "${SGX_TOKEN_MODE}" == "require" ]]; then
    echo "[!] Failed to fetch SGX launch token (SGX_TOKEN_MODE=require)." >&2
    printf '%s\n' "${token_out}" >&2
    exit 1
  fi
  if [[ "${SGX_TOKEN_MODE}" != "skip" ]]; then
    echo "[!] Failed to fetch SGX launch token; continuing (SGX_TOKEN_MODE=${SGX_TOKEN_MODE})." >&2
    printf '%s\n' "${token_out}" >&2
  fi
fi

ts="$(date +%Y%m%d_%H%M%S)"

native_h1_log="${RESULTS_DIR}/gapbs_sgx_native_h1_${GAPBS_KERNEL}_${ts}.log"
native_h2_log="${RESULTS_DIR}/gapbs_sgx_native_h2_${GAPBS_KERNEL}_${ts}.log"

plain_ring_pub_log="${RESULTS_DIR}/gapbs_sgx_multihost_ring_publish_${GAPBS_KERNEL}_${ts}.log"
plain_ring_h1_log="${RESULTS_DIR}/gapbs_sgx_multihost_ring_h1_${GAPBS_KERNEL}_${ts}.log"
plain_ring_h2_log="${RESULTS_DIR}/gapbs_sgx_multihost_ring_h2_${GAPBS_KERNEL}_${ts}.log"

sgx_ring_pub_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_ring_publish_${GAPBS_KERNEL}_${ts}.log"
sgx_ring_h1_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_ring_h1_${GAPBS_KERNEL}_${ts}.log"
sgx_ring_h2_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_ring_h2_${GAPBS_KERNEL}_${ts}.log"

sgx_crypto_pub_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_crypto_publish_${GAPBS_KERNEL}_${ts}.log"
sgx_crypto_h1_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_crypto_h1_${GAPBS_KERNEL}_${ts}.log"
sgx_crypto_h2_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_crypto_h2_${GAPBS_KERNEL}_${ts}.log"

sgx_secure_mgr_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_secure_mgr_${GAPBS_KERNEL}_${ts}.log"
sgx_secure_pub_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_secure_publish_${GAPBS_KERNEL}_${ts}.log"
sgx_secure_h1_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_secure_h1_${GAPBS_KERNEL}_${ts}.log"
sgx_secure_h2_log="${RESULTS_DIR}/gapbs_gramine_sgx_multihost_secure_h2_${GAPBS_KERNEL}_${ts}.log"

compare_csv="${RESULTS_DIR}/gapbs_compare_sgx_${GAPBS_KERNEL}_${ts}.csv"

echo "[*] Benchmark 1/5: Native (no Gramine) host1"
cd "${ROOT}/gapbs"
OMP_NUM_THREADS="${OMP_THREADS}" "./${GAPBS_KERNEL}" -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" | tee "${native_h1_log}"

echo "[*] Benchmark 1/5: Native (no Gramine) host2"
OMP_NUM_THREADS="${OMP_THREADS}" "./${GAPBS_KERNEL}" -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" | tee "${native_h2_log}"

echo "[*] Benchmark 2/5: MultihostRing (no Gramine) publish"
env OMP_NUM_THREADS="${OMP_THREADS}" \
  GAPBS_CXL_PATH="${RING_PATH}" GAPBS_CXL_MAP_SIZE="${RING_MAP_SIZE}" \
  GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 \
  "./${GAPBS_KERNEL}-ring" -g "${SCALE}" -k "${DEGREE}" -n 1 | tee "${plain_ring_pub_log}"

echo "[*] Benchmark 2/5: MultihostRing (no Gramine) attach+run (concurrent)"
(
  cd "${ROOT}/gapbs"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_PATH="${RING_PATH}" GAPBS_CXL_MAP_SIZE="${RING_MAP_SIZE}" \
    GAPBS_CXL_MODE=attach \
    "./${GAPBS_KERNEL}-ring" -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${plain_ring_h1_log}" 2>&1
) &
pid_plain_h1=$!

(
  cd "${ROOT}/gapbs"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_PATH="${RING_PATH}" GAPBS_CXL_MAP_SIZE="${RING_MAP_SIZE}" \
    GAPBS_CXL_MODE=attach \
    "./${GAPBS_KERNEL}-ring" -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${plain_ring_h2_log}" 2>&1
) &
pid_plain_h2=$!

wait "${pid_plain_h1}"
wait "${pid_plain_h2}"

echo "[*] Benchmark 3/5: GramineSGXMultihostRing publish"
(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 \
    gramine-sgx ./gapbs-ring -g "${SCALE}" -k "${DEGREE}" -n 1
) | tee "${sgx_ring_pub_log}"

echo "[*] Benchmark 3/5: GramineSGXMultihostRing attach+run (concurrent)"
(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=attach \
    gramine-sgx ./gapbs-ring -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${sgx_ring_h1_log}" 2>&1
) &
pid_sgx_ring_h1=$!

(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=attach \
    gramine-sgx ./gapbs-ring -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${sgx_ring_h2_log}" 2>&1
) &
pid_sgx_ring_h2=$!

wait "${pid_sgx_ring_h1}"
wait "${pid_sgx_ring_h2}"

crypto_key_h1_hex="$(openssl rand -hex 32)"
crypto_key_h2_hex="$(openssl rand -hex 32)"
crypto_key_common_hex="$(openssl rand -hex 32)"

echo "[*] Benchmark 4/5: GramineSGXMultihostCrypto publish (libsodium; per-host key + common key; no mgr)"
(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 \
    CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX="${crypto_key_h1_hex}" CXL_SEC_COMMON_KEY_HEX="${crypto_key_common_hex}" \
    gramine-sgx ./gapbs-ring-secure -g "${SCALE}" -k "${DEGREE}" -n 1
) | tee "${sgx_crypto_pub_log}"

echo "[*] Benchmark 4/5: GramineSGXMultihostCrypto attach+run (concurrent)"
(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=attach \
    CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=1 CXL_SEC_KEY_HEX="${crypto_key_h1_hex}" CXL_SEC_COMMON_KEY_HEX="${crypto_key_common_hex}" \
    gramine-sgx ./gapbs-ring-secure -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${sgx_crypto_h1_log}" 2>&1
) &
pid_sgx_crypto_h1=$!

(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=attach \
    CXL_SEC_ENABLE=1 CXL_SEC_NODE_ID=2 CXL_SEC_KEY_HEX="${crypto_key_h2_hex}" CXL_SEC_COMMON_KEY_HEX="${crypto_key_common_hex}" \
    gramine-sgx ./gapbs-ring-secure -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${sgx_crypto_h2_log}" 2>&1
) &
pid_sgx_crypto_h2=$!

wait "${pid_sgx_crypto_h1}"
wait "${pid_sgx_crypto_h2}"

echo "[*] Benchmark 5/5: GramineSGXMultihostSecure publish (ACL/key table via cxl_sec_mgr)"
dd if=/dev/zero of="${RING_PATH}" bs=4096 count=1 conv=notrunc >/dev/null 2>&1 || true

nohup /tmp/cxl_sec_mgr --ring "${RING_PATH}" --listen "127.0.0.1:${SEC_MGR_PORT}" --map-size "${RING_MAP_SIZE}" \
  >"${sgx_secure_mgr_log}" 2>&1 &
sec_mgr_pid="$!"

(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=publish GAPBS_CXL_PUBLISH_ONLY=1 \
    CXL_SEC_ENABLE=1 CXL_SEC_MGR="127.0.0.1:${SEC_MGR_PORT}" CXL_SEC_NODE_ID=1 \
    gramine-sgx ./gapbs-ring-secure -g "${SCALE}" -k "${DEGREE}" -n 1
) | tee "${sgx_secure_pub_log}"

echo "[*] Benchmark 5/5: GramineSGXMultihostSecure attach+run (concurrent)"
(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=attach \
    CXL_SEC_ENABLE=1 CXL_SEC_MGR="127.0.0.1:${SEC_MGR_PORT}" CXL_SEC_NODE_ID=1 \
    gramine-sgx ./gapbs-ring-secure -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${sgx_secure_h1_log}" 2>&1
) &
pid_sgx_secure_h1=$!

(
  cd "${ROOT}/gramine"
  env OMP_NUM_THREADS="${OMP_THREADS}" \
    GAPBS_CXL_MODE=attach \
    CXL_SEC_ENABLE=1 CXL_SEC_MGR="127.0.0.1:${SEC_MGR_PORT}" CXL_SEC_NODE_ID=2 \
    gramine-sgx ./gapbs-ring-secure -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" \
    >"${sgx_secure_h2_log}" 2>&1
) &
pid_sgx_secure_h2=$!

wait "${pid_sgx_secure_h1}"
wait "${pid_sgx_secure_h2}"

kill "${sec_mgr_pid}" >/dev/null 2>&1 || true
sec_mgr_pid=""

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

native_h1_avg="$(avg_from_log "${native_h1_log}")"
native_h2_avg="$(avg_from_log "${native_h2_log}")"
plain_ring_h1_avg="$(avg_from_log "${plain_ring_h1_log}")"
plain_ring_h2_avg="$(avg_from_log "${plain_ring_h2_log}")"
sgx_ring_h1_avg="$(avg_from_log "${sgx_ring_h1_log}")"
sgx_ring_h2_avg="$(avg_from_log "${sgx_ring_h2_log}")"
sgx_crypto_h1_avg="$(avg_from_log "${sgx_crypto_h1_log}")"
sgx_crypto_h2_avg="$(avg_from_log "${sgx_crypto_h2_log}")"
sgx_secure_h1_avg="$(avg_from_log "${sgx_secure_h1_log}")"
sgx_secure_h2_avg="$(avg_from_log "${sgx_secure_h2_log}")"

native_h1_edges="$(edges_for_teps_from_log "${native_h1_log}")"
native_h2_edges="$(edges_for_teps_from_log "${native_h2_log}")"
plain_ring_h1_edges="$(edges_for_teps_from_log "${plain_ring_h1_log}")"
plain_ring_h2_edges="$(edges_for_teps_from_log "${plain_ring_h2_log}")"
sgx_ring_h1_edges="$(edges_for_teps_from_log "${sgx_ring_h1_log}")"
sgx_ring_h2_edges="$(edges_for_teps_from_log "${sgx_ring_h2_log}")"
sgx_crypto_h1_edges="$(edges_for_teps_from_log "${sgx_crypto_h1_log}")"
sgx_crypto_h2_edges="$(edges_for_teps_from_log "${sgx_crypto_h2_log}")"
sgx_secure_h1_edges="$(edges_for_teps_from_log "${sgx_secure_h1_log}")"
sgx_secure_h2_edges="$(edges_for_teps_from_log "${sgx_secure_h2_log}")"

native_h1_teps="$(teps_from_edges_time "${native_h1_edges}" "${native_h1_avg}")"
native_h2_teps="$(teps_from_edges_time "${native_h2_edges}" "${native_h2_avg}")"
plain_ring_h1_teps="$(teps_from_edges_time "${plain_ring_h1_edges}" "${plain_ring_h1_avg}")"
plain_ring_h2_teps="$(teps_from_edges_time "${plain_ring_h2_edges}" "${plain_ring_h2_avg}")"
sgx_ring_h1_teps="$(teps_from_edges_time "${sgx_ring_h1_edges}" "${sgx_ring_h1_avg}")"
sgx_ring_h2_teps="$(teps_from_edges_time "${sgx_ring_h2_edges}" "${sgx_ring_h2_avg}")"
sgx_crypto_h1_teps="$(teps_from_edges_time "${sgx_crypto_h1_edges}" "${sgx_crypto_h1_avg}")"
sgx_crypto_h2_teps="$(teps_from_edges_time "${sgx_crypto_h2_edges}" "${sgx_crypto_h2_avg}")"
sgx_secure_h1_teps="$(teps_from_edges_time "${sgx_secure_h1_edges}" "${sgx_secure_h1_avg}")"
sgx_secure_h2_teps="$(teps_from_edges_time "${sgx_secure_h2_edges}" "${sgx_secure_h2_avg}")"

{
  echo "label,vm,kernel,scale,degree,trials,omp_threads,edge_traversals,avg_time_s,throughput_teps"
  echo "Native,host1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${native_h1_edges},${native_h1_avg},${native_h1_teps}"
  echo "Native,host2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${native_h2_edges},${native_h2_avg},${native_h2_teps}"
  echo "MultihostRing,host1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${plain_ring_h1_edges},${plain_ring_h1_avg},${plain_ring_h1_teps}"
  echo "MultihostRing,host2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${plain_ring_h2_edges},${plain_ring_h2_avg},${plain_ring_h2_teps}"
  echo "GramineSGXMultihostRing,host1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_ring_h1_edges},${sgx_ring_h1_avg},${sgx_ring_h1_teps}"
  echo "GramineSGXMultihostRing,host2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_ring_h2_edges},${sgx_ring_h2_avg},${sgx_ring_h2_teps}"
  echo "GramineSGXMultihostCrypto,host1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_crypto_h1_edges},${sgx_crypto_h1_avg},${sgx_crypto_h1_teps}"
  echo "GramineSGXMultihostCrypto,host2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_crypto_h2_edges},${sgx_crypto_h2_avg},${sgx_crypto_h2_teps}"
  echo "GramineSGXMultihostSecure,host1,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_secure_h1_edges},${sgx_secure_h1_avg},${sgx_secure_h1_teps}"
  echo "GramineSGXMultihostSecure,host2,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${sgx_secure_h2_edges},${sgx_secure_h2_avg},${sgx_secure_h2_teps}"
} > "${compare_csv}"

echo "[+] Done."
echo "[+] Throughput (TEPS; higher is better):"
echo "    Native(host1/host2)=${native_h1_teps}/${native_h2_teps}"
echo "    MultihostRing(host1/host2)=${plain_ring_h1_teps}/${plain_ring_h2_teps}"
echo "    GramineSGXMultihostRing(host1/host2)=${sgx_ring_h1_teps}/${sgx_ring_h2_teps}"
echo "    GramineSGXMultihostCrypto(host1/host2)=${sgx_crypto_h1_teps}/${sgx_crypto_h2_teps}"
echo "    GramineSGXMultihostSecure(host1/host2)=${sgx_secure_h1_teps}/${sgx_secure_h2_teps}"
echo "    ${compare_csv}"

