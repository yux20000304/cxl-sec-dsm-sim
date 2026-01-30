#!/usr/bin/env bash
set -euo pipefail

# Run YCSB against a Redis endpoint and save results under results/.
#
# This script ensures Java and a local YCSB copy are available (uses /tmp by default),
# then runs a load + run cycle for one or more workloads.
#
# Examples (inside VM2):
#   bash scripts/run_ycsb.sh
#   bash scripts/run_ycsb.sh --host 127.0.0.1 --port 6380 --workloads workloada,workloadb \
#       --recordcount 100000 --operationcount 100000 --threads 8
#
# Notes:
# - Uses the Redis binding (Jedis). Configure auth/cluster via flags below.
# - Results are timestamped and written to results/.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${ROOT}/results"
mkdir -p "${OUTDIR}"

HOST="127.0.0.1"
PORT=6379
DB="redis"
WORKLOADS="workloada,workloadb"   # comma-separated; files in YCSB workloads/
RECORDS=100000
OPS=100000
THREADS=4
TARGET=""         # ops/sec (optional)
PASSWORD=""       # optional redis password
CLUSTER="false"    # true/false
YCSB_DIR=""        # optional, pre-installed YCSB dir
REDIS_TIMEOUT_MS="" # optional redis socket timeout (ms)
YCSB_PROXY_RETRIES="${YCSB_PROXY_RETRIES:-3}"
YCSB_PROXY_PING_TRIES="${YCSB_PROXY_PING_TRIES:-50}"
YCSB_PROXY_PING_DELAY_MS="${YCSB_PROXY_PING_DELAY_MS:-200}"
YCSB_PROXY_PING_TIMEOUT_MS="${YCSB_PROXY_PING_TIMEOUT_MS:-2000}"
RING_RESP_PROXY_LOG=""

usage() {
  cat <<EOF
Usage: $0 [--host 127.0.0.1] [--port 6379] [--workloads workloada,workloadb] \
          [--recordcount 100000] [--operationcount 100000] [--threads 4] \
          [--target OPS] [--password PWD] [--cluster true|false] [--ycsb-dir PATH] \
          [--redis-timeout-ms MS] [--db redis|rediskv|ringkv]

Runs YCSB (redis binding) against the given Redis host:port.
Downloads YCSB locally if needed (to /tmp/ycsb-0.17.0).
Outputs logs to results/ycsb_<workload>_{load|run}_HOST_PORT_TIMESTAMP.log
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --db) DB="$2"; shift 2 ;;
    --workloads) WORKLOADS="$2"; shift 2 ;;
    --recordcount) RECORDS="$2"; shift 2 ;;
    --operationcount) OPS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --cluster) CLUSTER="$2"; shift 2 ;;
    --ycsb-dir) YCSB_DIR="$2"; shift 2 ;;
    --redis-timeout-ms) REDIS_TIMEOUT_MS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

ensure_java() {
  if command -v java >/dev/null 2>&1; then
    return 0
  fi
  echo "[*] Installing Java (openjdk-headless) ..."
  if command -v sudo >/dev/null 2>&1; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y
    if ! sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-11-jre-headless >/dev/null 2>&1; then
      sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jre-headless
    fi
  else
    env DEBIAN_FRONTEND=noninteractive apt-get update -y
    env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-11-jre-headless || \
      env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jre-headless
  fi
}

ensure_javac() {
  if command -v javac >/dev/null 2>&1; then
    return 0
  fi
  echo "[*] Installing JDK (openjdk-headless) ..."
  if command -v sudo >/dev/null 2>&1; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y
    if ! sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-11-jdk-headless >/dev/null 2>&1; then
      sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk-headless
    fi
  else
    env DEBIAN_FRONTEND=noninteractive apt-get update -y
    env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-11-jdk-headless || \
      env DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk-headless
  fi
}

ensure_ycsb() {
  if [[ -n "${YCSB_DIR}" ]]; then
    return 0
  fi
  local ver="0.17.0"
  local tgz="/tmp/ycsb-${ver}.tar.gz"
  local dir="/tmp/ycsb-${ver}"
  if [[ -d "${dir}" ]]; then
    YCSB_DIR="${dir}"
    return 0
  fi
  echo "[*] Downloading YCSB ${ver} ..."
  local url="https://github.com/brianfrankcooper/YCSB/releases/download/${ver}/ycsb-${ver}.tar.gz"
  if ! command -v curl >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y curl
  fi
  curl -LfsS -o "${tgz}" "${url}"
  mkdir -p "${dir}"
  tar -C /tmp -xzf "${tgz}"
  YCSB_DIR="${dir}"
}

ensure_kv_bindings() {
  local src_dir="${ROOT}/ycsb_bindings/src"
  if [[ ! -d "${src_dir}" ]]; then
    echo "[!] Missing KV binding sources at ${src_dir}" >&2
    exit 1
  fi
  ensure_javac

  local build_dir="/tmp/ycsb_kv_build"
  local jar_path="/tmp/ycsb_kv_binding.jar"
  local core_jar="${YCSB_DIR}/lib/core-0.17.0.jar"
  local redis_lib="${YCSB_DIR}/redis-binding/lib"
  local cp="${core_jar}:${redis_lib}/jedis-2.9.0.jar:${redis_lib}/commons-pool2-2.4.2.jar"

  if [[ ! -f "${jar_path}" ]] || [[ "${src_dir}" -nt "${jar_path}" ]]; then
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"
    javac -cp "${cp}" -d "${build_dir}" \
      "${src_dir}/site/ycsb/db/KVRecordCodec.java" \
      "${src_dir}/site/ycsb/db/RedisKVClient.java" \
      "${src_dir}/site/ycsb/db/RingKVClient.java"
    jar cf "${jar_path}" -C "${build_dir}" .
  fi

  mkdir -p "${YCSB_DIR}/rediskv-binding/lib" "${YCSB_DIR}/ringkv-binding/lib"
  cp -f "${jar_path}" "${YCSB_DIR}/rediskv-binding/lib/"
  cp -f "${jar_path}" "${YCSB_DIR}/ringkv-binding/lib/"
  cp -f "${redis_lib}"/*.jar "${YCSB_DIR}/rediskv-binding/lib/" || true

  local bindings_file="${YCSB_DIR}/bin/bindings.properties"
  if [[ -f "${bindings_file}" ]]; then
    if ! grep -q "^rediskv:" "${bindings_file}"; then
      echo "rediskv:site.ycsb.db.RedisKVClient" >> "${bindings_file}"
    fi
    if ! grep -q "^ringkv:" "${bindings_file}"; then
      echo "ringkv:site.ycsb.db.RingKVClient" >> "${bindings_file}"
    fi
  fi
}

ensure_ringkv_native() {
  local src="${ROOT}/ring_client/ring_kv_jni.c"
  local out="/tmp/libringkvjni.so"
  if [[ ! -f "${src}" ]]; then
    echo "[!] Missing ring kv JNI source: ${src}" >&2
    exit 1
  fi
  ensure_javac
  if [[ ! -f "${out}" ]] || [[ "${src}" -nt "${out}" ]]; then
    local javac_bin
    javac_bin="$(command -v javac)"
    local java_home
    java_home="$(dirname "$(dirname "$(readlink -f "${javac_bin}")")")"
    local jni_inc="${java_home}/include"
    local jni_inc_os="${jni_inc}/linux"
    gcc -O2 -fPIC -shared -I"${jni_inc}" -I"${jni_inc_os}" -I"${ROOT}" \
      -o "${out}" "${src}" -lsodium -lpthread
  fi
  export RING_KV_NATIVE_LIB="${out}"
}

find_ycsb_launcher() {
  if [[ -x "${YCSB_DIR}/bin/ycsb.sh" ]]; then
    echo "${YCSB_DIR}/bin/ycsb.sh"
    return 0
  fi
  if [[ -x "${YCSB_DIR}/bin/ycsb" ]]; then
    echo "${YCSB_DIR}/bin/ycsb"
    return 0
  fi
  return 1
}

run_ycsb() {
  local action="$1"   # load | run
  local wl_file="$2"  # workloads/workloada, etc
  local ts="$(date +%Y%m%d_%H%M%S)"
  local base="ycsb_${wl_file##*/}_${action}_${HOST}_${PORT}_${ts}.log"
  local outfile="${OUTDIR}/${base}"

  local extra_p=()
  [[ -n "${PASSWORD}" ]] && extra_p+=( -p "redis.password=${PASSWORD}" )
  [[ -n "${CLUSTER}" ]] && extra_p+=( -p "redis.cluster=${CLUSTER}" )
  [[ -n "${REDIS_TIMEOUT_MS}" ]] && extra_p+=( -p "redis.timeout.ms=${REDIS_TIMEOUT_MS}" )

  local tgt_args=()
  [[ -n "${TARGET}" ]] && tgt_args+=( -target "${TARGET}" )

  local launcher
  launcher="$(find_ycsb_launcher)" || { echo "[!] YCSB launcher not found under: ${YCSB_DIR}/bin" >&2; exit 1; }

  echo "[*] YCSB ${action} ${wl_file} -> ${HOST}:${PORT} (db=${DB} threads=${THREADS}, records=${RECORDS}, ops=${OPS})"
  "${launcher}" "${action}" "${DB}" -s -P "${YCSB_DIR}/${wl_file}" \
    -p "recordcount=${RECORDS}" -p "operationcount=${OPS}" \
    -p "redis.host=${HOST}" -p "redis.port=${PORT}" \
    "${extra_p[@]}" -threads "${THREADS}" "${tgt_args[@]}" 2>&1 | tee "${outfile}"
  echo "[+] Saved: ${outfile}"
}

resp_ping() {
  local host="$1"
  local port="$2"
  local timeout_ms="$3"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$host" "$port" "$timeout_ms" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3]) / 1000.0

try:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"*1\r\n$4\r\nPING\r\n")
    data = s.recv(64)
    s.close()
    sys.exit(0 if b"+PONG" in data else 1)
except Exception:
    sys.exit(1)
PY
    return $?
  fi
  local timeout_s
  timeout_s="$(awk "BEGIN{print ${timeout_ms}/1000}")"
  if exec 3<>"/dev/tcp/${host}/${port}" 2>/dev/null; then
    printf '*1\r\n$4\r\nPING\r\n' >&3 || true
    local line=""
    IFS= read -r -t "${timeout_s}" line <&3 || true
    exec 3>&-
    [[ "${line}" == "+PONG"* ]] && return 0
  fi
  return 1
}

wait_for_proxy_ready() {
  local host="$1"
  local port="$2"
  local tries="$3"
  local delay_ms="$4"
  local timeout_ms="$5"
  local attempt=1
  while [[ "${attempt}" -le "${tries}" ]]; do
    if resp_ping "${host}" "${port}" "${timeout_ms}"; then
      return 0
    fi
    sleep "$(awk "BEGIN{print ${delay_ms}/1000}")"
    attempt=$((attempt + 1))
  done
  return 1
}

# If caller sets RING_RESP_PROXY=1, try to launch local RESP-over-ring stream proxy
maybe_start_ring_proxy() {
  if [[ "${RING_RESP_PROXY:-0}" != "1" ]]; then return; fi
  local ring_path="${RING_PATH:-/sys/bus/pci/devices/0000:00:02.0/resource2}"
  local ring_size="${RING_MAP_SIZE:-1073741824}"
  local ring_offset="${RING_MAP_OFFSET:-${CXL_RING_OFFSET:-${CXL_SHM_OFFSET:-0}}}"
  local ring_idx="${RING_RING_IDX:-0}"
  local listen_addr="${RING_RESP_LISTEN:-127.0.0.1:${PORT}}"
  local sudo_prefix=()
  local proxy_env=(
    "CXL_RING_COUNT=${CXL_RING_COUNT:-}"
    "CXL_RING_REGION_SIZE=${CXL_RING_REGION_SIZE:-}"
    "CXL_RING_REGION_BASE=${CXL_RING_REGION_BASE:-}"
    "CXL_SHM_DELAY_NS=${CXL_SHM_DELAY_NS:-}"
    "CXL_SEC_KEY_HEX=${CXL_SEC_KEY_HEX:-}"
    "CXL_SEC_COMMON_KEY_HEX=${CXL_SEC_COMMON_KEY_HEX:-}"
    "CXL_CRYPTO_PRIV_REGION_SIZE=${CXL_CRYPTO_PRIV_REGION_SIZE:-}"
  )
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo_prefix=(sudo -n)
  fi
  if [[ -f "${ROOT}/ring_client/ring_resp_proxy.c" ]] && { [[ ! -x "/tmp/ring_resp_proxy" ]] || [[ "${ROOT}/ring_client/ring_resp_proxy.c" -nt "/tmp/ring_resp_proxy" ]]; }; then
    echo "[*] Building ring_resp_proxy ..."
    gcc -O2 -Wall -Wextra -std=gnu11 -pthread -I"${ROOT}" -o /tmp/ring_resp_proxy "${ROOT}/ring_client/ring_resp_proxy.c" "${ROOT}/tdx_shm/tdx_shm_transport.c" -lsodium || {
      echo "[!] Failed to build ring_resp_proxy" >&2; exit 1; }
  fi
  local secure_args=()
  if [[ -n "${RING_RESP_SECURE:-}" ]]; then
    local sec_mgr="${RING_RESP_SEC_MGR:-${CXL_SEC_MGR:-}}"
    local sec_node_id="${RING_RESP_SEC_NODE_ID:-${CXL_SEC_NODE_ID:-}}"
    local sec_timeout_ms="${RING_RESP_SEC_TIMEOUT_MS:-${CXL_SEC_TIMEOUT_MS:-}}"
    if [[ -z "${sec_mgr}" || -z "${sec_node_id}" ]]; then
      echo "[!] RING_RESP_SECURE requires RING_RESP_SEC_MGR (or CXL_SEC_MGR) and RING_RESP_SEC_NODE_ID (or CXL_SEC_NODE_ID)" >&2
      exit 1
    fi
    secure_args+=( --secure --sec-mgr "${sec_mgr}" --sec-node-id "${sec_node_id}" )
    [[ -n "${sec_timeout_ms}" ]] && secure_args+=( --sec-timeout-ms "${sec_timeout_ms}" )
  fi
  if [[ -n "${RING_RESP_CRYPTO:-}" ]]; then
    if [[ -n "${RING_RESP_SECURE:-}" ]]; then
      echo "[!] RING_RESP_CRYPTO cannot be combined with RING_RESP_SECURE" >&2
      exit 1
    fi
    local sec_node_id="${RING_RESP_SEC_NODE_ID:-${CXL_SEC_NODE_ID:-}}"
    if [[ -z "${sec_node_id}" ]]; then
      echo "[!] RING_RESP_CRYPTO requires RING_RESP_SEC_NODE_ID (or CXL_SEC_NODE_ID) plus CXL_SEC_KEY_HEX/CXL_SEC_COMMON_KEY_HEX" >&2
      exit 1
    fi
    secure_args+=( --crypto --sec-node-id "${sec_node_id}" )
  fi

  local listen_host="${listen_addr%:*}"
  local listen_port="${listen_addr##*:}"
  local attempt=1
  local proxy_log_ts
  proxy_log_ts="$(date +%Y%m%d_%H%M%S)"
  RING_RESP_PROXY_LOG="${OUTDIR}/ring_resp_proxy_${listen_port}_${proxy_log_ts}.log"

  while [[ "${attempt}" -le "${YCSB_PROXY_RETRIES}" ]]; do
    maybe_stop_ring_proxy
    echo "[*] Starting ring_resp_proxy at ${listen_addr} -> ${ring_path} (offset=${ring_offset} ring=${ring_idx})"
    ( "${sudo_prefix[@]}" env "${proxy_env[@]}" /tmp/ring_resp_proxy --path "${ring_path}" --map-size "${ring_size}" --map-offset "${ring_offset}" --ring "${ring_idx}" --listen "${listen_addr}" "${secure_args[@]}" >"${RING_RESP_PROXY_LOG}" 2>&1 & echo $! > /tmp/ring_resp_proxy.pid )
    sleep 0.3
    if wait_for_proxy_ready "${listen_host}" "${listen_port}" "${YCSB_PROXY_PING_TRIES}" "${YCSB_PROXY_PING_DELAY_MS}" "${YCSB_PROXY_PING_TIMEOUT_MS}"; then
      return 0
    fi
    echo "[!] ring_resp_proxy not ready after attempt ${attempt}/${YCSB_PROXY_RETRIES}" >&2
    if [[ -f "${RING_RESP_PROXY_LOG}" ]]; then
      echo "--- ${RING_RESP_PROXY_LOG} (tail) ---" >&2
      tail -n 200 "${RING_RESP_PROXY_LOG}" >&2 || true
    fi
    attempt=$((attempt + 1))
  done
  echo "[!] ring_resp_proxy failed to start or respond; aborting YCSB." >&2
  exit 1
}

maybe_stop_ring_proxy() {
  if [[ -f /tmp/ring_resp_proxy.pid ]]; then
    local pid; pid="$(cat /tmp/ring_resp_proxy.pid)"
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
      sudo -n kill "${pid}" >/dev/null 2>&1 || true
    else
      kill "${pid}" >/dev/null 2>&1 || true
    fi
    rm -f /tmp/ring_resp_proxy.pid
  fi
}

ensure_java
ensure_ycsb
if [[ "${DB}" == "rediskv" || "${DB}" == "ringkv" ]]; then
  ensure_kv_bindings
fi
if [[ "${DB}" == "ringkv" ]]; then
  ensure_ringkv_native
fi

if [[ "${DB}" != "ringkv" ]]; then
  maybe_start_ring_proxy
fi

IFS=',' read -r -a wls <<< "${WORKLOADS}"
for w in "${wls[@]}"; do
  wl_path="workloads/${w}"
  if [[ ! -f "${YCSB_DIR}/${wl_path}" ]]; then
    echo "[!] Workload file not found: ${YCSB_DIR}/${wl_path}" >&2
    exit 1
  fi
  run_ycsb load "${wl_path}"
  run_ycsb run  "${wl_path}"
done

if [[ "${DB}" != "ringkv" ]]; then
  maybe_stop_ring_proxy
fi
