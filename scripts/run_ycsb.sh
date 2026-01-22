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
WORKLOADS="workloada,workloadb"   # comma-separated; files in YCSB workloads/
RECORDS=100000
OPS=100000
THREADS=4
TARGET=""         # ops/sec (optional)
PASSWORD=""       # optional redis password
CLUSTER="false"    # true/false
YCSB_DIR=""        # optional, pre-installed YCSB dir

usage() {
  cat <<EOF
Usage: $0 [--host 127.0.0.1] [--port 6379] [--workloads workloada,workloadb] \
          [--recordcount 100000] [--operationcount 100000] [--threads 4] \
          [--target OPS] [--password PWD] [--cluster true|false] [--ycsb-dir PATH]

Runs YCSB (redis binding) against the given Redis host:port.
Downloads YCSB locally if needed (to /tmp/ycsb-0.17.0).
Outputs logs to results/ycsb_<workload>_{load|run}_HOST_PORT_TIMESTAMP.log
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --workloads) WORKLOADS="$2"; shift 2 ;;
    --recordcount) RECORDS="$2"; shift 2 ;;
    --operationcount) OPS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --cluster) CLUSTER="$2"; shift 2 ;;
    --ycsb-dir) YCSB_DIR="$2"; shift 2 ;;
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

  local tgt_args=()
  [[ -n "${TARGET}" ]] && tgt_args+=( -target "${TARGET}" )

  local launcher
  launcher="$(find_ycsb_launcher)" || { echo "[!] YCSB launcher not found under: ${YCSB_DIR}/bin" >&2; exit 1; }

  echo "[*] YCSB ${action} ${wl_file} -> ${HOST}:${PORT} (threads=${THREADS}, records=${RECORDS}, ops=${OPS})"
  "${launcher}" "${action}" redis -s -P "${YCSB_DIR}/${wl_file}" \
    -p "recordcount=${RECORDS}" -p "operationcount=${OPS}" \
    -p "redis.host=${HOST}" -p "redis.port=${PORT}" \
    "${extra_p[@]}" -threads "${THREADS}" "${tgt_args[@]}" | tee "${outfile}"
  echo "[+] Saved: ${outfile}"
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

  echo "[*] Starting ring_resp_proxy at ${listen_addr} -> ${ring_path} (offset=${ring_offset} ring=${ring_idx})"
  ( "${sudo_prefix[@]}" env "${proxy_env[@]}" /tmp/ring_resp_proxy --path "${ring_path}" --map-size "${ring_size}" --map-offset "${ring_offset}" --ring "${ring_idx}" --listen "${listen_addr}" "${secure_args[@]}" >/tmp/ring_resp_proxy.log 2>&1 & echo $! > /tmp/ring_resp_proxy.pid )
  sleep 0.3
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

maybe_start_ring_proxy

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

maybe_stop_ring_proxy
