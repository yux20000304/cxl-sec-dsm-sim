#!/usr/bin/env bash
set -euo pipefail

# Compare native Redis (TCP/RESP) vs ring Redis (shared-memory, no RESP) under
# Gramine SGX on an SGX-capable *host*.
#
# This script does NOT use QEMU VMs. It is meant for machines where SGX works
# on the host OS (i.e., `/dev/sgx_enclave` exists and AESM is running).
#
# Usage:
#   sudo -E bash scripts/host_bench_gramine_sgx.sh
#
# Tunables (env):
#   REQ_N        : total requests for TCP benchmark (default: 200000)
#   CLIENTS      : redis-benchmark concurrency (default: 4)
#   THREADS      : redis-benchmark threads (default: 4)
#   PIPELINE     : redis-benchmark pipeline depth (-P) (default: 256)
#   NATIVE_PORT  : TCP port for native Redis in SGX (default: 16379)
#   RING_PORT    : TCP port for ring Redis in SGX (optional; default: 17379)
#   RING_PATH    : shared-memory backing file (default: /dev/shm/cxl_shared.raw)
#   RING_MAP_SIZE: bytes (default: 134217728 = 128MB)
#   RING_COUNT   : number of rings (default: 4)
#   MAX_INFLIGHT : ring client inflight limit (default: 512)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

REQ_N="${REQ_N:-200000}"
CLIENTS="${CLIENTS:-4}"
THREADS="${THREADS:-4}"
PIPELINE="${PIPELINE:-256}"

NATIVE_PORT="${NATIVE_PORT:-16379}"
RING_PORT="${RING_PORT:-17379}"

RING_PATH="${RING_PATH:-/dev/shm/cxl_shared.raw}"
RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}" # 128MB
RING_COUNT="${RING_COUNT:-4}"
MAX_INFLIGHT="${MAX_INFLIGHT:-512}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[!] Missing command: $1" >&2
    return 1
  fi
}

check_sgx_host() {
  if ! grep -q -m1 -w aes /proc/cpuinfo 2>/dev/null; then
    echo "[!] Host CPU does not expose AES-NI ('aes' flag). Gramine SGX cannot run." >&2
    exit 1
  fi
  if ! grep -q -m1 -w sgx /proc/cpuinfo 2>/dev/null; then
    echo "[!] Host CPU does not expose SGX ('sgx' flag). Gramine SGX cannot run." >&2
    exit 1
  fi

  if [[ -c /dev/sgx_enclave || -c /dev/sgx/enclave || -c /dev/isgx ]]; then
    return 0
  fi

  echo "[!] No SGX device node found (/dev/sgx_enclave or /dev/isgx)." >&2
  echo "    Check BIOS SGX setting and SGX driver installation." >&2
  exit 1
}

port_in_use() {
  local port="$1"
  ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .
}

check_prereqs() {
  check_sgx_host
  need_cmd ss
  need_cmd tmux
  need_cmd make
  need_cmd gcc
  need_cmd redis-cli
  need_cmd redis-benchmark
  need_cmd gramine-manifest
  need_cmd gramine-sgx
  need_cmd gramine-sgx-sign
  need_cmd gramine-sgx-get-token
}

cleanup_tmux() {
  tmux kill-session -t redis_native_sgx >/dev/null 2>&1 || true
  tmux kill-session -t redis_ring_sgx >/dev/null 2>&1 || true
}

cleanup_tmux

if port_in_use "${NATIVE_PORT}"; then
  echo "[!] NATIVE_PORT already in use: ${NATIVE_PORT}" >&2
  echo "    Set NATIVE_PORT=<free-port> and rerun." >&2
  exit 1
fi
if port_in_use "${RING_PORT}"; then
  echo "[!] RING_PORT already in use: ${RING_PORT}" >&2
  echo "    Set RING_PORT=<free-port> and rerun." >&2
  exit 1
fi

check_prereqs

echo "[*] Preparing ring backing file: ${RING_PATH} (${RING_MAP_SIZE} bytes)"
mkdir -p "$(dirname "${RING_PATH}")"
truncate -s "${RING_MAP_SIZE}" "${RING_PATH}"
chmod 666 "${RING_PATH}" || true

echo "[*] Building Redis (ring version) ..."
make -C "${ROOT}/redis/src" -j"$(nproc)" MALLOC=libc USE_LTO=no CFLAGS='-O2 -fno-lto' LDFLAGS='-fno-lto'

echo "[*] Building ring client (/tmp/cxl_ring_direct) ..."
gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct "${ROOT}/ring_client/cxl_ring_direct.c"

echo "[*] Building Gramine manifests + SGX artifacts ..."
(
  cd "${ROOT}/gramine"
  make clean
  make links

  # Use Gramine runtime glibc for SGX mode.
  make native USE_RUNTIME_GLIBC=1
  make ring USE_RUNTIME_GLIBC=1 CXL_RING_PATH="${RING_PATH}" CXL_RING_COUNT="${RING_COUNT}" CXL_RING_MAP_SIZE="${RING_MAP_SIZE}"

  make sgx-sign
  make sgx-token
)

ts="$(date +%Y%m%d_%H%M%S)"
native_log="${RESULTS_DIR}/sgx_native_tcp_${ts}.log"
ring_log="${RESULTS_DIR}/sgx_ring_${ts}.log"
ring_csv="${RESULTS_DIR}/sgx_ring_${ts}.csv"
compare_csv="${RESULTS_DIR}/sgx_compare_${ts}.csv"

echo "[*] Benchmark 1/2: native Redis under Gramine SGX (TCP)"
tmux new-session -d -s redis_native_sgx "cd '${ROOT}/gramine' && gramine-sgx ./redis-native /repo/gramine/redis.conf --port '${NATIVE_PORT}' >/tmp/redis_native_sgx.log 2>&1"
for _ in $(seq 1 120); do
  redis-cli -p "${NATIVE_PORT}" ping >/dev/null 2>&1 && break
  sleep 0.25
done
if ! redis-cli -p "${NATIVE_PORT}" ping >/dev/null 2>&1; then
  echo "[!] redis-native (SGX) not ready on port ${NATIVE_PORT}" >&2
  tail -n 200 /tmp/redis_native_sgx.log >&2 || true
  exit 1
fi

redis-benchmark -h 127.0.0.1 -p "${NATIVE_PORT}" -t set,get -n "${REQ_N}" -c "${CLIENTS}" --threads "${THREADS}" -P "${PIPELINE}" | tee "${native_log}"
redis-cli -p "${NATIVE_PORT}" shutdown nosave >/dev/null 2>&1 || true
tmux kill-session -t redis_native_sgx >/dev/null 2>&1 || true

echo "[*] Benchmark 2/2: ring Redis under Gramine SGX (shared memory)"
tmux new-session -d -s redis_ring_sgx "cd '${ROOT}/gramine' && gramine-sgx ./redis-ring /repo/gramine/redis.conf --port '${RING_PORT}' >/tmp/redis_ring_sgx.log 2>&1"

for _ in $(seq 1 200); do
  timeout 2 /tmp/cxl_ring_direct --path "${RING_PATH}" --map-size "${RING_MAP_SIZE}" >/dev/null 2>&1 && break
  sleep 0.25
done
if ! timeout 2 /tmp/cxl_ring_direct --path "${RING_PATH}" --map-size "${RING_MAP_SIZE}" >/dev/null 2>&1; then
  echo "[!] ring transport not ready (SGX). Dumping diagnostics..." >&2
  tail -n 200 /tmp/redis_ring_sgx.log >&2 || true
  exit 1
fi

ring_label="sgx_ring_${ts}"
ring_n_per_thread=$(( (REQ_N + THREADS - 1) / THREADS ))
cd /tmp
/tmp/cxl_ring_direct --path "${RING_PATH}" --map-size "${RING_MAP_SIZE}" \
  --bench "${ring_n_per_thread}" --pipeline --threads "${THREADS}" --max-inflight "${MAX_INFLIGHT}" \
  --latency --cost --csv "/tmp/${ring_label}.csv" --label "${ring_label}" | tee "${ring_log}"
cat "/tmp/${ring_label}.csv" > "${ring_csv}"

tmux kill-session -t redis_ring_sgx >/dev/null 2>&1 || true

native_set="$(awk '/====== SET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
native_get="$(awk '/====== GET ======/{sec=1;next} sec && /throughput summary:/{print $3; exit} sec && /requests per second/{print $1; exit}' "${native_log}" || true)"
ring_set="$(awk -F, 'NR>1 && $2=="SET"{print $8; exit}' "${ring_csv}" || true)"
ring_get="$(awk -F, 'NR>1 && $2=="GET"{print $8; exit}' "${ring_csv}" || true)"

{
  echo "label,op,throughput_rps"
  echo "GramineSGXNativeTCP,SET,${native_set}"
  echo "GramineSGXNativeTCP,GET,${native_get}"
  echo "GramineSGXRing,SET,${ring_set}"
  echo "GramineSGXRing,GET,${ring_get}"
} > "${compare_csv}"

echo "[+] Done."
echo "    ${native_log}"
echo "    ${ring_log}"
echo "    ${ring_csv}"
echo "    ${compare_csv}"

