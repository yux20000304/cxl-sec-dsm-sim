#!/usr/bin/env bash
set -euo pipefail

# Local (no-VM) GAPBS benchmark runner.
#
# Compares:
# - GAPBS native binaries (heap graph)
# - GAPBS ring binaries (graph copied into shared memory via mmap)
#
# Usage:
#   bash scripts/host_bench_gapbs_local.sh
#
# Tunables (env):
#   GAPBS_KERNEL       : bfs|cc|pr|... (default: bfs)
#   SCALE              : -g scale for Kronecker graph (default: 20)
#   DEGREE             : -k degree (default: 16)
#   TRIALS             : -n trials (default: 3)
#   OMP_THREADS        : OMP_NUM_THREADS (default: 4)
#   GAPBS_CXL_PATH     : shared memory backing (default: /dev/shm/gapbs_cxl_shared.raw)
#   GAPBS_CXL_MAP_SIZE : bytes (or K/M/G suffix, default: 536870912)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
SCALE="${SCALE:-20}"
DEGREE="${DEGREE:-16}"
TRIALS="${TRIALS:-3}"
OMP_THREADS="${OMP_THREADS:-4}"

export OMP_NUM_THREADS="${OMP_THREADS}"
export GAPBS_CXL_PATH="${GAPBS_CXL_PATH:-/dev/shm/gapbs_cxl_shared.raw}"
export GAPBS_CXL_MAP_SIZE="${GAPBS_CXL_MAP_SIZE:-536870912}"

ts="$(date +%Y%m%d_%H%M%S)"
native_log="${RESULTS_DIR}/gapbs_native_${GAPBS_KERNEL}_${ts}.log"
ring_log="${RESULTS_DIR}/gapbs_ring_${GAPBS_KERNEL}_${ts}.log"
compare_csv="${RESULTS_DIR}/gapbs_compare_${GAPBS_KERNEL}_${ts}.csv"

echo "[*] Building GAPBS (native + ring) ..."
make -C "${ROOT}/gapbs" -j"$(nproc)" all ring

echo "[*] Running GAPBS native: ${GAPBS_KERNEL} -g ${SCALE} -k ${DEGREE} -n ${TRIALS}"
"${ROOT}/gapbs/${GAPBS_KERNEL}" -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" | tee "${native_log}"

echo "[*] Running GAPBS ring: ${GAPBS_KERNEL}-ring (GAPBS_CXL_PATH=${GAPBS_CXL_PATH}, GAPBS_CXL_MAP_SIZE=${GAPBS_CXL_MAP_SIZE})"
"${ROOT}/gapbs/${GAPBS_KERNEL}-ring" -g "${SCALE}" -k "${DEGREE}" -n "${TRIALS}" | tee "${ring_log}"

native_avg="$(awk '/^Average Time:/{print $3; exit}' "${native_log}" || true)"
ring_avg="$(awk '/^Average Time:/{print $3; exit}' "${ring_log}" || true)"

{
  echo "label,kernel,scale,degree,trials,omp_threads,avg_time_s"
  echo "GAPBSNative,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${native_avg}"
  echo "GAPBSRing,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${ring_avg}"
} > "${compare_csv}"

echo "[+] Done."
echo "    ${native_log}"
echo "    ${ring_log}"
echo "    ${compare_csv}"
