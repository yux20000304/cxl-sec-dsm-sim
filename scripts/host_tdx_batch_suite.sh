#!/usr/bin/env bash
set -euo pipefail

# Batch runner for the TDX (2-VM) workflow.
#
# Goals (default preset):
# - Redis: ring region size = 256MB; for each N in THREAD_LIST, keep
#   RING_COUNT=N, redis-benchmark THREADS=N, CLIENTS=N, and YCSB_THREADS=N,
#   and run YCSB workloads A-E.
# - GAPBS: run a kernel list (BFS/SSSP/PR/CC/BC/TC by default).
#
# Usage:
#   bash scripts/host_tdx_batch_suite.sh
#
# Tunables (env):
#   THREAD_LIST          : comma-separated (default: 1,2,4,8,16)
#   RING_REGION_SIZE     : per-ring region size (default: 256M)
#   RING_REGION_BASE     : base offset (default: 4096; keeps page 0 unused for fair ring vs ring-secure)
#   RING_MAP_SIZE        : BAR2 map size (default: 16G)
#   CXL_CRYPTO_PRIV_REGION_SIZE: per-node crypto private region size (default: 1G)
#   REDIS_BENCH_DATASIZE : redis-benchmark value size in bytes (-d) (default: 3)
#   RING_BENCH_KEY_SIZE  : ring benchmark fixed key size (bytes; 0=use k%d; optional K/M/G suffix) (default: 0)
#   RING_BENCH_VALUE_SIZE: ring benchmark fixed value size (bytes; 0=use v%d; optional K/M/G suffix) (default: 0)
#   YCSB_WORKLOADS       : comma-separated workloads (default: workloada..workloade)
#   GAPBS_KERNEL_LIST    : comma-separated kernels (default: bfs,sssp,pr,cc,bc,tc)
#   VM1_CPUS/VM2_CPUS    : guest vCPUs (forwarded; see host_recreate_and_bench_tdx.sh)
#   VM1_MEM/VM2_MEM      : guest memory (forwarded; see host_recreate_and_bench_tdx.sh)
#
# All other env vars are forwarded to scripts/host_recreate_and_bench_tdx.sh.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

THREAD_LIST="${THREAD_LIST:-1,2,4,8,16}"
RING_REGION_SIZE="${RING_REGION_SIZE:-256M}"
RING_REGION_BASE="${RING_REGION_BASE:-4096}"
RING_MAP_SIZE="${RING_MAP_SIZE:-128G}"
CXL_CRYPTO_PRIV_REGION_SIZE="${CXL_CRYPTO_PRIV_REGION_SIZE:-32G}"

YCSB_ENABLE="${YCSB_ENABLE:-0}"
YCSB_WORKLOADS="${YCSB_WORKLOADS:-workloada,workloadb,workloadc,workloadd}"
GAPBS_KERNEL_LIST="${GAPBS_KERNEL_LIST:-bfs,sssp,pr,cc,bc,tc}"

IFS=',' read -r -a threads_arr <<< "${THREAD_LIST}"

for n in "${threads_arr[@]}"; do
  if [[ -z "${n}" ]]; then
    continue
  fi
  if ! [[ "${n}" =~ ^[0-9]+$ ]]; then
    echo "[!] THREAD_LIST contains non-numeric value: '${n}'" >&2
    exit 1
  fi

  echo "[*] TDX batch: N=${n} (RING_COUNT/THREADS/CLIENTS/YCSB_THREADS/OMP_THREADS all = ${n})"
  RING_COUNT="${n}" \
  THREADS="${n}" \
  CLIENTS="${n}" \
  YCSB_ENABLE="${YCSB_ENABLE}" \
  YCSB_THREADS="${n}" \
  YCSB_WORKLOADS="${YCSB_WORKLOADS}" \
  OMP_THREADS="${n}" \
  GAPBS_KERNEL_LIST="${GAPBS_KERNEL_LIST}" \
  RING_REGION_SIZE="${RING_REGION_SIZE}" \
  RING_REGION_BASE="${RING_REGION_BASE}" \
  RING_MAP_SIZE="${RING_MAP_SIZE}" \
  bash "${ROOT}/scripts/host_recreate_and_bench_tdx.sh"
done

echo "[+] Done."
