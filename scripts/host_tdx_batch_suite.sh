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
#   THREAD_LIST          : comma-separated (default: 1,2,4,8)
#   RING_REGION_SIZE     : per-ring region size (default: 256M)
#   RING_REGION_BASE     : base offset (default: 0)
#   RING_MAP_SIZE        : BAR2 map size (default: 4G)
#   YCSB_WORKLOADS       : comma-separated workloads (default: workloada..workloade)
#   GAPBS_KERNEL_LIST    : comma-separated kernels (default: bfs,sssp,pr,cc,bc,tc)
#   VM1_CPUS/VM2_CPUS    : guest vCPUs (forwarded; see host_recreate_and_bench_tdx.sh)
#   VM1_MEM/VM2_MEM      : guest memory (forwarded; see host_recreate_and_bench_tdx.sh)
#
# All other env vars are forwarded to scripts/host_recreate_and_bench_tdx.sh.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

THREAD_LIST="${THREAD_LIST:-1,2,4,8}"
RING_REGION_SIZE="${RING_REGION_SIZE:-256M}"
RING_REGION_BASE="${RING_REGION_BASE:-0}"
RING_MAP_SIZE="${RING_MAP_SIZE:-4G}"

YCSB_ENABLE="${YCSB_ENABLE:-0}"
YCSB_WORKLOADS="${YCSB_WORKLOADS:-workloada,workloadb,workloadc,workloadd,workloade}"
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
