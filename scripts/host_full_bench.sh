#!/usr/bin/env bash
set -euo pipefail

# Full benchmark orchestrator:
# - Redis (TDX): 版本矩阵 + ring（含 RESP 代理）；YCSB 多 workload
# - GAPBS: native vs ring（本地）以及多机对比（可选）
#
# Usage:
#   bash scripts/host_full_bench.sh
#
# Tunables (env):
#   REDIS_REQ_N      : redis-benchmark requests (default: 200000)
#   REDIS_CLIENTS    : clients (default: 4)
#   REDIS_THREADS    : threads (default: 4)
#   REDIS_PIPELINE   : pipeline (default: 256)
#   VM_CPUS          : vCPU count for both VMs (default: 4)
#   VM_MEM           : RAM size for both VMs (default: 4G)
#   VM1_CPUS/VM2_CPUS: override per-VM vCPUs (default: VM_CPUS)
#   VM1_MEM/VM2_MEM  : override per-VM RAM (default: VM_MEM)
#   RING_COUNT       : number of ring regions (default: 4)
#   RING_REGION_SIZE : bytes per ring region (default: 16M)
#   RING_REGION_BASE : base offset within BAR2 mmap (default: 0)
#   RING_MAP_SIZE    : BAR2 mmap size (bytes or IEC like 4G; default: 4294967296)
#   YCSB_WORKLOADS   : comma-separated workloads (default: workloada,workloadb)
#   YCSB_RECORDS     : records (default: 100000)
#   YCSB_OPS         : ops (default: 100000)
#   YCSB_THREADS     : threads (default: 4)
#   RUN_GAPBS_LOCAL  : 1 to run local GAPBS (default: 1)
#   RUN_GAPBS_MULTI  : 1 to run multihost GAPBS (default: 0)
#
# Sweep lists (optional; comma-separated unless noted):
#   REDIS_CLIENTS_LIST, REDIS_THREADS_LIST, CXL_SHM_DELAY_NS_LIST
#   VM_CPUS_LIST, VM_MEM_LIST
#   RING_COUNT_LIST, RING_REGION_SIZE_LIST, RING_MAP_SIZE_LIST
#   YCSB_WORKLOADS_LIST : semicolon-separated workload groups
#
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

REDIS_REQ_N="${REDIS_REQ_N:-200000}"
REDIS_CLIENTS="${REDIS_CLIENTS:-4}"
REDIS_THREADS="${REDIS_THREADS:-4}"
REDIS_PIPELINE="${REDIS_PIPELINE:-256}"
# Sweep lists (comma-separated). If set, iterate over combinations; if unset, use single values above.
REDIS_CLIENTS_LIST="${REDIS_CLIENTS_LIST:-}"
REDIS_THREADS_LIST="${REDIS_THREADS_LIST:-}"

VM_CPUS="${VM_CPUS:-}"
VM_MEM="${VM_MEM:-}"
VM1_CPUS="${VM1_CPUS:-${VM_CPUS:-16}}"
VM2_CPUS="${VM2_CPUS:-${VM_CPUS:-16}}"
VM1_MEM="${VM1_MEM:-${VM_MEM:-32G}}"
VM2_MEM="${VM2_MEM:-${VM_MEM:-32G}}"
VM_CPUS_LIST="${VM_CPUS_LIST:-}"
VM_MEM_LIST="${VM_MEM_LIST:-}"

RING_COUNT="${RING_COUNT:-4}"
RING_COUNT_LIST="${RING_COUNT_LIST:-}"
RING_REGION_SIZE="${RING_REGION_SIZE:-128M}"
RING_REGION_SIZE_LIST="${RING_REGION_SIZE_LIST:-}"
RING_REGION_BASE="${RING_REGION_BASE:-0}"
RING_MAP_SIZE="${RING_MAP_SIZE:-4294967296}"
RING_MAP_SIZE_LIST="${RING_MAP_SIZE_LIST:-}"
CXL_SIZE="${CXL_SIZE:-}"

YCSB_WORKLOADS="${YCSB_WORKLOADS:-workloada,workloadb}"
YCSB_RECORDS="${YCSB_RECORDS:-100000}"
YCSB_OPS="${YCSB_OPS:-100000}"
YCSB_THREADS="${YCSB_THREADS:-4}"
# Sweep YCSB workloads list (comma of comma groups):
# If set, e.g. "workloada,workloadb;workloadc", will run with WORKLOADS set to each semicolon group.
YCSB_WORKLOADS_LIST="${YCSB_WORKLOADS_LIST:-}"

# Injected shared-memory latency (ns) for ring path (simulated CXL latency)
# Single value or sweep list (comma-separated). If unset, leave to downstream defaulting logic.
CXL_SHM_DELAY_NS="${CXL_SHM_DELAY_NS:-}"
CXL_SHM_DELAY_NS_LIST="${CXL_SHM_DELAY_NS_LIST:-}"

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

RUN_GAPBS_LOCAL="${RUN_GAPBS_LOCAL:-1}"
RUN_GAPBS_MULTI="${RUN_GAPBS_MULTI:-0}"

# GAPBS sweep/preset
GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
GAPBS_KERNEL_LIST="${GAPBS_KERNEL_LIST:-}"
GAPBS_SCALE="${GAPBS_SCALE:-20}"
GAPBS_DEGREE="${GAPBS_DEGREE:-16}"
GAPBS_TRIALS="${GAPBS_TRIALS:-3}"
GAPBS_OMP_THREADS="${GAPBS_OMP_THREADS:-4}"
GAPBS_EXTRA_ARGS="${GAPBS_EXTRA_ARGS:-}"

echo "[*] Phase: Redis (TDX dual-VM matrix + YCSB native/sodium + ring via proxy)"
if [[ -n "${REDIS_CLIENTS_LIST}" || -n "${REDIS_THREADS_LIST}" || -n "${YCSB_WORKLOADS_LIST}" || -n "${CXL_SHM_DELAY_NS_LIST}" || -n "${VM_CPUS_LIST}" || -n "${VM_MEM_LIST}" || -n "${RING_COUNT_LIST}" || -n "${RING_REGION_SIZE_LIST}" || -n "${RING_MAP_SIZE_LIST}" ]]; then
  IFS=',' read -r -a clients_arr <<< "${REDIS_CLIENTS_LIST:-${REDIS_CLIENTS}}"
  IFS=',' read -r -a threads_arr <<< "${REDIS_THREADS_LIST:-${REDIS_THREADS}}"
  IFS=';' read -r -a wls_arr <<< "${YCSB_WORKLOADS_LIST:-${YCSB_WORKLOADS}}"
  IFS=',' read -r -a delays_arr <<< "${CXL_SHM_DELAY_NS_LIST:-${CXL_SHM_DELAY_NS}}"
  IFS=',' read -r -a vm_cpus_arr <<< "${VM_CPUS_LIST:-}"
  IFS=',' read -r -a vm_mem_arr <<< "${VM_MEM_LIST:-}"
  IFS=',' read -r -a ring_count_arr <<< "${RING_COUNT_LIST:-${RING_COUNT}}"
  IFS=',' read -r -a ring_region_size_arr <<< "${RING_REGION_SIZE_LIST:-${RING_REGION_SIZE}}"
  IFS=',' read -r -a ring_map_size_arr <<< "${RING_MAP_SIZE_LIST:-${RING_MAP_SIZE}}"

  if [[ ${#vm_mem_arr[@]} -eq 0 ]]; then vm_mem_arr=(""); fi
  if [[ ${#vm_cpus_arr[@]} -eq 0 ]]; then vm_cpus_arr=(""); fi
  if [[ ${#delays_arr[@]} -eq 0 ]]; then delays_arr=(""); fi

  for mem in "${vm_mem_arr[@]}"; do
    for cpus in "${vm_cpus_arr[@]}"; do
      vm1_mem="${VM1_MEM}"
      vm2_mem="${VM2_MEM}"
      vm1_cpus="${VM1_CPUS}"
      vm2_cpus="${VM2_CPUS}"
      if [[ -n "${VM_MEM_LIST}" ]]; then
        vm1_mem="${mem}"
        vm2_mem="${mem}"
      fi
      if [[ -n "${VM_CPUS_LIST}" ]]; then
        vm1_cpus="${cpus}"
        vm2_cpus="${cpus}"
      fi
      for rms in "${ring_map_size_arr[@]}"; do
        ring_map_size_bytes="$(size_to_bytes "${rms}")" || { echo "[!] invalid RING_MAP_SIZE: ${rms}" >&2; exit 1; }
        cxl_size_val="${CXL_SIZE:-${ring_map_size_bytes}}"
        if [[ -n "${CXL_SIZE}" ]]; then
          cxl_size_bytes="$(size_to_bytes "${CXL_SIZE}")" || cxl_size_bytes=0
          if [[ "${cxl_size_bytes}" -gt 0 && "${cxl_size_bytes}" -lt "${ring_map_size_bytes}" ]]; then
            echo "[!] Invalid config: CXL_SIZE(${CXL_SIZE}) < RING_MAP_SIZE(${rms})" >&2
            exit 1
          fi
        fi
        for rc in "${ring_count_arr[@]}"; do
          for rrs in "${ring_region_size_arr[@]}"; do
            ring_region_size_bytes="$(size_to_bytes "${rrs}")" || { echo "[!] invalid RING_REGION_SIZE: ${rrs}" >&2; exit 1; }
            ring_region_base_bytes="$(size_to_bytes "${RING_REGION_BASE}")" || ring_region_base_bytes=0
            need_bytes=$((ring_region_base_bytes + rc * ring_region_size_bytes))
            if [[ "${need_bytes}" -gt "${ring_map_size_bytes}" ]]; then
              echo "[!] Skip config: ring regions exceed BAR2 map (RING_COUNT=${rc} RING_REGION_SIZE=${rrs} RING_REGION_BASE=${RING_REGION_BASE} needs ${need_bytes}B > RING_MAP_SIZE=${ring_map_size_bytes}B)" >&2
              continue
            fi

            for d in "${delays_arr[@]}"; do
              for c in "${clients_arr[@]}"; do
                for t in "${threads_arr[@]}"; do
                  for ws in "${wls_arr[@]}"; do
                    echo "[*] Sweep(TDX): VM1_MEM=${vm1_mem} VM2_MEM=${vm2_mem} VM1_CPUS=${vm1_cpus} VM2_CPUS=${vm2_cpus} RING_MAP_SIZE=${ring_map_size_bytes} RING_COUNT=${rc} RING_REGION_SIZE=${rrs} CLIENTS=${c} THREADS=${t} WORKLOADS=${ws} CXL_SHM_DELAY_NS=${d}"
                    CXL_SHM_DELAY_NS="${d}" \
                    VM1_MEM="${vm1_mem}" VM2_MEM="${vm2_mem}" VM1_CPUS="${vm1_cpus}" VM2_CPUS="${vm2_cpus}" \
                    RING_MAP_SIZE="${ring_map_size_bytes}" CXL_SIZE="${cxl_size_val}" \
                    RING_COUNT="${rc}" RING_REGION_SIZE="${rrs}" RING_REGION_BASE="${RING_REGION_BASE}" \
                    YCSB_ENABLE=1 YCSB_WORKLOADS="${ws}" YCSB_RECORDS="${YCSB_RECORDS}" YCSB_OPS="${YCSB_OPS}" YCSB_THREADS="${YCSB_THREADS}" \
                    REQ_N="${REDIS_REQ_N}" CLIENTS="${c}" THREADS="${t}" PIPELINE="${REDIS_PIPELINE}" \
                    bash "${ROOT}/scripts/host_recreate_and_bench_tdx.sh"
                  done
                done
              done
            done
          done
        done
      done
    done
  done
else
  YCSB_ENABLE=1 YCSB_WORKLOADS="${YCSB_WORKLOADS}" YCSB_RECORDS="${YCSB_RECORDS}" YCSB_OPS="${YCSB_OPS}" YCSB_THREADS="${YCSB_THREADS}" \
  VM1_MEM="${VM1_MEM}" VM2_MEM="${VM2_MEM}" VM1_CPUS="${VM1_CPUS}" VM2_CPUS="${VM2_CPUS}" \
  RING_MAP_SIZE="$(size_to_bytes "${RING_MAP_SIZE}")" CXL_SIZE="${CXL_SIZE:-$(size_to_bytes "${RING_MAP_SIZE}")}" \
  RING_COUNT="${RING_COUNT}" RING_REGION_SIZE="${RING_REGION_SIZE}" RING_REGION_BASE="${RING_REGION_BASE}" \
  REQ_N="${REDIS_REQ_N}" CLIENTS="${REDIS_CLIENTS}" THREADS="${REDIS_THREADS}" PIPELINE="${REDIS_PIPELINE}" \
  bash "${ROOT}/scripts/host_recreate_and_bench_tdx.sh"
fi

if [[ "${RUN_GAPBS_LOCAL}" == "1" ]]; then
  echo "[*] Phase: GAPBS local compare"
  GAPBS_KERNELS=( )
  if [[ -n "${GAPBS_KERNEL_LIST}" ]]; then IFS=',' read -r -a GAPBS_KERNELS <<< "${GAPBS_KERNEL_LIST}"; else GAPBS_KERNELS=("${GAPBS_KERNEL}"); fi
  for k in "${GAPBS_KERNELS[@]}"; do
    GAPBS_KERNEL="${k}" SCALE="${GAPBS_SCALE}" DEGREE="${GAPBS_DEGREE}" TRIALS="${GAPBS_TRIALS}" OMP_THREADS="${GAPBS_OMP_THREADS}" GAPBS_EXTRA_ARGS="${GAPBS_EXTRA_ARGS}" \
    bash "${ROOT}/scripts/host_bench_gapbs_local.sh"
  done
fi

if [[ "${RUN_GAPBS_MULTI}" == "1" ]]; then
  echo "[*] Phase: GAPBS multihost compare"
  GAPBS_KERNELS=( )
  if [[ -n "${GAPBS_KERNEL_LIST}" ]]; then IFS=',' read -r -a GAPBS_KERNELS <<< "${GAPBS_KERNEL_LIST}"; else GAPBS_KERNELS=("${GAPBS_KERNEL}"); fi
  for k in "${GAPBS_KERNELS[@]}"; do
    GAPBS_KERNEL="${k}" SCALE="${GAPBS_SCALE}" DEGREE="${GAPBS_DEGREE}" TRIALS="${GAPBS_TRIALS}" OMP_THREADS="${GAPBS_OMP_THREADS}" \
    bash "${ROOT}/scripts/host_recreate_and_bench_gapbs_multihost.sh"
  done
fi

echo "[+] Done. All artifacts in ${RESULTS_DIR}"
