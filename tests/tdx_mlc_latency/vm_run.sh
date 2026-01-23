#!/usr/bin/env bash
set -euo pipefail

# Run inside a guest VM (TDX or non-TDX). Requires /mnt/hostshare mounted.
#
# Outputs:
# - Intel MLC output (if available)
# - Pointer-chase latency for:
#   * private memory (malloc)
#   * ivshmem BAR2 (shared memory)

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

LAT_SIZE="${LAT_SIZE:-256M}"
LAT_STRIDE="${LAT_STRIDE:-64}"
LAT_ITERS="${LAT_ITERS:-0}"
LAT_SHM_REGION_OFF="${LAT_SHM_REGION_OFF:-64M}"
LAT_CPU="${LAT_CPU:-}"

MLC_BIN="${MLC_BIN:-/mnt/hostshare/tests/tdx_mlc_latency/mlc/mlc}"
MICRO_SRC="/mnt/hostshare/tests/tdx_mlc_latency/cxl_cacheline_lat.c"
MICRO_BIN="/tmp/cxl_cacheline_lat"

# MLC can OOM small VMs with the default --loaded_latency configuration.
# Keep a conservative default and allow overrides via env.
MLC_IDLE_ARGS="${MLC_IDLE_ARGS:-}"                 # e.g. "-r -t2"
MLC_LOADED_ARGS="${MLC_LOADED_ARGS:- -k1 -b200000 -t2 -u}" # safe-ish for ~4G VMs; use core1 only

apt_retry() {
  local desc="$1"
  shift
  local out=""
  local rc=0
  for _ in $(seq 1 120); do
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    if [[ "${rc}" -eq 0 ]]; then
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

echo "[*] Guest info:"
uname -a || true
lsb_release -sd 2>/dev/null || true
echo

echo "[*] Ensuring dependencies (gcc, make, taskset, pciutils) ..."
apt_retry "apt-get update" env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
apt_retry "apt-get install deps" env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential util-linux pciutils >/dev/null

echo "[*] Building microbench: ${MICRO_BIN}"
gcc -O2 -Wall -Wextra -std=gnu11 -o "${MICRO_BIN}" "${MICRO_SRC}"

pin_prefix=()
if [[ -n "${LAT_CPU}" ]] && command -v taskset >/dev/null 2>&1; then
  pin_prefix=(taskset -c "${LAT_CPU}")
fi

echo
echo "[*] Pointer-chase latency: private RAM"
"${pin_prefix[@]}" "${MICRO_BIN}" --mode private --size "${LAT_SIZE}" --stride "${LAT_STRIDE}" --iters "${LAT_ITERS}" --csv

detect_resource2() {
  for dev in /sys/bus/pci/devices/*; do
    [[ -f "${dev}/vendor" && -f "${dev}/device" ]] || continue
    local ven did
    ven="$(cat "${dev}/vendor")"
    did="$(cat "${dev}/device")"
    if [[ "${ven}" == "0x1af4" && "${did}" == "0x1110" && -e "${dev}/resource2" ]]; then
      echo "${dev}/resource2"
      return 0
    fi
  done
  return 1
}

SHM_PATH="${LAT_SHM_PATH:-}"
MAP_OFFSET=0
MAP_SIZE=""

if [[ -z "${SHM_PATH}" ]]; then
  SHM_PATH="$(detect_resource2 || true)"
fi

try_shm_run() {
  local p="$1"
  local off="$2"
  local sz="$3"
  echo
  echo "[*] Pointer-chase latency: ivshmem shared memory"
  echo "    path=${p} map_offset=${off} map_size=${sz} region_off=${LAT_SHM_REGION_OFF}"
  "${pin_prefix[@]}" "${MICRO_BIN}" --mode shm --path "${p}" --map-offset "${off}" --map-size "${sz}" --region-off "${LAT_SHM_REGION_OFF}" --size "${LAT_SIZE}" --stride "${LAT_STRIDE}" --iters "${LAT_ITERS}" --csv
}

if [[ -n "${SHM_PATH}" && -e "${SHM_PATH}" ]]; then
  MAP_SIZE="$(stat -c '%s' "${SHM_PATH}" 2>/dev/null || true)"
  if [[ -n "${MAP_SIZE}" && "${MAP_SIZE}" != "0" ]]; then
    set +e
    try_shm_run "${SHM_PATH}" "${MAP_OFFSET}" "${MAP_SIZE}"
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then
      echo "[!] resource2 mmap failed; will try UIO fallback." >&2
      SHM_PATH=""
    fi
  else
    echo "[!] Could not stat BAR2 size; will try UIO fallback." >&2
    SHM_PATH=""
  fi
else
  SHM_PATH=""
fi

if [[ -z "${SHM_PATH}" ]]; then
  echo
  echo "[*] Binding ivshmem to UIO (fallback) ..."
  if [[ -x /mnt/hostshare/guest/bind_ivshmem_uio.sh ]]; then
    bash /mnt/hostshare/guest/bind_ivshmem_uio.sh >/dev/null
  else
    echo "[!] Missing /mnt/hostshare/guest/bind_ivshmem_uio.sh" >&2
    exit 1
  fi

  UIO_DEV="$(ls -1 /dev/uio* 2>/dev/null | head -n 1 || true)"
  if [[ -z "${UIO_DEV}" ]]; then
    echo "[!] No /dev/uioX found after binding ivshmem." >&2
    exit 1
  fi

  uio_name="$(basename "${UIO_DEV}")"
  best_idx=-1
  best_size=0
  for map in /sys/class/uio/"${uio_name}"/maps/map*; do
    [[ -f "${map}/size" ]] || continue
    idx="${map##*/map}"
    size_raw="$(cat "${map}/size")"
    size_dec=$((size_raw))
    if (( size_dec > best_size )); then
      best_size="${size_dec}"
      best_idx="${idx}"
    fi
  done
  if (( best_idx < 0 )) || (( best_size == 0 )); then
    echo "[!] Failed to find UIO map sizes for ${UIO_DEV}" >&2
    exit 1
  fi

  page_size="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
  MAP_OFFSET=$((best_idx * page_size))
  MAP_SIZE="${best_size}"
  try_shm_run "${UIO_DEV}" "${MAP_OFFSET}" "${MAP_SIZE}"
fi

echo
echo "[*] Intel MLC (optional)"
if [[ -x "${MLC_BIN}" ]]; then
  echo "    Using MLC_BIN=${MLC_BIN}"
elif command -v mlc >/dev/null 2>&1; then
  MLC_BIN="$(command -v mlc)"
  echo "    Using mlc from PATH: ${MLC_BIN}"
else
  echo "    MLC not found. Put it at tests/tdx_mlc_latency/mlc/mlc or set MLC_BIN=..."
  exit 0
fi

set +e
help_out="$("${MLC_BIN}" --help 2>&1)"
rc=$?
set -e
if [[ "${rc}" -ne 0 ]]; then
  echo "[!] mlc --help failed (rc=${rc}); printing output:" >&2
  printf '%s\n' "${help_out}" >&2
else
  printf '%s\n' "${help_out}" | head -n 40 || true
fi

run_mlc_if_supported() {
  local flag="$1"; shift
  local extra=("$@")
  if printf '%s' "${help_out}" | grep -q -- "${flag}"; then
    echo
    echo "[*] Running: mlc ${flag} ${extra[*]}"
    set +e
    "${MLC_BIN}" "${flag}" "${extra[@]}"
    local rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then
      echo "[!] mlc ${flag} failed (rc=${rc})" >&2
    fi
  else
    echo "[*] mlc does not advertise ${flag}; skipping."
  fi
}

read -r -a idle_extra <<< "${MLC_IDLE_ARGS}"
run_mlc_if_supported "--idle_latency" "${idle_extra[@]}"

if command -v nproc >/dev/null 2>&1 && [[ "$(nproc)" -lt 2 ]]; then
  echo "[*] Skipping mlc --loaded_latency (need >=2 CPUs to exclude core0 safely)."
  exit 0
fi
read -r -a loaded_extra <<< "${MLC_LOADED_ARGS}"
run_mlc_if_supported "--loaded_latency" "${loaded_extra[@]}"
