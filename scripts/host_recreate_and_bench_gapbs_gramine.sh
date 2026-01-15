#!/usr/bin/env bash
set -euo pipefail

# Recreate VM1/VM2 from a fresh Ubuntu cloud image (prefer 24.04 "noble"),
# then run GAPBS benchmarks in VM1:
# 1) GAPBS native (no Gramine)
# 2) GAPBS native under Gramine (direct mode)
# 3) GAPBS ring under Gramine (direct mode, shared memory via ivshmem BAR2)
#
# Usage:
#   sudo bash scripts/host_recreate_and_bench_gapbs_gramine.sh
#
# Tunables (env):
#   BASE_IMG      : path to ubuntu-24.04-server-cloudimg-amd64.img (optional)
#   VM1_SSH/VM2_SSH: ssh forwarded ports (default: 2222/2223)
#   GAPBS_KERNEL  : bfs|cc|pr|... (default: bfs)
#   SCALE         : -g scale for Kronecker graph (default: 18)
#   DEGREE        : -k degree for synthetic graph (default: 16)
#   TRIALS        : -n trials (default: 3)
#   OMP_THREADS   : OMP_NUM_THREADS (default: 4)
#   RING_PATH     : BAR2 resource file (default: /sys/bus/pci/devices/0000:00:02.0/resource2)
#   RING_MAP_SIZE : mmap size in bytes (default: 134217728 = 128MB)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"

GAPBS_KERNEL="${GAPBS_KERNEL:-bfs}"
SCALE="${SCALE:-18}"
DEGREE="${DEGREE:-16}"
TRIALS="${TRIALS:-3}"
OMP_THREADS="${OMP_THREADS:-4}"

RING_PATH="${RING_PATH:-/sys/bus/pci/devices/0000:00:02.0/resource2}"
RING_MAP_SIZE="${RING_MAP_SIZE:-134217728}"

BASE_IMG="${BASE_IMG:-}"

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-gapbs-gramine.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

sshkey="${tmpdir}/vm_sshkey"
ssh-keygen -t ed25519 -N "" -f "${sshkey}" -q

ssh_opts=(
  -i "${sshkey}"
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_vm1() { ssh "${ssh_opts[@]}" -p "${VM1_SSH}" ubuntu@127.0.0.1 "$@"; }
ssh_vm2() { ssh "${ssh_opts[@]}" -p "${VM2_SSH}" ubuntu@127.0.0.1 "$@"; }

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

wait_ssh() {
  local name="$1"
  local port="$2"
  echo "[*] Waiting for ${name} SSH on 127.0.0.1:${port} ..."
  for _ in $(seq 1 300); do
    if ssh "${ssh_opts[@]}" -p "${port}" ubuntu@127.0.0.1 "true" >/dev/null 2>&1; then
      echo "    ${name} SSH ready."
      return 0
    fi
    sleep 1
  done
  echo "[!] Timeout waiting for ${name} SSH." >&2
  return 1
}

base_desc="${BASE_IMG:-auto (download Ubuntu 24.04 if missing)}"
echo "[*] Recreating VMs (BASE_IMG=${base_desc})"
STOP_EXISTING=1 FORCE_RECREATE=1 BASE_IMG="${BASE_IMG}" \
VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
bash "${ROOT}/scripts/host_quickstart.sh"

wait_ssh "vm1" "${VM1_SSH}"
wait_ssh "vm2" "${VM2_SSH}"

echo "[*] Waiting for cloud-init to finish (avoids apt/dpkg locks) ..."
ssh_vm1 "sudo timeout 300 cloud-init status --wait >/dev/null 2>&1 || true"
ssh_vm2 "sudo timeout 300 cloud-init status --wait >/dev/null 2>&1 || true"

mount_hostshare='
sudo mkdir -p /mnt/hostshare
if ! mountpoint -q /mnt/hostshare; then
  sudo mount -t 9p -o trans=virtio hostshare /mnt/hostshare
fi
'
ssh_vm1 "${mount_hostshare}"
ssh_vm2 "${mount_hostshare}"

echo "[*] Installing dependencies in vm1 ..."
ssh_retry_lock ssh_vm1 "vm1 apt-get update" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install deps" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates curl lsb-release pkg-config"

echo "[*] Installing Gramine in vm1 (direct mode) ..."
ssh_vm1 '
set -e
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg https://packages.gramineproject.io/gramine-keyring-$(lsb_release -sc).gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/gramine.list >/dev/null
'
ssh_retry_lock ssh_vm1 "vm1 apt-get update (gramine repo)" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update"
ssh_retry_lock ssh_vm1 "vm1 apt-get install gramine" "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y gramine"

echo "[*] Building GAPBS (native + ring) in vm1 ..."
ssh_vm1 "cd /mnt/hostshare/gapbs && sudo make clean && sudo make -j2 all ring"

echo "[*] Building Gramine manifests for GAPBS in vm1 ..."
ssh_vm1 "cd /mnt/hostshare/gramine && sudo make links gapbs-native.manifest gapbs-ring.manifest GAPBS_KERNEL='${GAPBS_KERNEL}' CXL_RING_PATH='${RING_PATH}' CXL_RING_MAP_SIZE='${RING_MAP_SIZE}'"

ts="$(date +%Y%m%d_%H%M%S)"
plain_log="${RESULTS_DIR}/gapbs_plain_${GAPBS_KERNEL}_${ts}.log"
native_log="${RESULTS_DIR}/gapbs_gramine_native_${GAPBS_KERNEL}_${ts}.log"
ring_log="${RESULTS_DIR}/gapbs_gramine_ring_${GAPBS_KERNEL}_${ts}.log"
compare_csv="${RESULTS_DIR}/gapbs_gramine_compare_${GAPBS_KERNEL}_${ts}.csv"

echo "[*] Benchmark 1/3: GAPBS native (no Gramine) in vm1"
ssh_vm1 "cd /mnt/hostshare/gapbs && OMP_NUM_THREADS='${OMP_THREADS}' ./'${GAPBS_KERNEL}' -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" | tee "${plain_log}"

echo "[*] Benchmark 2/3: GAPBS native under Gramine (direct) in vm1"
ssh_vm1 "cd /mnt/hostshare/gramine && OMP_NUM_THREADS='${OMP_THREADS}' gramine-direct ./gapbs-native -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" | tee "${native_log}"

echo "[*] Benchmark 3/3: GAPBS ring under Gramine (direct) in vm1"
ssh_vm1 "cd /mnt/hostshare/gramine && sudo env OMP_NUM_THREADS='${OMP_THREADS}' GAPBS_CXL_PATH='${RING_PATH}' GAPBS_CXL_MAP_SIZE='${RING_MAP_SIZE}' gramine-direct ./gapbs-ring -g '${SCALE}' -k '${DEGREE}' -n '${TRIALS}'" | tee "${ring_log}"

plain_avg="$(awk '/^Average Time:/{print $3; exit}' "${plain_log}" || true)"
native_avg="$(awk '/^Average Time:/{print $3; exit}' "${native_log}" || true)"
ring_avg="$(awk '/^Average Time:/{print $3; exit}' "${ring_log}" || true)"

{
  echo "label,kernel,scale,degree,trials,omp_threads,avg_time_s"
  echo "Plain,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${plain_avg}"
  echo "GramineDirectNative,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${native_avg}"
  echo "GramineDirectRing,${GAPBS_KERNEL},${SCALE},${DEGREE},${TRIALS},${OMP_THREADS},${ring_avg}"
} > "${compare_csv}"

echo "[+] Done."
echo "    ${plain_log}"
echo "    ${native_log}"
echo "    ${ring_log}"
echo "    ${compare_csv}"

