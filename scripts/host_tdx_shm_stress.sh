#!/usr/bin/env bash
set -euo pipefail

# Stress/bench test for the TDX shared-memory transport in tdx_shm/.
# - Initializes a host-backed shared file
# - Launches 2 TDX guests with ivshmem-plain backed by that file
# - Runs a timed ping-pong benchmark over the *new* shared-memory layout

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

SHM_PATH="${SHM_PATH:-/dev/shm/cxl-sec-dsm-sim-tdx-shm}"
SHM_SIZE="${SHM_SIZE:-16M}"

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"

TDX_BIOS="${TDX_BIOS:-/usr/share/ovmf/OVMF.fd}"

BASE_IMG="${BASE_IMG:-}"
if [[ -z "${BASE_IMG}" ]]; then
  if [[ -f "${ROOT}/infra/images/tdx-guest-ubuntu-24.04-generic.qcow2" ]]; then
    BASE_IMG="${ROOT}/infra/images/tdx-guest-ubuntu-24.04-generic.qcow2"
  elif [[ -f "${ROOT}/infra/images/.base_img_path" ]]; then
    BASE_IMG="$(cat "${ROOT}/infra/images/.base_img_path" || true)"
  fi
fi

if [[ -z "${BASE_IMG}" ]]; then
  echo "[!] BASE_IMG not set and no default found." >&2
  echo "    Set BASE_IMG=/path/to/ubuntu-image.img (or a TDX guest qcow2) and rerun." >&2
  exit 1
fi

stop_vm_if_running() {
  local name="$1"
  local pidfile="/tmp/${name}.pid"
  if [[ -f "${pidfile}" ]]; then
    local pid
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      echo "[*] Stopping ${name} (pid=${pid})"
      kill "${pid}" 2>/dev/null || true
      sleep 1
      if kill -0 "${pid}" 2>/dev/null; then
        kill -9 "${pid}" 2>/dev/null || true
      fi
    fi
    rm -f "/tmp/${name}.pid" "/tmp/${name}.monitor" "/tmp/${name}.log" 2>/dev/null || true
  fi
}

echo "[*] Building tdx_shm tools ..."
make -C "${ROOT}/tdx_shm" >/dev/null

echo "[*] Initializing shared memory file: ${SHM_PATH} (${SHM_SIZE})"
"${ROOT}/tdx_shm/tdx_shm_init" --path "${SHM_PATH}" --size "${SHM_SIZE}" >/dev/null

stop_vm_if_running vm1
stop_vm_if_running vm2

echo "[*] Launching 2 TDX VMs (SSH: ${VM1_SSH}/${VM2_SSH}) ..."
FULL_CLONE="${FULL_CLONE:-}"
if [[ -z "${FULL_CLONE}" && "${BASE_IMG}" == *.qcow2 ]]; then
  FULL_CLONE=1
fi

VM_TDX_ENABLE=1 TDX_ATTACH_IVSHMEM=1 \
TDX_BIOS="${TDX_BIOS}" \
BASE_IMG="${BASE_IMG}" \
CXL_PATH="${SHM_PATH}" CXL_SIZE="${SHM_SIZE}" \
VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
FULL_CLONE="${FULL_CLONE:-0}" \
FORCE_RECREATE="${FORCE_RECREATE:-0}" STOP_EXISTING=0 \
bash "${ROOT}/scripts/host_quickstart.sh" >/dev/null

ssh_common_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR)

SSH_USER="${SSH_USER:-ubuntu}"
SSH_UBUNTU_PASS="${SSH_UBUNTU_PASS:-ubuntu}"

SSH_KEY_FILE="${SSH_KEY_FILE:-}"
if [[ -z "${SSH_KEY_FILE}" ]]; then
  if [[ -n "${SUDO_USER:-}" && -f "/home/${SUDO_USER}/.ssh/id_ed25519" ]]; then
    SSH_KEY_FILE="/home/${SUDO_USER}/.ssh/id_ed25519"
  elif [[ -f "/home/ubuntu/.ssh/id_ed25519" ]]; then
    SSH_KEY_FILE="/home/ubuntu/.ssh/id_ed25519"
  elif [[ -n "${SUDO_USER:-}" && -f "/home/${SUDO_USER}/.ssh/id_rsa" ]]; then
    SSH_KEY_FILE="/home/${SUDO_USER}/.ssh/id_rsa"
  elif [[ -f "/home/ubuntu/.ssh/id_rsa" ]]; then
    SSH_KEY_FILE="/home/ubuntu/.ssh/id_rsa"
  fi
fi

ssh_vm() {
  local port="$1"; shift
  local cmd="$*"
  if [[ -n "${SSH_KEY_FILE}" && -f "${SSH_KEY_FILE}" ]]; then
    ssh "${ssh_common_opts[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "${SSH_KEY_FILE}" -p "${port}" "${SSH_USER}"@127.0.0.1 "${cmd}"
  else
    ssh "${ssh_common_opts[@]}" -o BatchMode=yes -p "${port}" "${SSH_USER}"@127.0.0.1 "${cmd}"
  fi
}

ssh_vm_pass() {
  local port="$1"; shift
  local cmd="$*"
  sshpass -p "${SSH_UBUNTU_PASS}" ssh "${ssh_common_opts[@]}" -o PreferredAuthentications=password -o PubkeyAuthentication=no -p "${port}" "${SSH_USER}"@127.0.0.1 "${cmd}"
}

wait_ssh() {
  local name="$1"
  local port="$2"
  echo "[*] Waiting for ${name} SSH on 127.0.0.1:${port} ..."
  for _ in $(seq 1 120); do
    if ssh_vm "${port}" "true" >/dev/null 2>&1; then
      return 0
    fi
    if command -v sshpass >/dev/null 2>&1 && ssh_vm_pass "${port}" "true" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

wait_ssh vm1 "${VM1_SSH}" || { echo "[!] vm1 SSH not ready" >&2; exit 1; }
wait_ssh vm2 "${VM2_SSH}" || { echo "[!] vm2 SSH not ready" >&2; exit 1; }

mount_hostshare_cmd='sudo mkdir -p /mnt/hostshare && (mountpoint -q /mnt/hostshare || sudo mount -t 9p -o trans=virtio,access=any,cache=none,msize=262144 hostshare /mnt/hostshare)'
ssh_vm "${VM1_SSH}" "${mount_hostshare_cmd}" >/dev/null 2>&1 || ssh_vm_pass "${VM1_SSH}" "${mount_hostshare_cmd}" >/dev/null
ssh_vm "${VM2_SSH}" "${mount_hostshare_cmd}" >/dev/null 2>&1 || ssh_vm_pass "${VM2_SSH}" "${mount_hostshare_cmd}" >/dev/null

DURATION_S="${DURATION_S:-60}"
WARMUP="${WARMUP:-1000}"
SLEEP_US="${SLEEP_US:-0}"
MSG_SIZES="${MSG_SIZES:-64,240}"

RESULTS_DIR="${RESULTS_DIR:-${ROOT}/results/tdx_shm}"
ts="$(date +%Y%m%d_%H%M%S)"
out_dir="${RESULTS_DIR}/${ts}"
mkdir -p "${out_dir}"

echo "[*] Running TDX shm bench: duration=${DURATION_S}s warmup=${WARMUP} sleep_us=${SLEEP_US} msg_sizes=${MSG_SIZES}"

IFS=',' read -r -a sizes <<<"${MSG_SIZES}"
for sz in "${sizes[@]}"; do
  sz="$(echo "${sz}" | xargs)"
  [[ -z "${sz}" ]] && continue

  echo "[*] msg_size=${sz}B ..."
  server_cmd="sudo bash -lc 'nohup /mnt/hostshare/tdx_shm/tdx_shm_ping_pong --bench --id 1 --role server --timeout-ms 0 --sleep-us ${SLEEP_US} --quiet > /tmp/tdx_shm_server_bench.log 2>&1 & disown'"
  ssh_vm "${VM1_SSH}" "${server_cmd}" >/dev/null 2>&1 || ssh_vm_pass "${VM1_SSH}" "${server_cmd}" >/dev/null

  client_cmd="sudo /mnt/hostshare/tdx_shm/tdx_shm_ping_pong --bench --id 2 --role client --duration-s ${DURATION_S} --msg-size ${sz} --warmup ${WARMUP} --timeout-ms 5000 --sleep-us ${SLEEP_US}"
  set +e
  ssh_vm "${VM2_SSH}" "${client_cmd}" | tee "${out_dir}/bench_${sz}B.log"
  rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    ssh_vm_pass "${VM2_SSH}" "${client_cmd}" | tee "${out_dir}/bench_${sz}B.log"
    rc=$?
  fi
  set -e

  if [[ "${rc}" -ne 0 ]]; then
    echo "[!] bench failed for msg_size=${sz}B (rc=${rc}). Logs:" >&2
    ssh_vm_pass "${VM1_SSH}" "sudo tail -n 100 /tmp/tdx_shm_server_bench.log 2>/dev/null || true" >&2 || true
    exit "${rc}"
  fi
done

echo "[+] Results saved under: ${out_dir}"
if [[ -n "${SUDO_USER:-}" ]]; then
  chown -R "${SUDO_USER}:${SUDO_USER}" "${out_dir}" 2>/dev/null || true
fi
