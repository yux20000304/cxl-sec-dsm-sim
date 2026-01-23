#!/usr/bin/env bash
set -euo pipefail

# Host-side harness:
# - boots 2 TDX VMs with ivshmem enabled
# - runs tests/tdx_mlc_latency/vm_run.sh inside each guest
# - writes logs to results/

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

RESULTS_DIR="${ROOT}/results"
mkdir -p "${RESULTS_DIR}"

VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"

TDX_BIOS="${TDX_BIOS:-/usr/share/ovmf/OVMF.fd}"
if [[ ! -f "${TDX_BIOS}" ]]; then
  for c in \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/OVMF/OVMF.fd \
    /usr/share/ovmf/OVMF.tdx.fd \
    /usr/share/OVMF/OVMF.tdx.fd; do
    if [[ -f "${c}" ]]; then
      TDX_BIOS="${c}"
      break
    fi
  done
fi

# Use a dedicated shared backing file for this test (avoid clobbering other runs).
CXL_PATH="${CXL_PATH:-/dev/shm/cxl-sec-dsm-sim-mlc.raw}"
CXL_SIZE="${CXL_SIZE:-4G}"

BASE_IMG="${BASE_IMG:-}"
if [[ -z "${BASE_IMG}" ]]; then
  if [[ -f "${ROOT}/infra/images/tdx-guest-ubuntu-24.04-generic.qcow2" ]]; then
    BASE_IMG="${ROOT}/infra/images/tdx-guest-ubuntu-24.04-generic.qcow2"
  elif [[ -f "${ROOT}/infra/images/.base_img_path" ]]; then
    BASE_IMG="$(cat "${ROOT}/infra/images/.base_img_path" || true)"
  fi
fi

# If BASE_IMG is still unset, let scripts/host_quickstart.sh auto-download a
# Ubuntu cloud image (DOWNLOAD_BASE_IMG=1 by default there).
if [[ -n "${BASE_IMG}" && ! -f "${BASE_IMG}" ]]; then
  echo "[!] BASE_IMG is set but not found: ${BASE_IMG}" >&2
  exit 1
fi

TDX_ENABLE="${TDX_ENABLE:-1}" # 1=try TDX guests; 0=plain KVM guests
TDX_REQUIRED="${TDX_REQUIRED:-0}" # 1=fail if TDX is unavailable

if [[ "${TDX_ENABLE}" == "1" ]]; then
  if ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
    echo "[!] QEMU_BIN not found: ${QEMU_BIN}" >&2
    exit 1
  fi
  if ! "${QEMU_BIN}" -object help 2>/dev/null | grep -q 'tdx-guest'; then
    if [[ "${TDX_REQUIRED}" == "1" ]]; then
      echo "[!] TDX_REQUIRED=1 but QEMU lacks 'tdx-guest' support." >&2
      echo "    QEMU_BIN=${QEMU_BIN}" >&2
      exit 1
    fi
    echo "[!] QEMU lacks 'tdx-guest' support; falling back to non-TDX VMs (TDX_ENABLE=0)." >&2
    echo "    To require TDX, set TDX_REQUIRED=1 and use a TDX-enabled QEMU build." >&2
    TDX_ENABLE=0
  fi
fi

tmpdir="$(mktemp -d /tmp/cxl-sec-dsm-sim-mlc.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

sshkey="${tmpdir}/vm_sshkey"
ssh-keygen -t ed25519 -N "" -f "${sshkey}" -q

SSH_USER="${SSH_USER:-ubuntu}"
SSH_PASS="${SSH_PASS:-ubuntu}"
SSH_AUTH_MODE="${SSH_AUTH_MODE:-auto}" # auto|key|pass

ssh_key_opts=(
  -i "${sshkey}"
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o ConnectionAttempts=1
  -o ConnectTimeout=5
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_pass_opts=(
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectionAttempts=1
  -o ConnectTimeout=5
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ensure_sshpass() {
  if command -v sshpass >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    echo "[*] Installing sshpass on host (for password SSH fallback) ..."
    env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    env DEBIAN_FRONTEND=noninteractive apt-get install -y sshpass >/dev/null 2>&1 || true
  fi
  command -v sshpass >/dev/null 2>&1
}

ssh_vm() {
  local port="$1"; shift
  if [[ "${SSH_AUTH_MODE}" == "pass" ]]; then
    ensure_sshpass || { echo "[!] sshpass not available for password SSH." >&2; return 1; }
    sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "$@"
    return $?
  fi

  # key / auto: try key once; on failure, fall back to password (auto only).
  set +e
  ssh "${ssh_key_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "$@"
  local rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${SSH_AUTH_MODE}" == "key" ]]; then
    return "${rc}"
  fi

  ensure_sshpass || { echo "[!] sshpass not available for password SSH." >&2; return "${rc}"; }
  sshpass -p "${SSH_PASS}" ssh "${ssh_pass_opts[@]}" -p "${port}" "${SSH_USER}"@127.0.0.1 "$@"
}

wait_ssh() {
  local name="$1"
  local port="$2"
  echo "[*] Waiting for ${name} SSH on 127.0.0.1:${port} ..."
  for _ in $(seq 1 180); do
    if ssh_vm "${port}" true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

echo "[*] Booting 2 TDX VMs with ivshmem (CXL_PATH=${CXL_PATH}, CXL_SIZE=${CXL_SIZE}) ..."

FULL_CLONE="${FULL_CLONE:-}"
if [[ -z "${FULL_CLONE}" && "${BASE_IMG}" == *.qcow2 ]]; then
  FULL_CLONE=1
fi

STOP_EXISTING="${STOP_EXISTING:-1}"
FORCE_RECREATE="${FORCE_RECREATE:-0}"

VM_TDX_ENABLE="${TDX_ENABLE}" TDX_ATTACH_IVSHMEM=1 \
TDX_BIOS="${TDX_BIOS}" \
BASE_IMG="${BASE_IMG}" \
CXL_PATH="${CXL_PATH}" CXL_SIZE="${CXL_SIZE}" \
VM1_SSH="${VM1_SSH}" VM2_SSH="${VM2_SSH}" \
FULL_CLONE="${FULL_CLONE:-0}" \
STOP_EXISTING="${STOP_EXISTING}" FORCE_RECREATE="${FORCE_RECREATE}" \
CLOUD_INIT_SSH_KEY_FILE="${sshkey}.pub" \
bash "${ROOT}/scripts/host_quickstart.sh" >/dev/null

wait_ssh vm1 "${VM1_SSH}" || { echo "[!] vm1 SSH not ready" >&2; exit 1; }
wait_ssh vm2 "${VM2_SSH}" || { echo "[!] vm2 SSH not ready" >&2; exit 1; }

mount_hostshare_cmd='sudo mkdir -p /mnt/hostshare && (mountpoint -q /mnt/hostshare || sudo mount -t 9p -o trans=virtio,access=any,cache=none,msize=262144 hostshare /mnt/hostshare)'
ssh_vm "${VM1_SSH}" "${mount_hostshare_cmd}" >/dev/null
ssh_vm "${VM2_SSH}" "${mount_hostshare_cmd}" >/dev/null

ts="$(date +%Y%m%d_%H%M%S)"
out_vm1="${RESULTS_DIR}/tdx_mlc_latency_vm1_${ts}.log"
out_vm2="${RESULTS_DIR}/tdx_mlc_latency_vm2_${ts}.log"

guest_env=()
for v in LAT_SIZE LAT_STRIDE LAT_ITERS LAT_SHM_REGION_OFF LAT_CPU LAT_SHM_PATH MLC_BIN; do
  if [[ -n "${!v:-}" ]]; then
    guest_env+=("${v}=${!v}")
  fi
done

echo "[*] Running latency tests in vm1 ..."
ssh_vm "${VM1_SSH}" "sudo -E env ${guest_env[*]} bash /mnt/hostshare/tests/tdx_mlc_latency/vm_run.sh" 2>&1 | tee "${out_vm1}"

echo "[*] Running latency tests in vm2 ..."
ssh_vm "${VM2_SSH}" "sudo -E env ${guest_env[*]} bash /mnt/hostshare/tests/tdx_mlc_latency/vm_run.sh" 2>&1 | tee "${out_vm2}"

echo "[+] Done:"
echo "    ${out_vm1}"
echo "    ${out_vm2}"
