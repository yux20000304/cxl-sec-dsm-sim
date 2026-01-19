#!/usr/bin/env bash
set -euo pipefail

# One-stop host launcher:
# 1) Create shared CXL file if missing
# 2) Create VM disks + cloud-init seeds if missing
# 3) Launch both VMs with ivshmem sharing + SSH port forwards
#
# Requirements on host: qemu-system-x86, qemu-utils, cloud-localds, numactl (optional), curl (or wget for download)
#
# Usage:
#   BASE_IMG=/path/to/ubuntu-24.04-server-cloudimg-amd64.img \
#   bash scripts/host_quickstart.sh
#
# Tunables (env):
#   BASE_IMG      : path to Ubuntu cloud image (optional if auto-detected)
#   DOWNLOAD_BASE_IMG: 1 to auto-download Ubuntu 24.04 image if missing (default: 1)
#   BASE_IMG_URL  : override download URL (default: Ubuntu 24.04 cloud image)
#   MIRROR_DIR    : download/cache dir for base images (default: ../mirror)
#   OUTDIR        : where to place qcow2/seed images (default: infra/images)
#   CXL_PATH      : shared backing file (default: /tmp/cxl_shared.raw)
#   CXL_SIZE      : size of shared file (default: 4G)
#   VM1_SSH       : host SSH port for VM1 (default: 2222)
#   VM2_SSH       : host SSH port for VM2 (default: 2223)
#   VM1_MEM/VM2_MEM (default: 4G)
#   VM1_CPUS/VM2_CPUS (default: 4)
#   HOSTSHARE     : path to share into guest via 9p (default: repo root)
#   VM1_CPU_NODE/VM2_CPU_NODE/CXL_MEM_NODE : optional numactl binding
#   FORCE_RECREATE: 1 to recreate qcow2 + seed images (default: 0)
#   STOP_EXISTING : 1 to stop existing VMs automatically when recreating (default: 0)
#   CLOUD_INIT_SSH_KEY_FILE: path to an SSH public key to inject into cloud-init

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA="${ROOT}/infra"

FORCE_RECREATE="${FORCE_RECREATE:-0}"
STOP_EXISTING="${STOP_EXISTING:-0}"
CLOUD_INIT_SSH_KEY_FILE="${CLOUD_INIT_SSH_KEY_FILE:-}"
BASE_IMG="${BASE_IMG:-}"
DOWNLOAD_BASE_IMG="${DOWNLOAD_BASE_IMG:-1}"
BASE_IMG_URL="${BASE_IMG_URL:-https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img}"
OUTDIR="${OUTDIR:-${INFRA}/images}"
CXL_PATH="${CXL_PATH:-/tmp/cxl_shared.raw}"
CXL_SIZE="${CXL_SIZE:-4G}"
VM1_SSH="${VM1_SSH:-2222}"
VM2_SSH="${VM2_SSH:-2223}"
VM1_MEM="${VM1_MEM:-4G}"
VM2_MEM="${VM2_MEM:-4G}"
VM1_CPUS="${VM1_CPUS:-4}"
VM2_CPUS="${VM2_CPUS:-4}"
HOSTSHARE="${HOSTSHARE:-${ROOT}}"

MIRROR_DIR="${MIRROR_DIR:-${ROOT}/../mirror}"
DEFAULT_NOBLE_IMG="${MIRROR_DIR}/ubuntu-24.04-server-cloudimg-amd64.img"
DEFAULT_JAMMY_IMG="${MIRROR_DIR}/jammy-server-cloudimg-amd64.img"

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

default_vm_state_dir() {
  if [[ -n "${VM_STATE_DIR:-}" ]]; then
    echo "${VM_STATE_DIR}"
  elif [[ "${EUID}" -eq 0 ]]; then
    echo "/tmp"
  else
    echo "/tmp/cxl-sec-dsm-sim-${UID}"
  fi
}

VM_STATE_DIR="$(default_vm_state_dir)"
export VM_STATE_DIR

download_file() {
  local url="$1"
  local out="$2"
  local tmp="${out}.part"

  mkdir -p "$(dirname "${out}")"

  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 5 --retry-delay 2 -C - -o "${tmp}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${tmp}" "${url}"
  else
    echo "[!] Need curl or wget to download base image." >&2
    return 1
  fi

  mv -f "${tmp}" "${out}"
  chmod 644 "${out}" || true
  if [[ ! -s "${out}" ]]; then
    echo "[!] Downloaded base image is empty: ${out}" >&2
    return 1
  fi
}

if [[ -z "${BASE_IMG}" ]]; then
  if [[ -f "${DEFAULT_NOBLE_IMG}" ]]; then
    BASE_IMG="${DEFAULT_NOBLE_IMG}"
  elif [[ -f "${DEFAULT_JAMMY_IMG}" ]]; then
    BASE_IMG="${DEFAULT_JAMMY_IMG}"
  elif [[ "${DOWNLOAD_BASE_IMG}" == "1" ]]; then
    echo "[*] Base image not found; downloading Ubuntu 24.04 cloud image..."
    echo "    url:  ${BASE_IMG_URL}"
    echo "    path: ${DEFAULT_NOBLE_IMG}"
    download_file "${BASE_IMG_URL}" "${DEFAULT_NOBLE_IMG}"
    BASE_IMG="${DEFAULT_NOBLE_IMG}"
  fi
fi

if [[ -z "${BASE_IMG}" ]]; then
  echo "[!] Please set BASE_IMG to Ubuntu cloud image path (e.g. ubuntu-24.04-server-cloudimg-amd64.img)" >&2
  echo "    Or rerun with DOWNLOAD_BASE_IMG=1 to auto-download Ubuntu 24.04." >&2
  exit 1
fi
if [[ ! -f "${BASE_IMG}" ]]; then
  if [[ "${DOWNLOAD_BASE_IMG}" == "1" ]]; then
    echo "[*] BASE_IMG not found; downloading Ubuntu 24.04 cloud image..."
    echo "    url:  ${BASE_IMG_URL}"
    echo "    path: ${BASE_IMG}"
    download_file "${BASE_IMG_URL}" "${BASE_IMG}"
  else
    echo "[!] BASE_IMG not found: ${BASE_IMG}" >&2
    exit 1
  fi
fi

mkdir -p "${OUTDIR}"

echo "[1/3] Shared CXL backing file..."
if [[ ! -f "${CXL_PATH}" ]]; then
  bash "${INFRA}/create_cxl_shared.sh" "${CXL_PATH}" "${CXL_SIZE}"
else
  cur_size="$(stat -c '%s' "${CXL_PATH}" 2>/dev/null || true)"
  req_size="$(size_to_bytes "${CXL_SIZE}" 2>/dev/null || true)"
  if [[ -n "${cur_size}" && -n "${req_size}" && "${cur_size}" -lt "${req_size}" ]]; then
    echo "    grow ${CXL_PATH} from ${cur_size} bytes to ${CXL_SIZE}"
    truncate -s "${CXL_SIZE}" "${CXL_PATH}"
  else
    echo "    reuse ${CXL_PATH}"
  fi
fi

echo "[2/3] VM disks + cloud-init seeds..."
stamp="${OUTDIR}/.base_img_path"
old_base=""
if [[ -f "${stamp}" ]]; then
  old_base="$(cat "${stamp}" || true)"
fi
echo "    base image: ${BASE_IMG}"

vm_running=0
for name in vm1 vm2; do
  pidfile="${VM_STATE_DIR}/${name}.pid"
  if [[ -f "${pidfile}" ]]; then
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      vm_running=1
    fi
  fi
done

need_recreate_disks=0
need_recreate_seeds=0

if [[ "${FORCE_RECREATE}" == "1" ]]; then
  need_recreate_disks=1
  need_recreate_seeds=1
elif [[ -n "${old_base}" && "${old_base}" != "${BASE_IMG}" ]]; then
  need_recreate_disks=1
else
  # If the stamp is missing (or empty), try to infer the backing file from qcow2.
  # This also works when the image is currently in use (qemu-img -U).
  if [[ -z "${old_base}" && -f "${OUTDIR}/vm1.qcow2" && -f "${OUTDIR}/vm2.qcow2" ]] && command -v qemu-img >/dev/null 2>&1; then
    backing1="$(qemu-img info -U "${OUTDIR}/vm1.qcow2" 2>/dev/null | sed -n 's/^backing file: //p' | head -n 1 || true)"
    backing2="$(qemu-img info -U "${OUTDIR}/vm2.qcow2" 2>/dev/null | sed -n 's/^backing file: //p' | head -n 1 || true)"
    if [[ -n "${backing1}" && "${backing1}" != "${BASE_IMG}" ]]; then
      need_recreate_disks=1
    fi
    if [[ -n "${backing2}" && "${backing2}" != "${BASE_IMG}" ]]; then
      need_recreate_disks=1
    fi
  fi
fi

  if [[ "${need_recreate_disks}" == "1" || "${need_recreate_seeds}" == "1" ]]; then
    if [[ "${vm_running}" == "1" ]]; then
      if [[ "${STOP_EXISTING}" != "1" ]]; then
        echo "[!] VMs appear to be running; stop them before recreating images." >&2
      echo "    Hint: sudo kill -9 \$(cat '${VM_STATE_DIR}/vm1.pid') \$(cat '${VM_STATE_DIR}/vm2.pid')  # then rerun" >&2
      echo "    Or:  sudo env STOP_EXISTING=1 FORCE_RECREATE=1 VM_STATE_DIR='${VM_STATE_DIR}' bash scripts/host_quickstart.sh" >&2
        exit 1
      fi

      echo "[*] STOP_EXISTING=1: stopping running VMs (vm1/vm2)"
      for name in vm1 vm2; do
      pidfile="${VM_STATE_DIR}/${name}.pid"
        if [[ -f "${pidfile}" && ! -r "${pidfile}" ]]; then
          echo "[!] Cannot read ${pidfile}; please run this script with sudo." >&2
          exit 1
        fi
    done

      for name in vm1 vm2; do
      pidfile="${VM_STATE_DIR}/${name}.pid"
        pid="$(cat "${pidfile}" 2>/dev/null || true)"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
          echo "    SIGTERM ${name} pid=${pid}"
          kill "${pid}" 2>/dev/null || true
      fi
    done

      for _ in $(seq 1 20); do
        still=0
        for name in vm1 vm2; do
        pidfile="${VM_STATE_DIR}/${name}.pid"
          pid="$(cat "${pidfile}" 2>/dev/null || true)"
          if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            still=1
          fi
      done
      [[ "${still}" == "0" ]] && break
      sleep 1
    done

      for name in vm1 vm2; do
      pidfile="${VM_STATE_DIR}/${name}.pid"
        pid="$(cat "${pidfile}" 2>/dev/null || true)"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
          echo "    SIGKILL ${name} pid=${pid}"
          kill -9 "${pid}" 2>/dev/null || true
        fi
      done

    rm -f "${VM_STATE_DIR}/vm1.pid" "${VM_STATE_DIR}/vm2.pid" "${VM_STATE_DIR}/vm1.monitor" "${VM_STATE_DIR}/vm2.monitor" || true
    fi
  if [[ "${FORCE_RECREATE}" == "1" ]]; then
    echo "    FORCE_RECREATE=1: removing existing qcow2 + seed images"
  else
    echo "    base image changed/unknown; recreating qcow2 disks"
  fi
  rm -f "${OUTDIR}/vm1.qcow2" "${OUTDIR}/vm2.qcow2"
  if [[ "${need_recreate_seeds}" == "1" ]]; then
    rm -f "${OUTDIR}/seed-vm1.img" "${OUTDIR}/seed-vm2.img"
  fi
fi

if [[ ! -f "${OUTDIR}/vm1.qcow2" || ! -f "${OUTDIR}/vm2.qcow2" ]]; then
  bash "${INFRA}/create_vm_images.sh" --base "${BASE_IMG}" --outdir "${OUTDIR}" --vm1 vm1.qcow2 --vm2 vm2.qcow2
else
  echo "    reuse ${OUTDIR}/vm1.qcow2, vm2.qcow2"
fi
if [[ ! -f "${OUTDIR}/seed-vm1.img" || ! -f "${OUTDIR}/seed-vm2.img" ]]; then
  args=(--outdir "${OUTDIR}")
  if [[ -n "${CLOUD_INIT_SSH_KEY_FILE}" ]]; then
    args+=(--ssh-key "${CLOUD_INIT_SSH_KEY_FILE}")
  fi
  bash "${INFRA}/create_cloud_init.sh" "${args[@]}"
else
  echo "    reuse ${OUTDIR}/seed-vm1.img, seed-vm2.img"
fi

echo "${BASE_IMG}" > "${stamp}"

echo "[3/3] Launching VMs..."

# Allow SKIP_SEED=1 to skip attaching cloud-init seed (e.g. for TD images built by canonical/tdx tools).
SKIP_SEED="${SKIP_SEED:-0}"
if [[ "${SKIP_SEED}" == "1" ]]; then
  bash "${INFRA}/run_vms.sh" \
    --cxl "${CXL_PATH}" --cxl-size "${CXL_SIZE}" \
    --vm1-disk "${OUTDIR}/vm1.qcow2" \
    --vm2-disk "${OUTDIR}/vm2.qcow2" \
    --vm1-ssh "${VM1_SSH}" --vm2-ssh "${VM2_SSH}" \
    --vm1-mem "${VM1_MEM}" --vm2-mem "${VM2_MEM}" \
    --vm1-cpus "${VM1_CPUS}" --vm2-cpus "${VM2_CPUS}" \
    --hostshare "${HOSTSHARE}"
else
  bash "${INFRA}/run_vms.sh" \
    --cxl "${CXL_PATH}" --cxl-size "${CXL_SIZE}" \
    --vm1-disk "${OUTDIR}/vm1.qcow2" --vm1-seed "${OUTDIR}/seed-vm1.img" \
    --vm2-disk "${OUTDIR}/vm2.qcow2" --vm2-seed "${OUTDIR}/seed-vm2.img" \
    --vm1-ssh "${VM1_SSH}" --vm2-ssh "${VM2_SSH}" \
    --vm1-mem "${VM1_MEM}" --vm2-mem "${VM2_MEM}" \
    --vm1-cpus "${VM1_CPUS}" --vm2-cpus "${VM2_CPUS}" \
    --hostshare "${HOSTSHARE}"
fi

echo "[+] Done. SSH:"
echo "    VM1: ssh ubuntu@127.0.0.1 -p ${VM1_SSH}"
echo "    VM2: ssh ubuntu@127.0.0.1 -p ${VM2_SSH}"
