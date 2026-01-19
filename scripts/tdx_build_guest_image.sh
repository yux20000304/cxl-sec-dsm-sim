#!/usr/bin/env bash
set -euo pipefail

# Build a TDX-enabled Ubuntu guest image (qcow2) using the canonical/tdx tools
# in this repo's tdx/ submodule. This follows tdx/README.md section 5
# (Create TD Image) and produces an image suitable for booting as a TD.
#
# Defaults:
# - Ubuntu Noble 24.04 guest
# - Generic kernel (set TDX_SETUP_INTEL_KERNEL=1 in tdx/setup-tdx-config to use -intel kernel)
# - Output: infra/images/tdx-guest-ubuntu-<ver>-generic.qcow2 (or -intel)
#
# Usage examples:
#   bash scripts/tdx_build_guest_image.sh                 # build 24.04 image
#   UBUNTU_VERSION=25.04 bash scripts/tdx_build_guest_image.sh
#   OUTPUT=infra/images/my-tdx-guest.qcow2 bash scripts/tdx_build_guest_image.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TDX_DIR="${ROOT}/tdx"
TDX_IMG_DIR="${TDX_DIR}/guest-tools/image"
OUTDIR="${ROOT}/infra/images"
mkdir -p "${OUTDIR}"

UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"

# Derive default output path based on kernel choice in setup-tdx-config
kernel_suffix="generic"
if grep -q '^\s*TDX_SETUP_INTEL_KERNEL\s*=\s*1\b' "${TDX_DIR}/setup-tdx-config" 2>/dev/null; then
  kernel_suffix="intel"
fi
OUTPUT="${OUTPUT:-${OUTDIR}/tdx-guest-ubuntu-${UBUNTU_VERSION}-${kernel_suffix}.qcow2}"

if [[ ! -d "${TDX_DIR}" ]]; then
  echo "[!] tdx submodule not found at ${TDX_DIR}. Initialize submodules first." >&2
  echo "    git submodule update --init --recursive" >&2
  exit 1
fi

if [[ -f "${OUTPUT}" ]]; then
  echo "[+] Reusing existing TD image: ${OUTPUT}"
  exit 0
fi

echo "[*] Building TD image via canonical/tdx tools ..."
echo "    Ubuntu: ${UBUNTU_VERSION}"
echo "    Output: ${OUTPUT}"

# Ensure libvirt daemon and default network are available for virt-install
ensure_libvirt() {
  if ! command -v virsh >/dev/null 2>&1; then
    echo "[*] Installing libvirt client tools (virsh) ..."
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y libvirt-clients >/dev/null 2>&1 || true
  fi

  if ! sudo systemctl is-active --quiet libvirtd; then
    echo "[*] Starting libvirtd service ..."
    sudo systemctl enable --now libvirtd >/dev/null 2>&1 || true
  fi

  # Ensure the default NAT network exists and is active
  if ! sudo virsh net-info default >/dev/null 2>&1; then
    if [[ -f /usr/share/libvirt/networks/default.xml ]]; then
      echo "[*] Defining libvirt default network ..."
      sudo virsh net-define /usr/share/libvirt/networks/default.xml >/dev/null 2>&1 || true
    fi
  fi
  if sudo virsh net-info default >/dev/null 2>&1; then
    if ! sudo virsh net-is-active default >/dev/null 2>&1; then
      echo "[*] Starting libvirt default network ..."
      sudo virsh net-start default >/dev/null 2>&1 || true
    fi
    sudo virsh net-autostart default >/dev/null 2>&1 || true
  fi
}

ensure_libvirt

set +e
sudo -E bash -lc "cd '${TDX_IMG_DIR}'; ./create-td-image.sh -v '${UBUNTU_VERSION}' -o '${OUTPUT}'"
rc=$?
set -e

if [[ "${rc}" -ne 0 || ! -f "${OUTPUT}" ]]; then
  echo "[!] create-td-image.sh did not complete; attempting fallback finalize on tmp image ..." >&2
  TMP_IMG="/tmp/tdx-guest-tmp.qcow2"
  if [[ ! -f "${TMP_IMG}" ]]; then
    echo "[!] Fallback failed: ${TMP_IMG} not found." >&2
    exit 1
  fi

  # Prepare a minimal netplan to ensure DHCP on first NIC (en*)
  tmpdir="$(mktemp -d /tmp/tdx-netplan.XXXXXX)"
  cat >"${tmpdir}/99-netcfg.yaml" <<'NP'
network:
  version: 2
  renderer: networkd
  ethernets:
    en:
      match:
        name: "en*"
      dhcp4: true
      dhcp-identifier: mac
NP

  # Inject setup scripts and enable SSH/password/root login, set root password, add netplan.
  sudo virt-customize -a "${TMP_IMG}" \
    --mkdir /tmp/tdx \
    --copy-in "${TDX_IMG_DIR}/setup.sh":/tmp/tdx/ \
    --copy-in "${TDX_DIR}/setup-tdx-guest.sh":/tmp/tdx/ \
    --copy-in "${TDX_DIR}/setup-tdx-common":/tmp/tdx \
    --copy-in "${TDX_DIR}/setup-tdx-config":/tmp/tdx \
    --copy-in "${TDX_DIR}/attestation/":/tmp/tdx \
    --copy-in "${TDX_DIR}/tests/lib/tdx-tools/":/tmp/tdx \
    --run-command "/tmp/tdx/setup.sh" \
    --run-command "sed -i '/^\s*KbdInteractiveAuthentication\b.*/d' /etc/ssh/sshd_config || true" \
    --run-command "rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf || true" \
    --run-command "mkdir -p /etc/systemd/system && ln -sf /dev/null /etc/systemd/system/systemd-networkd-wait-online.service || true" \
    --mkdir /etc/netplan \
    --copy-in "${tmpdir}/99-netcfg.yaml":/etc/netplan/ \
    --run-command "echo root:123456 | chpasswd"

  rm -rf "${tmpdir}" || true

  # Move into place as final OUTPUT
  sudo mv -f "${TMP_IMG}" "${OUTPUT}"
  sudo chmod a+rw "${OUTPUT}" || true
fi

if [[ -f "${OUTPUT}" ]]; then
  echo "[+] TD image ready: ${OUTPUT}"
else
  echo "[!] TD image build failed: ${OUTPUT} not found" >&2
  exit 1
fi
