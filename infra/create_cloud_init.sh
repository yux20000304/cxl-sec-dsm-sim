#!/usr/bin/env bash
set -euo pipefail

# Generate cloud-init seed images for VM1 / VM2.
# The default user is "ubuntu" with password "ubuntu" (ssh password enabled).
#
# Example:
#   bash infra/create_cloud_init.sh --outdir infra/images

usage() {
  cat >&2 <<'EOF'
Usage: create_cloud_init.sh --outdir <dir> [--ssh-key <pubkey_file> ...]

Options:
  --ssh-key <pubkey_file>  Add an SSH public key to ubuntu's authorized_keys.
                           May be specified multiple times. If omitted, the
                           script auto-detects common keys from the invoking
                           user (SUDO_USER when run via sudo, otherwise $HOME).
EOF
}

OUTDIR=""
SSH_KEY_FILES=()

PASSWORD="${PASSWORD:-ubuntu}"  # plaintext password; can override env PASSWORD
INSTALL_PACKAGES="${INSTALL_PACKAGES:-0}" # 1 = run apt via cloud-init (slower)

# Configure an internal VM-to-VM NIC (created by infra/run_vms.sh via QEMU socket netdev).
# This gives VM1/VM2 a stable direct TCP path without going through host SSH tunnels.
CXL_NET_ENABLE="${CXL_NET_ENABLE:-1}"
CXL_NET_VM1_IP="${CXL_NET_VM1_IP:-192.168.100.1}"
CXL_NET_VM2_IP="${CXL_NET_VM2_IP:-192.168.100.2}"
CXL_NET_VM1_MAC="${CXL_NET_VM1_MAC:-52:54:00:12:34:01}"
CXL_NET_VM2_MAC="${CXL_NET_VM2_MAC:-52:54:00:12:34:02}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --outdir) OUTDIR="$2"; shift 2 ;;
    --ssh-key) SSH_KEY_FILES+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${OUTDIR}" ]]; then
  usage
  exit 1
fi

mkdir -p "${OUTDIR}"

PASS_HASH="$(openssl passwd -6 "${PASSWORD}")"

append_unique_file() {
  local f="$1"
  [[ -n "${f}" && -f "${f}" ]] || return 0
  for existing in "${SSH_KEY_FILES[@]}"; do
    if [[ "${existing}" == "${f}" ]]; then
      return 0
    fi
  done
  SSH_KEY_FILES+=("${f}")
}

# Try to pick up the caller's SSH key so you can log into the VMs without a password.
# When run via sudo, $HOME points to /root, so use $SUDO_USER if present.
user_home="${HOME}"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  user_home="$(eval echo "~${SUDO_USER}" 2>/dev/null || echo "${HOME}")"
fi
append_unique_file "${user_home}/.ssh/id_ed25519.pub"
append_unique_file "${user_home}/.ssh/id_rsa.pub"
append_unique_file "${user_home}/.ssh/google_compute_engine.pub"

SSH_AUTH_KEYS_YAML=""
if [[ "${#SSH_KEY_FILES[@]}" -gt 0 ]]; then
  keys=()
  for f in "${SSH_KEY_FILES[@]}"; do
    if [[ ! -f "${f}" ]]; then
      echo "[!] Warning: SSH public key not found: ${f}" >&2
      continue
    fi
    key="$(tr -d '\n' < "${f}")"
    [[ -n "${key}" ]] && keys+=("${key}")
  done
  if [[ "${#keys[@]}" -gt 0 ]]; then
    SSH_AUTH_KEYS_YAML=$'\n'"    ssh_authorized_keys:"
    for k in "${keys[@]}"; do
      SSH_AUTH_KEYS_YAML+=$'\n'"      - ${k}"
    done
  fi
fi

make_user_data() {
  local host="$1"
  local cxl_ip=""
  local cxl_mac=""
  if [[ "${host}" == "vm1" ]]; then
    cxl_ip="${CXL_NET_VM1_IP}"
    cxl_mac="${CXL_NET_VM1_MAC}"
  else
    cxl_ip="${CXL_NET_VM2_IP}"
    cxl_mac="${CXL_NET_VM2_MAC}"
  fi

  cat > "${OUTDIR}/user-data-${host}" <<EOF
#cloud-config
hostname: ${host}
manage_etc_hosts: true
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
    passwd: ${PASS_HASH}
${SSH_AUTH_KEYS_YAML}
ssh_pwauth: true
EOF

  if [[ "${INSTALL_PACKAGES}" == "1" ]]; then
    cat >> "${OUTDIR}/user-data-${host}" <<'EOF'
package_update: true
packages:
  - python3
  - python3-pip
  - numactl
  - net-tools
  - qemu-guest-agent
  - redis-tools
EOF
  fi

  if [[ "${CXL_NET_ENABLE}" == "1" ]]; then
    cat >> "${OUTDIR}/user-data-${host}" <<EOF
write_files:
  - path: /etc/netplan/99-cxl0.yaml
    permissions: "0644"
    content: |
      network:
        version: 2
        ethernets:
          cxl0:
            match:
              macaddress: ${cxl_mac}
            set-name: cxl0
            dhcp4: false
            dhcp6: false
            addresses:
              - ${cxl_ip}/24
            optional: true
EOF
  fi

  cat >> "${OUTDIR}/user-data-${host}" <<'EOF'
runcmd:
  - netplan apply
  - systemctl enable --now qemu-guest-agent || true
EOF
}

make_meta() {
  local host="$1"
  cat > "${OUTDIR}/meta-data-${host}" <<EOF
instance-id: ${host}
local-hostname: ${host}
EOF
}

echo "[*] Generating cloud-init data for vm1/vm2"
make_user_data "vm1"
make_user_data "vm2"
make_meta "vm1"
make_meta "vm2"

echo "[*] Building seed images (cloud-localds)"
cloud-localds "${OUTDIR}/seed-vm1.img" "${OUTDIR}/user-data-vm1" "${OUTDIR}/meta-data-vm1"
cloud-localds "${OUTDIR}/seed-vm2.img" "${OUTDIR}/user-data-vm2" "${OUTDIR}/meta-data-vm2"

echo "[+] Done. Seeds at ${OUTDIR}/seed-vm1.img and seed-vm2.img"
echo "[+] Login user: ubuntu, password: ${PASSWORD}"
