#!/usr/bin/env bash
set -euo pipefail

# Generate cloud-init seed images for VM1 / VM2.
# The default user is "ubuntu" with password "ubuntu" (ssh password enabled).
#
# Example:
#   bash infra/create_cloud_init.sh --outdir infra/images

usage() {
  cat >&2 <<'EOF'
Usage: create_cloud_init.sh --outdir <dir>
EOF
}

OUTDIR=""

PASSWORD="${PASSWORD:-ubuntu}"  # plaintext password; can override env PASSWORD

while [[ $# -gt 0 ]]; do
  case "$1" in
    --outdir) OUTDIR="$2"; shift 2 ;;
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

make_user_data() {
  local host="$1"
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
ssh_pwauth: true
package_update: true
packages:
  - python3
  - python3-pip
  - numactl
  - net-tools
  - qemu-guest-agent
  - redis-tools
write_files:
  - path: /etc/sysctl.d/99-ip-forward.conf
    content: |
      net.ipv4.ip_forward=1
runcmd:
  - systemctl enable --now qemu-guest-agent
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
