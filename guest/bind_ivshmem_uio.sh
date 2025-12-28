#!/usr/bin/env bash
set -euo pipefail

# Bind the QEMU ivshmem device to uio_pci_generic and expose /dev/uioX.
# Must be run inside the guest VM (vm1/vm2).

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

modprobe uio_pci_generic

echo "[*] Searching for ivshmem (virtio vendor 0x1af4, device 0x1110)..."
# new_id 可能已存在，再写会报错；忽略此类错误
echo "1af4 1110" > /sys/bus/pci/drivers/uio_pci_generic/new_id 2>/dev/null || true

found=0
for dev in /sys/bus/pci/devices/*; do
  [[ -f "${dev}/vendor" ]] || continue
  ven=$(cat "${dev}/vendor")
  dev_id=$(cat "${dev}/device")
  if [[ "${ven}" == "0x1af4" && "${dev_id}" == "0x1110" ]]; then
    slot=$(basename "${dev}")
    echo "[*] Binding ${slot} to uio_pci_generic"
    # Unbind from any existing driver
    if [[ -L "${dev}/driver" ]]; then
      echo "${slot}" > "${dev}/driver/unbind"
    fi
    echo "${slot}" > /sys/bus/pci/drivers/uio_pci_generic/bind
    found=1
  fi
done

if [[ "${found}" -eq 0 ]]; then
  echo "[!] ivshmem device not found. Is QEMU started with -device ivshmem-plain?" >&2
  exit 1
fi

echo "[*] UIO devices:"
ls -l /dev/uio*
for dev in /sys/class/uio/uio*/maps/map0/size; do
  echo "    $(basename "$(dirname "$(dirname "${dev}")")"): size=$(cat "${dev}")"
done

# Relax permissions for quick experiments
for dev in /dev/uio*; do
  chmod 666 "${dev}" || true
done

echo "[+] Done. You can mmap /dev/uio0 (or relevant) from shim scripts."
