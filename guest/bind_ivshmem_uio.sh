#!/usr/bin/env bash
set -euo pipefail

# Bind the QEMU ivshmem device to uio_pci_generic and expose /dev/uioX.
# Must be run inside the guest VM (vm1/vm2).

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

driver="uio_ivshmem"
if ! modprobe uio_ivshmem 2>/dev/null; then
  if ! modinfo uio_ivshmem >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      echo "[*] uio_ivshmem not found; installing linux-modules-extra-$(uname -r) ..."
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
    fi
  fi
  if modprobe uio_ivshmem 2>/dev/null; then
    driver="uio_ivshmem"
  else
    driver="uio_pci_generic"
    modprobe uio_pci_generic || { echo "[!] Failed to load uio_pci_generic" >&2; exit 1; }
  fi
fi

echo "[*] Searching for ivshmem (virtio vendor 0x1af4, device 0x1110)..."
if [[ "${driver}" == "uio_pci_generic" ]]; then
  # new_id may already exist; writing again can error out, so ignore failures here
  echo "1af4 1110" > /sys/bus/pci/drivers/uio_pci_generic/new_id 2>/dev/null || true
fi

found=0
for dev in /sys/bus/pci/devices/*; do
  [[ -f "${dev}/vendor" ]] || continue
  ven=$(cat "${dev}/vendor")
  dev_id=$(cat "${dev}/device")
  if [[ "${ven}" == "0x1af4" && "${dev_id}" == "0x1110" ]]; then
    slot=$(basename "${dev}")
    echo "[*] Binding ${slot} to ${driver}"
    # Unbind from any existing driver
    if [[ -L "${dev}/driver" ]]; then
      echo "${slot}" > "${dev}/driver/unbind"
    fi
    echo "${slot}" > "/sys/bus/pci/drivers/${driver}/bind"
    found=1
  fi
done

if [[ "${found}" -eq 0 ]]; then
  echo "[!] ivshmem device not found. Is QEMU started with -device ivshmem-plain?" >&2
  exit 1
fi

echo "[*] Using driver: ${driver}"
echo "[*] UIO devices:"
ls -l /dev/uio*
for uio in /sys/class/uio/uio*; do
  [[ -d "${uio}/maps" ]] || continue
  uio_name="$(basename "${uio}")"
  best_idx=-1
  best_size=0
  for map in "${uio}"/maps/map*; do
    [[ -f "${map}/size" ]] || continue
    idx="${map##*/map}"
    size_raw="$(cat "${map}/size")"
    size_dec=$((size_raw))
    echo "    ${uio_name}: map${idx} size=${size_raw}"
    if [[ "${size_dec}" -gt "${best_size}" ]]; then
      best_size="${size_dec}"
      best_idx="${idx}"
    fi
  done
  if [[ "${best_idx}" -ge 0 ]]; then
    echo "    ${uio_name}: largest=map${best_idx} size=${best_size}"
  fi
done

# Relax permissions for quick experiments
for dev in /dev/uio*; do
  chmod 666 "${dev}" || true
done

echo "[+] Done. You can mmap /dev/uio0 (or relevant) from shim scripts."
echo "    Hint: UIO maps use mmap offset = map_index * page_size."
