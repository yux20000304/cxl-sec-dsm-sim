TDX ivshmem Ping-Pong Demo

This is a minimal verification program showing two TDX-protected VMs communicating through a host-backed shared memory region (QEMU ivshmem). It reuses the shared-memory ring format already used elsewhere in this repo.

Prerequisites
- Host supports TDX and QEMU exposes `tdx-guest` (see `README.md` TDX section).
- Dual-VM setup sharing an ivshmem backing file (you can use `scripts/host_recreate_and_bench_tdx.sh`).
- Inside both guests, ensure the ivshmem BAR is accessible:
  - Preferred: bind ivshmem to `/dev/uioX`: `sudo bash /repo/guest/bind_ivshmem_uio.sh` (adjust `/repo` if the repo is mounted elsewhere in the guest).
  - Fallback: use the PCI BAR2 resource file directly (e.g., `/sys/bus/pci/devices/0000:00:02.0/resource2`).

Run
1) VM1 (server):
   - UIO path
     - `sudo python3 /repo/examples/tdx-ivshmem-ping/ping_pong.py --uio /dev/uio0 --map-size 134217728 --role server`
   - PCI BAR2 path
     - `sudo python3 /repo/examples/tdx-ivshmem-ping/ping_pong.py --path /sys/bus/pci/devices/0000:00:02.0/resource2 --role server --map-size 134217728`

2) VM2 (client):
   - UIO path
     - `sudo python3 /repo/examples/tdx-ivshmem-ping/ping_pong.py --uio /dev/uio0 --map-size 134217728 --role client --count 10`
   - PCI BAR2 path
     - `sudo python3 /repo/examples/tdx-ivshmem-ping/ping_pong.py --path /sys/bus/pci/devices/0000:00:02.0/resource2 --role client --count 10 --map-size 134217728`

Notes
- If using `/dev/uioX`, `--map-size` is required for mmap. Use the size of the largest UIO map shown by `guest/bind_ivshmem_uio.sh`.
- If the largest UIO map is not `map0`, compute `--map-offset` as `map_index * page_size` (page_size is usually 4096).
- Either VM can start first; if no header is present, the first process initializes the ring layout.
- The shared region is not protected by TDX (by design). For secure payloads, use the secure ring variants in this repo.
