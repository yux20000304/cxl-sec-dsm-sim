TDX ivshmem Ping-Pong Demo (new TDX SHM layout)

This is a minimal verification program showing two TDX-protected VMs communicating through a host-backed shared memory region (QEMU ivshmem).

It uses the lightweight transport in `tdx_shm/` (two SPSC queues with fixed 4KiB slots) modeled after `/home/ubuntu/test-tdx`, and does **not** use the older `shim/cxl_shm.py` ring layout.

Prerequisites
- Host supports TDX and QEMU exposes `tdx-guest` (see `README.md` TDX section).
- Dual-VM setup sharing an ivshmem backing file (you can use `scripts/host_quickstart.sh` or `scripts/host_recreate_and_bench_tdx.sh`).
  - Initialize the shared memory file on the host (use the same `CXL_PATH`/`CXL_SIZE` used to launch QEMU):
  - `make -C tdx_shm`
  - `sudo tdx_shm/tdx_shm_init --path /tmp/cxl_shared.raw --size 16M`

Inside both guests, ensure the repo is mounted (scripts mount it at `/mnt/hostshare`). If needed:
- `sudo mkdir -p /mnt/hostshare`
- `sudo mount -t 9p -o trans=virtio,access=any,cache=none,msize=262144 hostshare /mnt/hostshare`

Run
1) VM1 (server):
   - Default (auto-detect ivshmem + mmap PCI BAR2 resource2)
     - `sudo /mnt/hostshare/tdx_shm/tdx_shm_ping_pong --id 1 --role server --timeout-ms 0`
   - UIO fallback (when mmap of resource2 is blocked)
     - `sudo bash /mnt/hostshare/guest/bind_ivshmem_uio.sh`
     - `sudo /mnt/hostshare/tdx_shm/tdx_shm_ping_pong --id 1 --role server --uio /dev/uio0 --timeout-ms 0`

2) VM2 (client):
   - Default (auto-detect ivshmem + mmap PCI BAR2 resource2)
     - `sudo /mnt/hostshare/tdx_shm/tdx_shm_ping_pong --id 2 --role client --count 10`
   - UIO fallback (when mmap of resource2 is blocked)
     - `sudo bash /mnt/hostshare/guest/bind_ivshmem_uio.sh`
     - `sudo /mnt/hostshare/tdx_shm/tdx_shm_ping_pong --id 2 --role client --uio /dev/uio0 --count 10`

Notes
- The shared region is not protected by TDX (by design). Treat it as untrusted input.
- Message size is limited to `4094` bytes (`4096B slot - 2B length`).
