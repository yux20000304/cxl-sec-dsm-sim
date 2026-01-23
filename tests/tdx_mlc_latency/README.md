# TDX MLC + Shared-Memory Latency Tests

This folder contains a small harness to measure:

- "Normal" guest memory latency (Intel MLC, plus a simple pointer-chase microbench)
- ivshmem shared-memory latency (pointer-chase on the ivshmem BAR2 mapping)

Important limitation:
Intel MLC measures latency on memory it allocates via the OS (guest RAM / NUMA).
The ivshmem BAR2 region is a PCI-mapped region, not guest system memory, so MLC
cannot directly target it. For ivshmem, we use a cacheline pointer-chase
microbenchmark.

## 0) Put Intel MLC Binary (Optional)

Intel MLC is not vendored in this repo (license). If you have it:

- Place the `mlc` binary at `tests/tdx_mlc_latency/mlc/mlc`, or
- Set `MLC_BIN=/path/to/mlc` when running the VM script.

## 1) Run From The Host (Recommended)

This will boot 2 TDX VMs with ivshmem enabled, then run the tests inside each
VM and write logs under `results/`.

```bash
sudo -E bash tests/tdx_mlc_latency/host_run.sh
```

Useful knobs:

- VM image/firmware: `BASE_IMG=...` `TDX_BIOS=...`
- Shared memory backing: `CXL_PATH=...` `CXL_SIZE=...`
- Host NUMA shaping (if you have >=2 NUMA nodes): `VM1_CPU_NODE=0 VM2_CPU_NODE=0 CXL_MEM_NODE=1`
- Pointer-chase params (passed into the guest):
  - `LAT_SIZE=256M` (working set, should be > LLC to reflect memory latency)
  - `LAT_STRIDE=64` (bytes, cacheline by default)
  - `LAT_SHM_REGION_OFF=64M` (offset inside the BAR2 mapping to avoid headers)
  - `LAT_ITERS=0` (0 = auto)
  - `LAT_CPU=0` (pin inside VM if `taskset` exists; empty = no pin)

## 2) Run Inside A VM (Manual)

If your VMs are already running and `/mnt/hostshare` is mounted:

```bash
sudo -E bash /mnt/hostshare/tests/tdx_mlc_latency/vm_run.sh
```

The script will:
- compile `cxl_cacheline_lat.c` to `/tmp/cxl_cacheline_lat`
- run pointer-chase latency on private RAM and on the ivshmem mapping
- run Intel MLC if `mlc` is found

