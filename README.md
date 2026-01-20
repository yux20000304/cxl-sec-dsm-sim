# CXL-DSM Multi-host Security (NUMA/QEMU/Gramine/Redis)

Single-host PoC that uses NUMA + QEMU (two VMs) + shared memory to emulate a CXL-DSM multi-host environment. Redis is the target workload. The client talks to the server by writing directly into a shared-memory ring (binary protocol, no RESP). The repo covers Phases 1–3 of the original plan; Phase 4 gives KVM/EPT hook hints.

Highlights
- Two VMs share an ivshmem backing file (default `/tmp/cxl_shared.raw`), both can mmap PCI BAR2 directly.
- Redis runs with a binary ring protocol (version=2, slot=4096B, rings=4, map=1GB). Client writes/reads shared memory; no TCP sockets on the hot path.
- Benchmarks proven with 200k/500k requests, 4 threads, pipeline + client-side inflight throttling.
- Optional secure-ring variant: address-range ACL table + software encrypt/decrypt (libsodium) managed by `cxl_sec_mgr`.

## Repo layout
- `infra/` – host scripts: create shared backing, cloud-init seeds, launch dual VMs.
- `guest/` – guest-side helper scripts: bind ivshmem -> uio, basic install/start.
- `shim/` – legacy Python shim (kept for reference; replaced by C direct path).
- `gramine/` – Gramine manifest templates and build rules for Redis.
- `gapbs/` – GAP Benchmark Suite (graph kernels); includes `*-ring` (shared-memory CSR) and `*-ring-secure` (ACL + libsodium encrypt-at-rest) builds.
- `kvm/` – Phase 4 hints for KVM/EPT permission checks (no kernel build here).
- `ring_client/` – C direct client (binary ring, no RESP).
- `cxl_sec_mgr/` – ACL/key table manager process for secure ring mode.
- `sodium_tunnel/` – libsodium encrypted TCP tunnel (software encryption baseline for native Redis).
- `redis/src/cxl_ring.c` – Redis-side ring driver (binary GET/SET).
- `results/` – saved benchmark logs/CSVs.

## Phase 1: Dual VMs + shared “CXL medium” (ivshmem)
### Host prerequisites (Ubuntu 22.04/24.04)
`qemu-system-x86`, `qemu-utils`, `numactl`, `cloud-image-utils`, `curl` (or `wget`)

### Create shared backing file (host)
```bash
sudo bash infra/create_cxl_shared.sh /tmp/cxl_shared.raw 4G
```

### Prepare Ubuntu cloud image + VM disks
Download a cloud image (e.g., `ubuntu-24.04-server-cloudimg-amd64.img`), then:
```bash
bash infra/create_vm_images.sh \
  --base /path/to/ubuntu-24.04-server-cloudimg-amd64.img \
  --outdir infra/images \
  --vm1 vm1.qcow2 \
  --vm2 vm2.qcow2

bash infra/create_cloud_init.sh --outdir infra/images
```
Or let `scripts/host_quickstart.sh` auto-download Ubuntu 24.04 into `../mirror/` (default).

### Launch dual VMs (host)
User-mode networking with SSH forwards:
- VM1 SSH: `127.0.0.1:2222`
- VM2 SSH: `127.0.0.1:2223`

```bash
bash infra/run_vms.sh \
  --cxl /tmp/cxl_shared.raw --cxl-size 4G \
  --vm1-disk infra/images/vm1.qcow2 --vm1-seed infra/images/seed-vm1.img \
  --vm2-disk infra/images/vm2.qcow2 --vm2-seed infra/images/seed-vm2.img
```

Optional NUMA pinning (simulate “remote” CXL memory):
```bash
VM1_CPU_NODE=0 VM2_CPU_NODE=0 CXL_MEM_NODE=1 bash infra/run_vms.sh ...
```
This pins vCPUs to node0 and allocates shared memory on node1.
If your host exposes only a single NUMA node, you can still simulate “remote CXL”
latency by injecting artificial delay on each shared-memory ring access:
```bash
CXL_SHM_DELAY_NS=150 bash scripts/host_recreate_and_bench_gramine.sh
```
(`CXL_SHM_DELAY_NS` is in nanoseconds; set to `0` to disable. The benchmark scripts
auto-default it to `150` on 1-NUMA hosts if unset.)

### Mount host repo inside guests (convenience)
```bash
sudo mkdir -p /mnt/hostshare
sudo mount -t 9p -o trans=virtio hostshare /mnt/hostshare
```

## Phase 2: VM1 with Gramine + Redis (SGX optional)
### Bind ivshmem to `/dev/uioX` inside VM1
```bash
sudo bash guest/bind_ivshmem_uio.sh
ls -la /dev/uio*
```

### Install Redis / Gramine (VM1)
Install Gramine + SGX repo keys (Jammy/Noble) and update:
```bash
sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg https://packages.gramineproject.io/gramine-keyring-$(lsb_release -sc).gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/gramine.list

sudo curl -fsSLo /etc/apt/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install -y gramine
```

Use apt or the helper:
```bash
sudo bash guest/vm1_setup.sh   # optional helper
```
Gramine templates live in `gramine/`:
```bash
cd gramine
# Build two manifests:
# - `redis-native.manifest` for `/usr/bin/redis-server` (TCP/RESP baseline)
# - `redis-ring.manifest`   for `/repo/redis/src/redis-server` (CXL ring enabled)
make links native ring

# Run native Redis under Gramine (direct mode).
gramine-direct ./redis-native /repo/gramine/redis.conf

# Run ring-enabled Redis under Gramine (direct mode, needs BAR2 access).
sudo gramine-direct ./redis-ring /repo/gramine/redis.conf

# Optional SGX artifacts:
# - sign manifests (no SGX hardware required): make sgx-sign
# - fetch launch tokens (requires SGX + AESM): make sgx-token
#
# Run under SGX (requires SGX hardware in the environment):
# sudo gramine-sgx ./redis-native /repo/gramine/redis.conf
```

## Phase 3: CXL shim – direct binary ring (C)
### VM1: Build + start Redis with ring (version 2, no RESP)
```bash
ssh -p 2222 ubuntu@127.0.0.1
cd /mnt/hostshare/redis/src
sudo rm -rf ../deps/cachedObjs cxl_ring.d cxl_ring.o
sudo make MALLOC=libc USE_LTO=no CFLAGS='-O2 -fno-lto' LDFLAGS='-fno-lto' -j2
sudo env CXL_RING_PATH=/sys/bus/pci/devices/0000:00:02.0/resource2 \
    CXL_RING_MAP_SIZE=1073741824 CXL_RING_COUNT=4 \
    nohup ./redis-server --port 7379 --protected-mode no --save '' --appendonly no \
    >/tmp/redis_ring_direct.log 2>&1 &
```
Expect log: `cxl ring: enabled ... rings=4 slots_per_ring=26624`.

### VM2: Build C client (version 2)
```bash
ssh -p 2223 ubuntu@127.0.0.1
cd /mnt/hostshare/ring_client
gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct cxl_ring_direct.c -lsodium
```

### Benchmark examples
200k requests, 4 threads, pipeline, inflight limit 5000:
```bash
sudo /tmp/cxl_ring_direct \
  --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
  --map-size 1073741824 --bench 200000 --pipeline --threads 4 --max-inflight 5000 \
  | tee /mnt/hostshare/results/ring_bench_threads4_c4_200k.log
```
Result (measured): SET ≈ 1,024,965 req/s; GET ≈ 1,852,467 req/s.

500k requests, same params:
```bash
sudo /tmp/cxl_ring_direct \
  --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
  --map-size 1073741824 --bench 500000 --pipeline --threads 4 --max-inflight 5000 \
  | tee /mnt/hostshare/results/ring_bench_threads4_c4_500k.log
```
Result: SET ≈ 1,255,842 req/s; GET ≈ 1,605,614 req/s.

### CSV export (latency + cost, optional)
- `--latency`: per-op samples; outputs avg/p50/p75/p90/p99/p99.9/p99.99.
- `--cost`: counts push retries and sleep time (coarse; off by default).
- `--csv <path>`: CSV output (default `results/ring_metrics.csv`, append with header).
- `--label <name>`: label for the run.

Example with latency/cost on:
```bash
sudo /tmp/cxl_ring_direct \
  --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
  --map-size 1073741824 --bench 200000 --pipeline --threads 4 --max-inflight 5000 \
  --latency --cost --label ring_v2 \
  | tee /mnt/hostshare/results/ring_bench_threads4_c4_200k.log
# CSV written/appended to /mnt/hostshare/results/ring_metrics.csv
```

## Baseline: native Redis over TCP
VM1 (6379):
```bash
cd /mnt/hostshare/redis/src
nohup ./redis-server --port 6379 --protected-mode no --save '' --appendonly no >/tmp/redis_native.log 2>&1 &
```
Benchmark (4 threads, concurrency 4, 200k requests):
```bash
./redis-benchmark -h 127.0.0.1 -p 6379 -t set,get -n 200000 -c 4 --threads 4 \
  | tee /mnt/hostshare/results/redis_bench_native_threads4_c4_large.log
```
Result: SET/GET ≈ 199,800 req/s.

## Key code notes
- `redis/src/cxl_ring.c`
  - `CXL_VERSION=2`, binary protocol (op/key_len/val_len + payload), bypasses RESP.
  - Defaults: slot_size=4096, rings=4, map_size=1GB; head/tail in shared header, req/resp halves.
  - `handle_request`: parses binary GET/SET, calls Redis internals `setKey/lookupKeyRead`, writes status/value.

- `ring_client/cxl_ring_direct.c`
  - Version 2 client, slot=4096, map=1GB default.
  - `--threads` spreads across rings; `--pipeline` batches; `--max-inflight` caps outstanding to avoid ring overflow.
  - `--latency/--cost/--csv/--label` capture metrics with minimal code overhead (off by default).
  - `--secure` enables ACL+crypto over the shared-memory payload (requires `--sec-mgr ip:port` + `--sec-node-id N`).

## One-command host bootstrap
If you already have a cloud image (BASE_IMG) and host deps installed:
```bash
BASE_IMG=/path/to/ubuntu-24.04-server-cloudimg-amd64.img \
bash scripts/host_quickstart.sh
```
If you don't have one, `scripts/host_quickstart.sh` downloads Ubuntu 24.04 by default (set `DOWNLOAD_BASE_IMG=0` to disable).
This creates the shared file, qcow2/seed, and boots both VMs (SSH: 2222/2223). Tune memory/CPU/NUMA via env vars if needed.

If you switch the base image (e.g., Jammy -> Noble), recreate the VM disks:
```bash
FORCE_RECREATE=1 bash scripts/host_quickstart.sh
```

### One command: recreate VMs + Gramine benchmarks
This rebuilds VM1/VM2 from the base image and runs:
- Native Redis over TCP (no Gramine; VM2 -> VM1 via `cxl0` internal NIC)
- Gramine + native Redis over TCP (VM2 -> VM1 via `cxl0` internal NIC)
- Gramine + native Redis over libsodium-encrypted TCP (VM2 -> VM1 via user-space tunnel)
- Gramine + ring-enabled Redis over BAR2 (VM2 uses `cxl_ring_direct`)
- Gramine + secure ring Redis over BAR2 (VM2 uses `cxl_ring_direct --secure`, ACL managed by `cxl_sec_mgr`)

```bash
bash scripts/host_recreate_and_bench_gramine.sh
```
Outputs are written to `results/` as timestamped `gramine_*.log` / `gramine_*.csv`.
The compare CSV includes `NativeTCP`, `GramineNativeTCP`, `GramineSodiumTCP`, `GramineRing`, and `GramineRingSecure` labels.

### One command: recreate VMs + Redis YCSB (Gramine SGX inside SGX VM)
This rebuilds VM1/VM2, enables SGX virtualization in VM1, then runs YCSB (CRUD+scan mix) across:
- Native Redis over TCP
- Gramine SGX Redis over TCP
- Gramine SGX Redis over libsodium-encrypted TCP
- Gramine SGX ring Redis over BAR2 (YCSB JNI binding)
- Gramine SGX secure ring Redis over BAR2 (YCSB JNI binding + `cxl_sec_mgr`)

```bash
sudo -E bash scripts/host_recreate_and_ycsb_gramine_sgxvm.sh
```

Notes:
- Default workload file: `ycsb/workloads/workload_cxl_crudscan` (override with `YCSB_WORKLOAD`).
- Outputs are written to `results/` as timestamped `sgxvm_ycsb_*.log` plus a compare CSV `sgxvm_ycsb_compare_*.csv`.

### Local GAPBS benchmark (no VMs)
```bash
bash scripts/host_bench_gapbs_local.sh
```

### One command: recreate VMs + GAPBS multi-host compare (5 versions)
This rebuilds VM1/VM2 and runs a GAPBS kernel across the two VMs in five modes:
- `Native`: plain GAPBS (no Gramine, no shared memory)
- `MultihostRing`: shared-memory ring (no Gramine)
- `GramineMultihostRing`: shared-memory ring under `gramine-direct`
- `GramineMultihostCrypto`: shared-memory ring encrypted-at-rest via libsodium (per-VM key + common key; no manager)
- `GramineMultihostSecure`: shared-memory ring with `cxl_sec_mgr` ACL/key table (permission-managed crypto)

```bash
sudo bash scripts/host_recreate_and_bench_gapbs_multihost.sh
```
If VM1/VM2 are already running, reuse them:
```bash
SKIP_RECREATE=1 bash scripts/host_recreate_and_bench_gapbs_multihost.sh
```
Outputs are written to `results/` as timestamped `gapbs_*` logs plus a compare CSV (includes `throughput_teps`).

## TDX hardware: TDX guests (VMs + ivshmem, no Gramine)
This workflow keeps the two-VM + ivshmem setup, but runs both Redis variants directly
inside **Intel TDX confidential guests**. TDX is a VM-level TEE, so Gramine is not
required to run inside a TEE (though you *can* still run Gramine inside a TDX guest
for additional isolation/debugging).

Host prereqs:
- `/dev/kvm` available (nested virt enabled if running inside a cloud VM)
- QEMU supports TDX guests (`qemu-system-x86_64 -object help | grep tdx-guest`)
- A TDVF/OVMF firmware file for `-bios` (Ubuntu: `sudo apt-get install -y ovmf`, then set `TDX_BIOS=/usr/share/OVMF/OVMF_CODE_4M.fd`)

Notes:
- The ivshmem-backed “shared CXL medium” is **shared memory** and is therefore not
  protected by TDX (it must be shared with the host/device). Use this workflow to
  validate functionality and measure performance, but do not treat the ring payload
  as confidential unless you add application-level crypto/auth (see `TDXRingSecure`).

One command:
```bash
sudo -E bash scripts/host_recreate_and_bench_tdx.sh
```
Outputs are written to `results/` as timestamped `tdx_*.log` / `tdx_*.csv`.
The compare CSV includes `TDXNativeTCP`, `TDXRing`, and `TDXRingSecure` labels.

## SGX hardware: Gramine SGX compare (no VMs)
This workflow runs on an SGX-capable *host OS* (not inside QEMU guests): it starts
Redis under `gramine-sgx` and benchmarks (host native TCP vs Gramine SGX TCP vs libsodium-encrypted TCP vs ring shared-memory vs secure ring).

Prereqs:
- CPU flags include `aes` and `sgx`
- SGX device nodes exist (typically `/dev/sgx_enclave`)
- AESM is running (`aesmd`)
- Gramine is installed (`gramine-sgx`, `gramine-sgx-sign`; `gramine-sgx-get-token` optional) or let `scripts/host_bench_gramine_sgx.sh` install it on Ubuntu (`INSTALL_GRAMINE=1`)
- libsodium headers are available (`libsodium-dev`) or let `scripts/host_bench_gramine_sgx.sh` install them (`INSTALL_LIBSODIUM=1`)
- `numactl` is installed (optional; only needed for NUMA pinning) or let `scripts/host_bench_gramine_sgx.sh` install it (`INSTALL_NUMACTL=1`)
- Redis tools are installed (`redis-cli`, `redis-benchmark`, usually via `redis-tools`)
Notes:
- Some platforms use SGX Launch Control (FLC) and don't need a launch token. Recent Gramine packages may not ship `gramine-sgx-get-token`; if you see a warning about it, run with `SGX_TOKEN_MODE=skip`.

One command:
```bash
sudo -E bash scripts/host_bench_gramine_sgx.sh
```
Optional NUMA pinning (simulate “remote” CXL memory on the host):
```bash
BENCH_CPU_NODE=0 CXL_MEM_NODE=1 sudo -E bash scripts/host_bench_gramine_sgx.sh
```
If the host has only a single NUMA node, the script auto-falls back to the
software delay model above (`CXL_SHM_DELAY_NS`) instead of NUMA binding.
Outputs are written to `results/` as timestamped `sgx_*.log` / `sgx_*.csv`.
The compare CSV includes `HostNativeTCP`, `GramineSGXNativeTCP`, `GramineSGXSodiumTCP`, `GramineSGXRing`, and `GramineSGXRingSecure` labels.

### GAPBS under Gramine SGX (no VMs)
This runs the GAPBS multi-host shared-memory matrix on a single SGX-capable host (two processes sharing a file-backed `/dev/shm` mapping).

One command:
```bash
sudo -E bash scripts/host_bench_gapbs_gramine_sgx.sh
```
Outputs are written to `results/` as timestamped `gapbs_sgx_*` logs plus a compare CSV (`gapbs_compare_sgx_*.csv`).

## SGX hardware: Gramine SGX inside guests (VMs + ivshmem)
This workflow keeps the two-VM + ivshmem setup, but runs Redis under `gramine-sgx`
*inside VM1*. This requires **SGX virtualization** support in the host KVM/QEMU
stack; otherwise the guest won't have `/dev/sgx_enclave`.
Benchmarks include VM native TCP, Gramine SGX TCP, libsodium-encrypted TCP, ring shared-memory, and secure ring.

Host prereqs:
- `/dev/kvm` available (nested virt enabled if running inside a cloud VM)
- CPU flags include `aes` and `sgx`
- QEMU supports SGX EPC objects (`qemu-system-x86_64 -object help | grep memory-backend-epc`)

One command:
```bash
sudo -E bash scripts/host_recreate_and_bench_gramine_sgxvm.sh
```
Outputs are written to `results/` as timestamped `sgxvm_*.log` / `sgxvm_*.csv`.
The compare CSV includes `SGXVMNativeTCP`, `GramineSGXVMNativeTCP`, `GramineSGXVMSodiumTCP`, `GramineSGXVMRing`, and `GramineSGXVMRingSecure` labels.

### GAPBS under Gramine SGX inside guests (VMs + ivshmem)
This runs the GAPBS multi-host shared-memory matrix with each VM running the GAPBS binaries under `gramine-sgx` (requires SGX virtualization for both guests).

One command:
```bash
sudo -E bash scripts/host_recreate_and_bench_gapbs_gramine_sgxvm.sh
```
Outputs are written to `results/` as timestamped `gapbs_sgxvm_*` logs plus a compare CSV (`gapbs_sgxvm_compare_*.csv`).

## Quick shared-memory sanity check
VM1:
```bash
python3 shim/cxl_mem_test.py --uio /dev/uio0 --write --offset 0x1000 --data 'hello-from-vm1'
```
VM2:
```bash
python3 shim/cxl_mem_test.py --uio /dev/uio0 --read --offset 0x1000 --len 32
```

## If /dev/uio0 only exposes 4KB (no shared region)
Some kernels expose only BAR0 via `uio_pci_generic` (4KB doorbell). Use PCI BAR2 directly:

- VM1:
  ```bash
  sudo python3 shim/cxl_server_agent.py \
    --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
    --map-size 134217728 \
    --redis 127.0.0.1:6379
  ```
- VM2:
  ```bash
  sudo python3 shim/cxl_client_agent.py \
    --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
    --map-size 134217728 \
    --listen 0.0.0.0:6380
  ```
Or via helper scripts:
```bash
sudo bash scripts/vm1_server.sh --path /sys/bus/pci/devices/0000:00:02.0/resource2 --map-size 134217728 --redis 127.0.0.1:6379
sudo bash scripts/vm2_client.sh --path /sys/bus/pci/devices/0000:00:02.0/resource2 --map-size 134217728 --listen 0.0.0.0:6380
```
`--map-size 134217728` = 128MB; ensure it is >= total ring footprint.

## KVM/EPT hooks (Phase 4 pointer)
See `kvm/README.md` for where to intercept GPA faults (e.g., `kvm_mmu_page_fault` or `handle_ept_violation`) and how to hardcode a protected CXL GPA range plus an “attacker VM” check. Only guidance is provided; kernel build is not included here.
