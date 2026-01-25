# cxl-sec-dsm-sim (TDX-focused)

This repository runs **Redis / YCSB / GAPBS** on top of a **2-VM Intel TDX setup** with an **ivshmem shared-memory device (PCI BAR2)** to emulate a multi-host CXL-DSM-like shared medium. It compares:

- `ring`: direct shared-memory access (no crypto / no ACL)
- `secure`: `cxl_sec_mgr`-managed ACL + per-payload crypto/auth (libsodium)
- `crypto`: manager-less software crypto (used by GAPBS and Redis ring-crypto in this repo)

Primary entry points:

- `scripts/host_recreate_and_bench_tdx.sh`: recreate 2 TDX VMs and run the full suite
- `scripts/host_tdx_batch_suite.sh`: batch sweep (threads, kernels, optional YCSB)

---

## Repository layout (relevant parts)

- `scripts/host_recreate_and_bench_tdx.sh`: **TDX: Redis + GAPBS (optional YCSB)**
- `scripts/host_tdx_batch_suite.sh`: batch runner (Redis + GAPBS, optional YCSB)
- `scripts/run_ycsb.sh`: run YCSB inside a VM (installs Java, downloads YCSB)
- `scripts/tdx_build_guest_image.sh`: build a TDX guest image via the `tdx/` submodule
- `ring_client/`: `cxl_ring_direct` (binary ring client) + `ring_resp_proxy` (RESP-over-ring for YCSB)
- `redis/`: Redis with a ring backend (`redis/src/cxl_ring.c`)
- `gapbs/`: GAPBS with multi-host shared-memory variants (`*-ring`, `*-ring-secure`)
- `cxl_sec_mgr/`: secure-mode ACL/key manager
- `tdx/`: canonical/tdx submodule (host/guest TDX enablement tools)
- `results/`: logs/CSVs emitted by scripts

---

## 1. Host prerequisites (TDX)

### 1.1 Hardware / BIOS

You need a platform that supports Intel TDX, and TDX must be enabled in BIOS/firmware. If TDX is not enabled at the platform level, QEMU/KVM will fail to start a TDX guest.

Use `tdx/README.md` as the canonical reference for supported platforms and host setup steps.

### 1.2 Host OS + TDX stack (recommended via `tdx/`)

This repo includes `tdx/` as a submodule (canonical/tdx). To prepare the host:

```bash
git submodule update --init --recursive

cd tdx
# Optional: edit setup-tdx-config before running
sudo -E ./setup-tdx-host.sh
```

Quick checks:

```bash
ls -l /dev/kvm
cat /sys/module/kvm_intel/parameters/tdx
sudo dmesg | grep -i tdx | tail -n 50
qemu-system-x86_64 -object help | rg -n "tdx-guest" || true
```

### 1.3 Firmware (TDVF / OVMF)

`scripts/host_recreate_and_bench_tdx.sh` passes a firmware file via `-bios`. You can override it:

```bash
TDX_BIOS=/usr/share/ovmf/OVMF.fd
# or /usr/share/OVMF/OVMF_CODE_4M.fd, etc.
```

If your distro QEMU does not expose `tdx-guest` in `-object help`, use a TDX-capable QEMU build and set `QEMU_BIN=/path/to/qemu-system-x86_64`.

---

## 2. Guest image preparation

### Option A (recommended): let the script build a TD guest image

With submodules initialized:

```bash
git submodule update --init --recursive
sudo -E bash scripts/host_recreate_and_bench_tdx.sh
```

If `BASE_IMG` is unset, the script calls:

- `scripts/tdx_build_guest_image.sh` (uses `tdx/guest-tools/image/create-td-image.sh`)
- default output: `infra/images/tdx-guest-ubuntu-24.04-generic.qcow2`

### Option B: provide your own `BASE_IMG`

Build a 24.04 TD image:

```bash
git submodule update --init --recursive
bash scripts/tdx_build_guest_image.sh
```

Run the suite using that image:

```bash
sudo -E BASE_IMG=infra/images/tdx-guest-ubuntu-24.04-generic.qcow2 \
  bash scripts/host_recreate_and_bench_tdx.sh
```

Note: `host_recreate_and_bench_tdx.sh` attaches a cloud-init seed for the 2-VM topology (SSH, networking, etc.), so you typically do not need to manually tweak the guest image.

---

## 3. Run the suite (TDX)

### 3.1 Redis + GAPBS (default)

```bash
sudo -E bash scripts/host_recreate_and_bench_tdx.sh
```

High-level workflow:

- boot 2 TDX guests (VM1/VM2) and attach ivshmem (shared “CXL medium”)
- VM1 starts Redis endpoints (native TCP, libsodium TCP, ring, secure-ring)
- VM2 runs the corresponding clients/benchmarks (`redis-benchmark`, `cxl_ring_direct`)
- GAPBS: VM1 publishes a graph to shared memory; VM1/VM2 attach and run kernels
- everything is written to `results/`

For manual debugging (default SSH ports):

```bash
ssh -p 2222 ubuntu@127.0.0.1  # VM1
ssh -p 2223 ubuntu@127.0.0.1  # VM2
```

The repo is mounted inside the guests at `/mnt/hostshare` via 9p (the script mounts it automatically).

### 3.2 Optional: enable YCSB

YCSB requires RESP/TCP. For ring and secure-ring, the script starts a local proxy on VM2 (`ring_resp_proxy`) that exposes a TCP/RESP endpoint backed by the shared-memory ring.

```bash
sudo -E YCSB_ENABLE=1 YCSB_WORKLOADS=workloada,workloadb \
  YCSB_RECORDS=100000 YCSB_OPS=100000 YCSB_THREADS=4 \
  bash scripts/host_recreate_and_bench_tdx.sh
```

### 3.3 Batch sweep (threads / kernels)

```bash
YCSB_ENABLE=1 \
THREAD_LIST=1,2,4,8 \
GAPBS_KERNEL_LIST=bfs,sssp,pr,cc,bc,tc \
bash scripts/host_tdx_batch_suite.sh
```

---

## 4. Outputs (`results/`)

### 4.1 Redis

- `results/tdx_compare_<ts>.csv`: overview throughput (`TDXNativeTCP`, `TDXSodiumTCP`, `TDXRing`, `TDXRingCrypto`, `TDXRingSecure`)
- `results/tdx_ring_<ts>.csv` / `results/tdx_ring_crypto_<ts>.csv` / `results/tdx_ring_secure_<ts>.csv`: detailed ring metrics (throughput, latency percentiles, `sleep_ms`, etc.)
- `results/tdx_*_tcp_<ts>.log`: raw `redis-benchmark` logs for native/sodium TCP

### 4.2 GAPBS

- `results/tdx_gapbs_compare_<kernel>_<ts>.csv`: per-kernel end-to-end metrics for native/ring/crypto/secure (includes `vm=avg`)
- `results/tdx_gapbs_overhead_<kernel>_<ts>.csv`: attach breakdown (`attach_total_ms`, `attach_decrypt_ms`, `attach_pretouch_ms`, etc.)
- `results/tdx_gapbs_*_<kernel>_<ts>.log`: per-VM raw logs

---

## 5. Security model (important)

### 5.1 Shared memory is not TD private memory

TDX protects **TD private memory**. The ivshmem BAR2 region is **shared memory**, and it does not get the same confidentiality properties as private memory pages.

Implications:

- `ring` / `GAPBS ring`: data in the shared medium is plaintext
- `secure` / `crypto`: software crypto/auth is used to protect payloads stored/transferred via the shared medium

### 5.2 What “ring / secure / crypto” mean (conceptually)

- `ring`: minimal overhead; shared-memory queues / shared CSR access only
- `secure`: `cxl_sec_mgr` mediates ACL + key distribution; payload crypto/auth adds CPU overhead; attach may include decrypt/prepare work
- `crypto` (GAPBS): manager-less crypto path; typically heavier attach-time decrypt cost on the consumer VM

---

## 6. Common environment knobs

Frequently used knobs supported by `scripts/host_recreate_and_bench_tdx.sh`:

- VMs: `VM1_MEM` `VM2_MEM` `VM1_CPUS` `VM2_CPUS` `TDX_BIOS` `QEMU_BIN`
- Ring layout: `RING_MAP_SIZE` `RING_COUNT` `RING_REGION_SIZE` `RING_REGION_BASE` `RING_SECURE_REGION_BASE`
- Latency injection: `CXL_SHM_DELAY_NS` (set `0` to disable)
- Redis bench: `REQ_N` `CLIENTS` `THREADS` `PIPELINE` `MAX_INFLIGHT`
- Ring polling: `CXL_RING_POLL_SPIN_NS` `CXL_RING_POLL_SLEEP_NS`
- YCSB: `YCSB_ENABLE=1` `YCSB_WORKLOADS` `YCSB_RECORDS` `YCSB_OPS` `YCSB_THREADS`
- GAPBS: `GAPBS_KERNEL_LIST` `SCALE` `DEGREE` `TRIALS` `OMP_THREADS` `GAPBS_DROP_FIRST_TRIAL`
- Crypto ring: `ENABLE_CRYPTO=1` `CXL_SEC_KEY_HEX` `CXL_SEC_COMMON_KEY_HEX` `CXL_CRYPTO_PRIV_REGION_BASE` `CXL_CRYPTO_PRIV_REGION_SIZE`

---

## 7. Troubleshooting (TDX)

- `qemu-system-x86_64: -object tdx-guest,...`: your QEMU is not TDX-capable; use a TDX build and set `QEMU_BIN=...`
- `vm-type tdx not supported by KVM`: host kernel/BIOS/TDX module is not ready (platform issue, not a repo issue)
- Cannot SSH into guests: first boot may be slow; increase `WAIT_SSH_SECS` or ensure ports `2222/2223` are free
- YCSB fails: make sure `YCSB_ENABLE=1` and VM2 has network access to download dependencies, or run `scripts/run_ycsb.sh` manually in VM2

---

## Licenses / third-party

- `tdx/` is the canonical/tdx submodule; refer to `tdx/README.md` and `tdx/LICENSE` for its license and usage terms.
