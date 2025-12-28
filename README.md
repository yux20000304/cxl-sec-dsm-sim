# CXL-DSM Multi-host Security (NUMA/QEMU/Gramine/Redis)

在单台物理机上用 **NUMA + QEMU 双 VM + 共享内存** 近似模拟 **CXL-DSM 多主机共享内存**，并用 Redis 作为实验目标完成“客户端经共享内存直连服务端”的 PoC。当前状态：

- 双 VM 共享 ivshmem 文件（`/tmp/cxl_shared.raw`），支持直接 mmap PCI BAR2。
- Redis 采用 **二进制 ring 协议（无 RESP）**，slot=4096B、rings=4、映射 1GB，客户端直读写共享内存。
- 已跑通 20 万 / 50 万 请求的 4 线程压测（pipeline+限流）。

> 对应你给出的 4 Phases / 12 Steps，本仓库覆盖 Phase 1～3 的可运行脚本与 shim 代码，并给 Phase 4 提供定位与改造建议（`kvm/`）。

---

## 目录结构

- `infra/`：宿主机侧脚本（创建共享介质、cloud-init、启动双 VM）
- `guest/`：Guest 内脚本（绑定 ivshmem->uio，安装/启动建议）
- `shim/`：Python shim（早期版本，现已用 C 直连替代）
- `gramine/`：Redis 的 Gramine manifest 模板与构建规则
- `kvm/`：Phase 4 的 KVM/EPT 修改提示（不直接编译内核）
- `ring_client/`：C 版直连客户端（无 RESP，直接写 ring）
- `redis/src/cxl_ring.c`：Redis 侧 ring 驱动（无 RESP，二进制 GET/SET）

---

## Phase 1：双 VM + “CXL 物理介质”共享内存（ivshmem）

### 1) 宿主机依赖（Ubuntu 22.04/24.04）

需要：`qemu-system-x86`、`qemu-utils`、`numactl`、`cloud-image-utils`

### 2) 创建共享内存文件（宿主机）

```bash
sudo bash infra/create_cxl_shared.sh /tmp/cxl_shared.raw 4G
```

### 3) 准备 Ubuntu cloud 镜像与 VM 磁盘

你需要先下载一个 Ubuntu cloud image（例如 `jammy-server-cloudimg-amd64.img`）。

```bash
bash infra/create_vm_images.sh \
  --base /path/to/jammy-server-cloudimg-amd64.img \
  --outdir infra/images \
  --vm1 vm1.qcow2 \
  --vm2 vm2.qcow2
```

生成 cloud-init seed：

```bash
bash infra/create_cloud_init.sh --outdir infra/images
```

### 4) 启动双 VM（宿主机）

默认使用 user-mode 网络（不需要 root 配网），并把：
- VM1 SSH 转发到 `127.0.0.1:2222`
- VM2 SSH 转发到 `127.0.0.1:2223`

```bash
bash infra/run_vms.sh \
  --cxl /tmp/cxl_shared.raw --cxl-size 4G \
  --vm1-disk infra/images/vm1.qcow2 --vm1-seed infra/images/seed-vm1.img \
  --vm2-disk infra/images/vm2.qcow2 --vm2-seed infra/images/seed-vm2.img
```

NUMA 绑核/绑内存（可选，用于“NUMA 节点模拟 CXL 远端访问”）：

```bash
VM1_CPU_NODE=0 VM2_CPU_NODE=0 CXL_MEM_NODE=1 bash infra/run_vms.sh ...
```

> 这里的含义是：vCPU 线程尽量跑在 node0，而共享内存页尽量分配在 node1，从而制造“远端内存”效果。

### 5) Guest 内挂载宿主机工程（方便拿到 shim 代码）

```bash
sudo mkdir -p /mnt/hostshare
sudo mount -t 9p -o trans=virtio hostshare /mnt/hostshare
```

---

## Phase 2：VM1 内 Gramine + Redis（可选 SGX）

### 1) VM1：绑定 ivshmem 到 `/dev/uioX`（CXL 共享内存设备）

```bash
sudo bash guest/bind_ivshmem_uio.sh
ls -la /dev/uio*
```

### 2) VM1：安装 Redis / Gramine

按你环境选择 `apt install redis-server redis-tools gramine`（或直接运行 `sudo bash guest/vm1_setup.sh`）。也可以先只跑裸 Redis，等 shim 跑通再上 Gramine。

Gramine 相关模板在 `gramine/`，典型流程：

```bash
cd gramine
make SGX=1
gramine-sgx ./redis-server -c redis.conf
```

---

## Phase 3：CXL Shim（代理层）——通过共享内存搬运 Redis TCP 流量

### 1) VM1：启动 Redis + Server Agent

Redis 监听本地 6379（可以是系统 redis，也可以是 Gramine-Redis）。

快捷脚本（VM1 内，root）：

```bash
sudo bash scripts/vm1_server.sh --uio /dev/uio0 --redis 127.0.0.1:6379
```

若已经有 redis 运行，可加 `--no-redis` 跳过启动。

### 2) VM2：启动 Client Agent

```bash
sudo bash guest/vm2_setup.sh   # 安装依赖（可选）
sudo bash guest/bind_ivshmem_uio.sh
python3 shim/cxl_client_agent.py --uio /dev/uio0 --listen 0.0.0.0:6380
```

或直接使用快捷脚本（VM2 内，root）：

```bash
sudo bash scripts/vm2_client.sh --uio /dev/uio0 --listen 0.0.0.0:6380
```

### 3) VM2：跑压测

```bash
redis-benchmark -h 127.0.0.1 -p 6380 -t set,get -n 10000
```

> Ring 配置（旧 Python 版）：默认每 ring 4096 个 slot，slot=4096 字节（约 16MB/方向）。新 C 版 ring 使用 4 个 ring，每 ring 26624 slot，slot=4096 字节（映射 1GB）。

---

## Phase 4：Sec-DSM（KVM/EPT 权限单元）提示

见 `kvm/README.md`：给出推荐的切入点（KVM MMU/EPT fault path）以及如何将 “CXL 共享内存 GPA 范围” 做成一个最小可用的硬编码权限检查。

---

## 快速验证：共享内存互通

VM1：

```bash
python3 shim/cxl_mem_test.py --uio /dev/uio0 --write --offset 0x1000 --data 'hello-from-vm1'
```

VM2：

```bash
python3 shim/cxl_mem_test.py --uio /dev/uio0 --read --offset 0x1000 --len 32
```

## 如果 /dev/uio0 只暴露 4KB（没有共享内存映射）

某些内核的 `uio_pci_generic` 只给出 BAR0（doorbell，4KB）。可以直接 mmap PCI BAR2：

- VM1：
  ```bash
  sudo python3 shim/cxl_server_agent.py \
    --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
    --map-size 134217728 \
    --redis 127.0.0.1:6379
  ```
- VM2：
  ```bash
  sudo python3 shim/cxl_client_agent.py \
    --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
    --map-size 134217728 \
    --listen 0.0.0.0:6380
  ```

也可用快捷脚本并传参：
```bash
sudo bash scripts/vm1_server.sh --path /sys/bus/pci/devices/0000:00:02.0/resource2 --map-size 134217728 --redis 127.0.0.1:6379
sudo bash scripts/vm2_client.sh --path /sys/bus/pci/devices/0000:00:02.0/resource2 --map-size 134217728 --listen 0.0.0.0:6380
```

`--map-size 134217728` 对应 128MB，可根据需要调整（需 >= ring 大小）。

---

## 当前推荐的“纯 C 直连”运行流程（版本 2，无 RESP）

### 环境要求
- 宿主机已启动双 VM（`bash scripts/host_quickstart.sh`），共享文件 `/tmp/cxl_shared.raw` 约 1GB。
- VM1、VM2 均可访问 `/sys/bus/pci/devices/0000:00:02.0/resource2`（如 uio 只给 4KB，请直接 mmap BAR2）。

### VM1：重编 + 启动二进制 ring Redis
```bash
ssh -p 2222 ubuntu@127.0.0.1
cd /mnt/hostshare/redis/src
echo ubuntu | sudo -S rm -rf ../deps/cachedObjs cxl_ring.d cxl_ring.o
echo ubuntu | sudo -S make MALLOC=libc USE_LTO=no CFLAGS='-O2 -fno-lto' LDFLAGS='-fno-lto' -j2
echo ubuntu | sudo -S env CXL_RING_PATH=/sys/bus/pci/devices/0000:00:02.0/resource2 \
    CXL_RING_MAP_SIZE=1073741824 CXL_RING_COUNT=4 \
    nohup ./redis-server --port 7379 --protected-mode no --save '' --appendonly no \
    >/tmp/redis_ring_direct.log 2>&1 &
```
日志应出现：`cxl ring: enabled ... rings=4 slots_per_ring=26624`

### VM2：编译 C 客户端（匹配版本 2）
```bash
ssh -p 2223 ubuntu@127.0.0.1
cd /mnt/hostshare/ring_client
gcc -O2 -Wall -Wextra -std=gnu11 -pthread -o /tmp/cxl_ring_direct cxl_ring_direct.c
```

### 压测（示例）
- 20 万请求（4 线程、pipeline，限流 max-inflight=5000）：
  ```bash
  echo ubuntu | sudo -S /tmp/cxl_ring_direct \
    --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
    --map-size 1073741824 --bench 200000 --pipeline --threads 4 --max-inflight 5000 \
    | tee /mnt/hostshare/results/ring_bench_threads4_c4_200k.log
  ```
  结果：SET ≈ 1,024,965 req/s；GET ≈ 1,852,467 req/s。

- 50 万请求（同参数）：
  ```bash
  echo ubuntu | sudo -S /tmp/cxl_ring_direct \
    --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
    --map-size 1073741824 --bench 500000 --pipeline --threads 4 --max-inflight 5000 \
    | tee /mnt/hostshare/results/ring_bench_threads4_c4_500k.log
 ```
  结果：SET ≈ 1,255,842 req/s；GET ≈ 1,605,614 req/s。

### 压测结果导出为 CSV（可选：延迟 + 开销拆解）
- `--latency`：开启 per-op 延迟采样，输出 avg/p50/p75/p90/p99/p99.9/p99.99。
- `--cost`：记录 push 重试次数、sleep 时间（粗粒度，默认关闭以免影响性能）。
- `--csv <path>`：CSV 输出位置，默认 `results/ring_metrics.csv`；自动追加，首行含表头。
- `--label <name>`：本次测试标签，便于区分多组结果。

示例（20 万请求、4 线程、pipeline、记录延迟与开销）：
```bash
echo ubuntu | sudo -S /tmp/cxl_ring_direct \
  --path /sys/bus/pci/devices/0000:00:02.0/resource2 \
  --map-size 1073741824 --bench 200000 --pipeline --threads 4 --max-inflight 5000 \
  --latency --cost --label ring_v2 \
  | tee /mnt/hostshare/results/ring_bench_threads4_c4_200k.log
# 生成的 CSV：/mnt/hostshare/results/ring_metrics.csv
```

### 与原生 Redis（TCP）的对照压测
VM1 启动原生 Redis（6379）：
```bash
cd /mnt/hostshare/redis/src
nohup ./redis-server --port 6379 --protected-mode no --save '' --appendonly no >/tmp/redis_native.log 2>&1 &
```
压测（4 线程，并发 4，20 万请求）：
```bash
./redis-benchmark -h 127.0.0.1 -p 6379 -t set,get -n 200000 -c 4 --threads 4 \
  | tee /mnt/hostshare/results/redis_bench_native_threads4_c4_large.log
```
结果：SET/GET 均 ≈ 199,800 req/s。

---

## 关键技术点与代码注释

- `redis/src/cxl_ring.c`
  - 版本号 `CXL_VERSION=2`，二进制协议（op/key_len/val_len + payload），不再走 RESP。
  - 默认 `slot_size=4096`，`rings=4`，map_size=1GB。head/tail 位于共享内存头部，req/resp 各占一半。
  - `handle_request`：直接解析二进制 GET/SET，调用 Redis 内部 API `setKey/lookupKeyRead`，再写回状态 + 值。

- `ring_client/cxl_ring_direct.c`
  - 版本号 2，与服务端匹配，默认 map_size=1GB。
  - `--threads` 控制并发线程，线程均匀分配 ring；`--pipeline` 开启批量；`--max-inflight` 控制在途请求数量（客户端限流，防止塞满 ring）。

以上文件已在关键位置添加注释，便于阅读和调整参数。

---

## 一键启动（宿主机）

如果已经有 Ubuntu cloud image（BASE_IMG），并安装好了 qemu/cloud-localds，可在宿主机直接运行：

```bash
BASE_IMG=/path/to/jammy-server-cloudimg-amd64.img \
bash scripts/host_quickstart.sh
```

脚本会自动创建共享文件、生成 qcow2/seed，并启动双 VM（SSH: 2222/2223）。必要时用环境变量调整内存/CPU/NUMA/共享路径。
