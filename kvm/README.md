# Phase 4：KVM/EPT 权限单元改造提示

目标：在宿主机 KVM 模块中拦截访问 CXL 共享内存 GPA 范围，对“攻击者 VM” 注入 SIGBUS 或拒绝映射。

## 关键位置

- KVM EPT 违规处理（Intel VMX）：`arch/x86/kvm/vmx/vmx.c` 中的 `handle_ept_violation()`
- 通用 MMU 缺页路径：`arch/x86/kvm/mmu/mmu.c`，特别是 `kvm_mmu_page_fault()`

推荐切入点：在 `kvm_mmu_page_fault()` 里，缺页地址 `gpa` 已知，可以在进入慢速路径前做一次“CXL 区域” 判定。

## 硬编码最小实现（伪代码）

```c
static bool is_cxl_gpa(u64 gpa)
{
    // 根据 run_vms.sh 配置的共享文件映射区间来定（示例: 0x8000_0000 - 0x9000_0000）
    return gpa >= CXL_GPA_BASE && gpa < CXL_GPA_LIMIT;
}

static bool is_attacker_vm(struct kvm_vcpu *vcpu)
{
    // 简化：用 vmid 或者 vcpu->kvm->debugfs_id 硬编码
    return vcpu->kvm->debugfs_id == ATTACKER_ID;
}

if (is_cxl_gpa(fault->gpa) && is_attacker_vm(vcpu)) {
    kvm_inject_sigbus(vcpu, fault->gpa);
    return RET_PF_RETRY; // 或直接 return RET_PF_EMULATE
}
```

> 建议用模块参数或 debugfs 导出 `CXL_GPA_BASE/LIMIT` 和 `ATTACKER_ID`，便于开关。

## 编译与加载

1. 获取与宿主机匹配的 Linux 源码与 config，启用模块编译：
   ```bash
   make olddefconfig
   make -C tools/testing/selftests/kvm
   make M=arch/x86/kvm modules
   ```
2. 卸载/加载模块（需要 root）：
   ```bash
   sudo rmmod kvm_intel kvm
   sudo insmod arch/x86/kvm/kvm.ko
   sudo insmod arch/x86/kvm/intel/kvm-intel.ko cxl_base=0x80000000 cxl_len=0x10000000 attacker_id=2
   ```
3. 重新启动 QEMU 双 VM，验证：
   - 保护关闭：VM2 shim/benchmark 正常
   - 保护开启：VM2 在访问 CXL 区域时触发 SIGBUS/卡死

## 调试建议

- 打开 KVM tracepoint：`trace-cmd record -e kvm_ept`，观察 ept_violation
- 在 QEMU 命令行添加 `-d guest_errors` 查看访存报错
- 若需要更精细粒度，可在 `kvm_mmu_set_spte()` 中对 CXL 页的权限位（R/W/X）做动态调整，实现按 VM 粒度的权限表。
