# Phase 4: KVM/EPT permission unit hints

Goal: in the host KVM module, intercept accesses to the CXL shared-memory GPA range and reject/kill an “attacker VM” (e.g., inject SIGBUS or refuse the mapping).

## Key locations
- EPT violation handling (Intel VMX): `arch/x86/kvm/vmx/vmx.c` → `handle_ept_violation()`
- Generic MMU fault path: `arch/x86/kvm/mmu/mmu.c` → `kvm_mmu_page_fault()`

Recommended hook: in `kvm_mmu_page_fault()`, `fault->gpa` is known; check if it falls in the CXL window before entering the slow path.

## Minimal hardcoded sketch
```c
static bool is_cxl_gpa(u64 gpa)
{
    /* Align with the mapping range used by run_vms.sh, e.g., 0x8000_0000 - 0x9000_0000 */
    return gpa >= CXL_GPA_BASE && gpa < CXL_GPA_LIMIT;
}

static bool is_attacker_vm(struct kvm_vcpu *vcpu)
{
    /* Simplest form: hardcode vmid/debugfs_id */
    return vcpu->kvm->debugfs_id == ATTACKER_ID;
}

if (is_cxl_gpa(fault->gpa) && is_attacker_vm(vcpu)) {
    kvm_inject_sigbus(vcpu, fault->gpa);
    return RET_PF_RETRY; /* or RET_PF_EMULATE */
}
```

Tip: export `CXL_GPA_BASE/LIMIT` and `ATTACKER_ID` via module params or debugfs for easy toggling.

## Build and load
1. Get a kernel tree/config matching the host; enable module builds:
   ```bash
   make olddefconfig
   make -C tools/testing/selftests/kvm
   make M=arch/x86/kvm modules
   ```
2. Unload/load (root):
   ```bash
   sudo rmmod kvm_intel kvm
   sudo insmod arch/x86/kvm/kvm.ko
   sudo insmod arch/x86/kvm/intel/kvm-intel.ko \
       cxl_base=0x80000000 cxl_len=0x10000000 attacker_id=2
   ```
3. Reboot the dual-VM setup and verify:
   - Protection off: VM2 shim/benchmark runs normally.
   - Protection on: VM2 faults (SIGBUS/hang) on CXL range access.

## Debug tips
- Enable KVM tracepoints: `trace-cmd record -e kvm_ept` to watch ept_violation.
- Add `-d guest_errors` to the QEMU command line to log guest memory errors.
- For finer control, adjust R/W/X bits for CXL pages inside `kvm_mmu_set_spte()` to build a per-VM permission map.
