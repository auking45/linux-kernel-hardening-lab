# Stackable LSM Architecture and Multiple LSM Activation (lsm=...)

## 1. Overview and Background

Introduced in Linux 2.6, the **Linux Security Modules (LSM)** framework serves as the standard Mandatory Access Control (MAC) infrastructure operating directly after standard Discretionary Access Control (DAC) permission checks. Early LSM designs relied on a single global function pointer table (`security_ops`), allowing only one "Major" security module (SELinux, AppArmor, Smack, or TOMOYO) to be registered at any given time.

Modern enterprise and cloud-native environments, however, require multiple specialized security layers running concurrently:
1. **Separation of Specialized Security Domains**:
   - System-wide Mandatory Access Control (MAC): AppArmor, SELinux
   - Process memory debugging and injection protection: Yama
   - Unprivileged application filesystem and network sandboxing: Landlock
   - Firmware and kernel module supply chain integrity: LoadPin
   - Direct kernel tampering and hardware register protection: Lockdown
   - Dynamic programmable security policies: BPF LSM
2. **Overcoming Monolithic Monopoly**:
   - Starting with Linux 5.1 (2019), the kernel eliminated the single function pointer table, transitioning to **stackable doubly-linked lists (`hlist_head`)** and **composite shared security blobs**.
   - Multiple independent security modules now coexist seamlessly, evaluating hooks sequentially whenever a kernel security event occurs.

---

## 2. Real-World Analogy: Airport Multi-Stage Security Checkpoints

The mechanism of `Stackable LSM` is directly comparable to **multi-stage airport security checkpoints with a unified credential badge**:

```
[ Legacy Single LSM Model (Only One Screening Station Allowed) ]
  Passenger (Syscall): "I want to board the aircraft (access kernel resources)!"
  Airport Authority:   "Our terminal can only operate ONE checkpoint:
                        either the ID inspector (SELinux) OR baggage X-ray (AppArmor)!"
  Outcome:             Choosing ID inspection misses weapons in luggage;
                       choosing baggage X-ray misses forged passports.
                       A dangerous mutually exclusive security gap!

[ Modern Stackable LSM Model (Chained Checkpoints & Composite Badge) ]
  Passenger (Syscall): "I want to board the aircraft!"
  Unified Badge:       [ ID Tag | Liquid Sticker | Hazard Clearance | Customs Stamp ]
  
  [Checkpoint 1: Identity / POSIX DAC (Capability)] ──► PASS (ret = 0)
  [Checkpoint 2: Sandboxed Confinement (Landlock)]   ──► PASS (ret = 0)
  [Checkpoint 3: Dangerous Items Block (Lockdown)]   ──► "Tampering Attempt Detected!" (ret = -EPERM)
  [Checkpoint 4: Body Pat-Down (Yama)]               ──► (Bypassed! Rejected at Station 3, immediate exit)

  Final Outcome: If ANY checkpoint denies access, the entire request is terminated (Fail-Closed)!
```

1. **Legacy Monopoly**:
   - Each kernel object provided only a single `void *security` pointer, sparking conflicts between modules.
2. **Stackable Multi-Chain**:
   - Each object receives a single composite blob split into dedicated offsets for every active module.
   - All modules in the chain are evaluated sequentially; any module returning an error triggers immediate short-circuit termination (Fail-Closed).

---

## 3. Core Architecture and Internal Mechanics

### 3.1 Hook Chains and Fail-Closed Evaluation

Every security event in the kernel is represented as an entry within `struct security_hook_heads`:

```c
/* include/linux/lsm_hook_defs.h & security/security.c */
struct security_hook_heads {
    struct hlist_head bprm_check_security;
    struct hlist_head file_open;
    struct hlist_head inode_permission;
    struct hlist_head ptrace_access_check;
    /* ... over 200 security hook heads ... */
};

/* Hook evaluation macro */
#define call_int_hook(FUNC, IRC, ...) ({       \
    int RC = IRC;                              \
    struct security_hook_list *P;              \
    hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
        RC = P->hook.FUNC(__VA_ARGS__);        \
        if (RC != 0)                           \
            break; /* Fail-Closed! Immediately terminate loop */ \
    }                                          \
    RC;                                        \
})
```

- **Fail-Closed Principle**:
  - Registered modules execute in order.
  - Access is granted only if **every** module returns `0` (success).
  - If any module returns a negative error code (such as `-EACCES` or `-EPERM`), the loop breaks immediately, preventing subsequent modules from running and rejecting the syscall.

---

### 3.2 Composite Shared Security Blobs

The historical barrier preventing multi-LSM stacking—exclusive ownership of `void *security`—was solved via **single contiguous slab allocation with fixed byte offsets**:

```c
/* include/linux/lsm_hooks.h */
struct lsm_blob_sizes {
    int lbs_cred;   /* Task credentials size */
    int lbs_file;   /* File structure size */
    int lbs_inode;  /* Inode metadata size */
    int lbs_ipc;    /* IPC objects size */
    int lbs_msg;    /* SysV message size */
    int lbs_task;   /* Task struct size */
    int lbs_xattr;  /* Extended attribute size */
};
```

1. **Boot-Time Aggregation**:
   - During early boot initialization, the kernel aggregates the `lsm_blob_sizes` requested by all active modules.
2. **Single Allocation and Assigned Offsets**:
   - When kernel objects (`struct cred`, `struct inode`, etc.) are created, a single `kmalloc` allocates the combined blob.
   - Each module receives a dedicated relative offset (e.g., Landlock gets `+16`, SafeSetID gets `+24`), accessing its private state via inline accessor helpers.

---

### 3.3 Boot Parameter Control (`lsm=...`) and SecurityFS

While `CONFIG_LSM` establishes the default compile-time stack, bootloader parameters allow runtime overrides:

```bash
# Compile-time default in Kconfig
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,bpf"

# Runtime command-line override
lsm=landlock,lockdown,yama,bpf lsm.debug
```

- **`lsm=...`**: Explicitly defines which LSMs to initialize and their execution order. Unlisted modules remain inactive (`capability` is always implicitly placed first).
- **`lsm.debug`**: Dumps detailed module registration orders, blob sizes, and allocated offsets to `dmesg`.
- **`/sys/kernel/security/lsm`**: Exposed via `securityfs`, presenting the active LSM stack as a comma-separated list.
- **`lsm_list_modules` (Syscall 461)**: Introduced in Linux 6.8, this dedicated UAPI syscall returns active module IDs to userspace.

---

## 4. Interactive Architecture Simulator

Explore the sequential hook execution pipeline, fail-closed semantics, shared blob layout, and runtime parameter configuration using the interactive simulator below:

<iframe src="../../assets/diagrams/lsm-stacking/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. Lab Architecture & Verification Guide

### 5.1 Target Driver (`/proc/vuln_lsm`)

- **File Path**: `labs/26-lsm-stacking/vuln_lsm_stacking.c`
- **Exposed Node**: `/proc/vuln_lsm` (permissions `0666`)
- **Control Commands**:
  - `echo 'mode baseline' > /proc/vuln_lsm`: Mode 0 (DAC/Capability only, advanced stacked LSMs bypassed)
  - `echo 'mode hardened' > /proc/vuln_lsm`: Mode 1 (Stacked LSM enforcement active, fail-closed containment)
  - `echo 'test_access normal' > /proc/vuln_lsm`: Tests benign access request
  - `echo 'test_access yama' > /proc/vuln_lsm`: Tests unauthorized ptrace inspection (Yama target)
  - `echo 'test_access landlock' > /proc/vuln_lsm`: Tests path write outside sandbox (Landlock target)
  - `echo 'test_access lockdown' > /proc/vuln_lsm`: Tests direct kernel memory tampering (Lockdown target)
  - `echo 'run_bench' > /proc/vuln_lsm`: Runs internal automated verification benchmark

---

### 5.2 Userland PoC Exploit (`exploit_lsm_stacking`)

- **File Path**: `labs/26-lsm-stacking/exploit.c`
- **Workflow**:
  1. Inspects active LSM stack via `/sys/kernel/security/lsm` and syscall 461 (`__NR_lsm_list_modules`).
  2. Evaluates Baseline mode to confirm policy violations succeed when stacking is disabled.
  3. Evaluates Hardened mode to verify fail-closed blocking across Yama, Landlock, and Lockdown.

---

### 5.3 In-Guest Test Runner (`test_lsm_stacking`)

- **File Path**: `labs/26-lsm-stacking/test.sh` (packaged as `/bin/test_lsm_stacking`)
- **Workflow**:
  1. Ensures `securityfs` is mounted and queries active LSMs.
  2. Confirms presence and status of `/proc/vuln_lsm`.
  3. Executes `/bin/exploit_lsm_stacking` as unprivileged user `lab`.
  4. Inspects kernel `dmesg` logs for driver events.

---

## 6. Kconfig Configuration Comparison

### 6.1 Hardened Configuration (`configs/features/lsm-stacking.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_YAMA=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_LOADPIN=y
CONFIG_SECURITY_SAFESETID=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,bpf"
```

### 6.2 Baseline Configuration (`configs/features/lsm-stacking-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LSM="capability"
```

---

## 7. Verification and QEMU Testing

### 7.1 Root Filesystem Build
```bash
./scripts/build_rootfs.sh --arch arm64 --force
./scripts/build_rootfs.sh --arch x86_64 --force
```

### 7.2 Kernel Build
```bash
# Build ARM64 Kernel
./scripts/build_kernel.sh --arch arm64 --feature lsm-stacking

# Build x86_64 Kernel
./scripts/build_kernel.sh --arch x86_64 --feature lsm-stacking
```

### 7.3 Automated QEMU Verification
```bash
# Verify ARM64
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-lsm-stacking/arch/arm64/boot/Image --test test_lsm_stacking --timeout 30

# Verify x86_64
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-lsm-stacking/arch/x86/boot/bzImage --test test_lsm_stacking --timeout 30
```
