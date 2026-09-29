# Landlock Unprivileged Application Sandboxing

## 1. Overview & Background

**Landlock** is an innovative Linux Security Module (LSM) merged in Linux 5.13 designed to empower **unprivileged user-space processes (without root or `CAP_SYS_ADMIN`) to safely restrict their own system access rights (sandboxing)**.

Traditional Mandatory Access Control (MAC) architectures such as SELinux and AppArmor rely on privileged system-wide configurations, root daemons, and administrative policy languages. In contrast, modern security-sensitive user-space environments (such as web browser rendering engines, containerized microservices, untrusted plugin executors, and autonomous AI agents) require fine-grained self-confinement directly from application code:
1. **Unprivileged Self-Confinement (No Root Required)**:
   - Any standard process can configure and enforce its own sandbox boundary using standardized UAPI system calls (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`).
2. **Privilege Elevation Lockdown (`PR_SET_NO_NEW_PRIVS`)**:
   - Enforcing `prctl(PR_SET_NO_NEW_PRIVS, 1)` prior to sandboxing ensures that child processes cannot regain privileges via `setuid` binaries.
3. **Hierarchical Ruleset Stacking & Fail-Closed Semantics**:
   - As a process spawns children or applies additional Landlock layers, access rights can only be reduced (intersection), never expanded.
4. **Granular Filesystem & Network Controls**:
   - Governs file read, write, execution, and directory navigation, as well as TCP bind/connect port restrictions introduced in Linux 6.7+.

---

## 2. Real-World Analogy: Researcher Self-Isolation in a Cleanroom

The operational model of `Landlock` directly mirrors **a research scientist voluntarily locking themselves in a bio-safety cleanroom and shredding their master building keys**:

```
[ Traditional Unconfined Environment (Free Access: Employee badge opens any lab) ]
  Researcher (Process: lab): "I will execute an unverified third-party data analysis script!"
  Outcome:                   If malicious code is executed, it can read the user's home directory,
                             steal shared system files (/tmp/host_secret), and exfiltrate private SSH keys!

[ Landlock Sandboxed Environment (Voluntary Confinement & Master Key Destruction) ]
  Researcher (Process: lab): "Before handling untrusted data, I will confine my access:
                              1. I grant access ONLY to my dedicated workspace (/tmp/sandbox/).
                              2. I forfeit the right to acquire new privileges (PR_SET_NO_NEW_PRIVS).
                              3. I lock the door from the inside (landlock_restrict_self)!"

  [Untrusted Code Attempts Malicious Actions]
  Malicious Code:            "Attempting to read host secrets at /tmp/host_secret!"
  Landlock Kernel Guard:     "Your active ruleset only authorizes /tmp/sandbox/!
                              Access denied immediately (-EACCES: Permission denied)!"
  Malicious Code:            "Attempting to run a setuid binary to become root!"
  Landlock Kernel Guard:     "NO_NEW_PRIVS bit is permanently locked; privilege escalation blocked!"

  Final Result: Even if the application is fully exploited, the attacker remains trapped in the sandbox!
```

---

## 3. Core Architecture & Internal Mechanisms

### 3.1 Landlock 3-Step UAPI Workflow

Implementing a Landlock sandbox in user space involves three primary system calls:

```c
/* Step 1: Create a ruleset declaring the access rights to be managed */
struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                         LANDLOCK_ACCESS_FS_WRITE_FILE |
                         LANDLOCK_ACCESS_FS_READ_DIR,
};
int ruleset_fd = syscall(444 /* __NR_landlock_create_ruleset */,
                         &ruleset_attr, sizeof(ruleset_attr), 0);

/* Step 2: Add allowed path rules (PATH_BENEATH: authorize subtree) */
int dir_fd = open("/tmp/sandbox", O_PATH | O_DIRECTORY);
struct landlock_path_beneath_attr path_attr = {
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_READ_DIR,
    .parent_fd = dir_fd,
};
syscall(445 /* __NR_landlock_add_rule */, ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);

/* Step 3: Prevent privilege escalation and enforce restrictions */
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
syscall(446 /* __NR_landlock_restrict_self */, ruleset_fd, 0);
```

---

### 3.2 Access Rights Bitmask Definitions

Landlock provides fine-grained control over filesystem operations:

| Bitmask Flag | Description |
| :--- | :--- |
| `LANDLOCK_ACCESS_FS_EXECUTE` | Permit binary execution (`execve`) |
| `LANDLOCK_ACCESS_FS_WRITE_FILE` | Permit opening files with write flags |
| `LANDLOCK_ACCESS_FS_READ_FILE` | Permit opening files with read flags |
| `LANDLOCK_ACCESS_FS_READ_DIR` | Permit directory enumeration (`getdents64`) |
| `LANDLOCK_ACCESS_FS_REMOVE_DIR` | Permit removing empty directories (`rmdir`) |
| `LANDLOCK_ACCESS_FS_REMOVE_FILE` | Permit unlinking regular files (`unlink`) |
| `LANDLOCK_ACCESS_FS_MAKE_REG` | Permit creating regular files (`creat`, `mknod`) |
| `LANDLOCK_ACCESS_FS_MAKE_DIR` | Permit creating new directories (`mkdir`) |

- **Default Deny Principle**: For all actions declared in `handled_access_fs`, any path not explicitly whitelisted via `landlock_add_rule` is denied with `-EACCES`.

---

### 3.3 Hierarchical Stacking & Credential Inheritance

Landlock rulesets are attached to the process credentials (`struct cred`) as an immutable linked hierarchy:

```
[ Parent Process ] ── (Ruleset A: authorizes /usr and /tmp)
        │ fork() / execve()
        ▼
[ Child Process ]  ── (Inherits Ruleset A)
        │ landlock_restrict_self(Ruleset B: authorizes only /tmp/sandbox)
        ▼
[ Confined Child ] ── (Effective Access = Ruleset A ∩ Ruleset B = /tmp/sandbox only!)
```

- Subsequent `restrict_self` calls can only narrow permissible operations, preventing any form of sandbox relaxation.

---

## 4. Interactive Architecture Simulator

The interactive simulator below visualizes the Landlock system call lifecycle, VFS hook evaluation, authorized sandbox access, and denied sandbox escape attempts:

<iframe src="../../assets/diagrams/landlock/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. Attack Vectors & Lab Structure

### 5.1 Target Driver (`/proc/vuln_landlock`)

- **Source File**: `labs/29-landlock/vuln_landlock.c`
- **Proc Interface**: `/proc/vuln_landlock` (permissions `0666`)
- **Control Commands**:
  - `echo 'mode baseline' > /proc/vuln_landlock`: Switch to Mode 0 (Baseline: standard DAC, escape permitted)
  - `echo 'mode hardened' > /proc/vuln_landlock`: Switch to Mode 1 (Hardened: Landlock sandbox enforced, escape blocked with `-EACCES`)
  - `echo 'test sandbox' > /proc/vuln_landlock`: Test access to authorized path (`/tmp/sandbox/allowed_file.txt`)
  - `echo 'test escape' > /proc/vuln_landlock`: Test unauthorized access outside sandbox (`/tmp/host_secret`)
  - `echo 'test write' > /proc/vuln_landlock`: Test unauthorized system write
  - `echo 'run_bench' > /proc/vuln_landlock`: Run in-kernel automated benchmark and verification suite

---

### 5.2 Userland PoC Exploit (`exploit_landlock`)

- **Source File**: `labs/29-landlock/exploit.c`
- **Execution Workflow**:
  1. **ABI Detection**: Queries system call 444 to confirm kernel Landlock ABI version.
  2. **Phase 1 (Baseline Verification)**:
     - Confirms that unconfined access to `/tmp/host_secret` outside the sandbox succeeds.
  3. **Phase 2 (Hardened Verification)**:
     - Access to `/tmp/sandbox/allowed_file.txt` succeeds (GRANTED).
     - Access to `/tmp/host_secret` is blocked with `-EACCES`.

---

### 5.3 In-Guest Test Runner (`test_landlock`)

- **Source File**: `labs/29-landlock/test.sh` (installed to `/bin/test_landlock` in rootfs)
- **Validation Steps**:
  1. Verify `securityfs` and inspect `/sys/kernel/security/lsm` for `landlock`.
  2. Prepare test sandbox directory and secret file.
  3. Run `/bin/exploit_landlock` as unprivileged user `lab` (UID 1000).
  4. Inspect kernel `dmesg` for Landlock denial logs.

---

## 6. Kconfig Configuration Comparison

### 6.1 Defense Enabled (`configs/features/landlock.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 6.2 Defense Disabled (`configs/features/landlock-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LSM="capability"
```

---

## 7. Verification & QEMU Execution

### 7.1 Root Filesystem Build
```bash
./scripts/build_rootfs.sh --arch arm64 --force
./scripts/build_rootfs.sh --arch x86_64 --force
```

### 7.2 Kernel Compilation
```bash
# ARM64 Build
./scripts/build_kernel.sh --arch arm64 --feature landlock

# x86_64 Build
./scripts/build_kernel.sh --arch x86_64 --feature landlock
```

### 7.3 QEMU Automated Verification
```bash
# ARM64 Test
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-landlock/arch/arm64/boot/Image --test test_landlock --timeout 60

# x86_64 Test
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-landlock/arch/x86/boot/bzImage --test test_landlock --timeout 60
```
