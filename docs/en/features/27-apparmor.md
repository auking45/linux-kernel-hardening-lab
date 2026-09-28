# AppArmor Profile-Based Process Isolation & Path Confinement (Path MAC)

## 1. Overview & Background

**AppArmor (Application Armor)** is an established Linux Security Module (LSM) that enforces Mandatory Access Control (MAC) based on **full file system pathnames**. Unlike SELinux, which associates security contexts with filesystem inodes and requires extended attribute (`xattr`) support, AppArmor specifies access policies using human-readable path rules. This makes profile authoring, auditing, and maintenance straightforward and intuitive.

Modern enterprise distributions (Ubuntu, Debian, SUSE) and container engines (Docker, Kubernetes, containerd) rely on AppArmor as a primary security layer for several key reasons:
1. **Filesystem-Agnostic Path Control**:
   - Uniform security policies apply across all filesystem types (ext4, xfs, tmpfs, nfs) without requiring filesystem labeling or extended attribute support.
2. **Enforcement of the Principle of Least Privilege**:
   - Even if an attacker gains arbitrary code execution within a process, accessible file directories, network sockets, IPC mechanisms, and `ptrace` tracing capabilities remain strictly confined to the pre-declared profile.
3. **Progressive Deployment Model (Complain vs Enforce)**:
   - AppArmor supports a dual-mode workflow: **Complain mode** (logs policy violations without blocking for profile development and auditing) and **Enforce mode** (strictly denies unauthorized operations at the kernel level), enabling safe zero-downtime policy maturation.

---

## 2. Real-World Analogy: Bank Branch Badges & Work Area Protocols

The operational model of `AppArmor` directly mirrors **physical access control and work area policies in a banking facility**:

```
[ Traditional DAC Environment (Free Access: Employee ID allows visiting any room) ]
  Worker (Process: lab):  "I want to open the main bank vault (/tmp/secret_token)!"
  Guard (Kernel DAC):     "You have a valid bank badge (UID 1000). The door is unlocked."
  Outcome:                A rogue or compromised insider accesses confidential assets and financial databases!

[ AppArmor Complain Mode (Audit/Learning Mode: Record infractions without blocking) ]
  Worker (Process: lab):  "I will open the vault (/tmp/secret_token) and connect an unauthorized tap (Raw Socket)!"
  Officer (AppArmor):     "Protocol infraction detected! However, this station is in audit mode.
                           The request is permitted, and a warning is logged to auditd/dmesg."
  Outcome:                Normal operations continue uninterrupted while violation patterns are gathered for profiling.

[ AppArmor Enforce Mode (Strict Mandatory Confinement: Instant denial for unauthorized areas) ]
  Worker (Process: lab):  "I want to open the main bank vault (/tmp/secret_token)!"
  Officer (AppArmor):     "Your assigned profile only authorizes desk ledger access (/tmp/allowed_file)!
                           Vault access is denied immediately (-EACCES)!"
  Worker (Process: lab):  "Then I will create a raw packet socket or attach a debugger (ptrace) to another worker!"
  Officer (AppArmor):     "No network or ptrace permissions granted! Request blocked (-EPERM)!"

  Final Result: Even if an attacker hijacks the application process, unauthorized files, sockets, and memory are protected!
```

---

## 3. Core Architecture & Internal Mechanisms

### 3.1 Pathname Resolution Engine

When a file operation occurs, rather than relying solely on inode numbers, AppArmor hooks (`apparmor_file_open` and `apparmor_inode_permission`) compute the normalized absolute path of the target within the Virtual File System (VFS):

```c
/* kernel source: security/apparmor/lsm.c & file.c */
static int apparmor_file_open(struct file *file)
{
    struct aa_profile *profile = aa_current_profile();
    struct path_cond cond = {
        .uid = file_inode(file)->i_uid,
        .mode = file_inode(file)->i_mode,
    };
    struct aa_perms perms;

    if (unconfined(profile))
        return 0;

    /* Compute normalized absolute path from dentry/vfsmount */
    aa_path_perm(OP_OPEN, profile, &file->f_path, 0,
                 MAY_READ | MAY_WRITE, &cond, &perms);

    return aa_check_perms(profile, &perms, ...);
}
```

- **Path Normalization**: Resolves symbolic links, mount namespace boundaries, and path canonicalization using `d_path()`.
- **Deterministic Finite Automata (DFA)**: Compiled binary profiles are loaded into kernel memory as highly optimized DFA state machines, achieving near $O(1)$ pathname pattern matching.

---

### 3.2 Profile State Machine & Confinement Modes

Each process confined by AppArmor operates in one of several states:

1. **Unconfined**:
   - The process runs without an AppArmor profile; standard Linux DAC (permission bits, POSIX ACLs) applies.
2. **Complain (Audit Mode)**:
   - Operations violating the profile policy are permitted (`return 0`), while audit records (`apparmor="ALLOWED"`) are dispatched to the kernel ring buffer (`dmesg`) and `auditd`.
3. **Enforce (Strict Confinement)**:
   - Any operation not explicitly permitted by the profile is denied immediately (`-EACCES` or `-EPERM`), generating audit denial events (`apparmor="DENIED"`).
4. **Kill Mode**:
   - Specific critical infractions trigger an immediate `SIGKILL` termination of the violating process.

---

### 3.3 SecurityFS Interface & Dynamic Management

AppArmor exports policy management controls via the `/sys/kernel/security/apparmor/` directory:

```bash
/sys/kernel/security/apparmor/
├── profiles              # List of all currently loaded profiles and active modes
├── .load                 # Interface to load new binary profiles into the kernel
├── .replace              # Atomic in-place profile update interface
└── .remove               # Interface to unload profiles
```

- **`/proc/[pid]/attr/apparmor/current`**: Reports the active profile name and mode for a given task, and enables dynamic sub-profile transitions via `aa_change_hat` or `aa_change_profile`.

---

## 4. Interactive Architecture Simulator

The interactive simulator below visualizes AppArmor's pathname resolution pipeline, DFA policy matching engine, mode transitions (Complain vs Enforce), and SecurityFS management interface:

<iframe src="../../assets/diagrams/apparmor/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. Attack Vectors & Lab Structure

### 5.1 Target Driver (`/proc/vuln_apparmor`)

- **Source File**: `labs/27-apparmor/vuln_apparmor.c`
- **Proc Interface**: `/proc/vuln_apparmor` (permissions `0666`)
- **Control Commands**:
  - `echo 'mode complain' > /proc/vuln_apparmor`: Switch to Mode 0 (Complain mode: violations permitted and audited)
  - `echo 'mode enforce' > /proc/vuln_apparmor`: Switch to Mode 1 (Enforce mode: strict blocking of file, network, ptrace violations)
  - `echo 'test normal' > /proc/vuln_apparmor`: Test access to authorized path (`/tmp/allowed_file`)
  - `echo 'test file' > /proc/vuln_apparmor`: Test access to restricted secret file (`/tmp/secret_token`)
  - `echo 'test network' > /proc/vuln_apparmor`: Test unauthorized raw packet socket creation (`AF_PACKET`)
  - `echo 'test ptrace' > /proc/vuln_apparmor`: Test unauthorized cross-process memory inspection (`PTRACE_ATTACH`)
  - `echo 'run_bench' > /proc/vuln_apparmor`: Run in-kernel automated benchmark and verification suite

---

### 5.2 Userland PoC Exploit (`exploit_apparmor`)

- **Source File**: `labs/27-apparmor/exploit.c`
- **Execution Workflow**:
  1. **Pre-flight Checks**: Inspect `/sys/kernel/security/lsm`, `/proc/self/attr/apparmor/current`, and `/sys/kernel/security/apparmor/profiles`.
  2. **Phase 1 (Complain Mode Verification)**:
     - Confirms that unauthorized file, network, and ptrace operations succeed without blocking (ALLOWED).
  3. **Phase 2 (Enforce Mode Verification)**:
     - Authorized file access succeeds (GRANTED).
     - Unauthorized path access is blocked with `-EACCES`.
     - Raw socket and ptrace calls are blocked with `-EPERM`.

---

### 5.3 In-Guest Test Runner (`test_apparmor`)

- **Source File**: `labs/27-apparmor/test.sh` (installed to `/bin/test_apparmor` in rootfs)
- **Validation Steps**:
  1. Ensure `securityfs` is mounted and verify `/sys/kernel/security/apparmor`.
  2. Confirm presence of `/proc/vuln_apparmor`.
  3. Run `/bin/exploit_apparmor` as unprivileged user `lab` (UID 1000).
  4. Inspect kernel `dmesg` for AppArmor audit events (`apparmor="ALLOWED"`, `apparmor="DENIED"`).

---

## 6. Kconfig Configuration Comparison

### 6.1 Defense Enabled (`configs/features/apparmor.config`)
```ini
CONFIG_NET=y
CONFIG_INET=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_SECURITY_APPARMOR_HASH=y
CONFIG_SECURITY_APPARMOR_HASH_DEFAULT=y
CONFIG_DEFAULT_SECURITY_APPARMOR=y
CONFIG_LSM="landlock,lockdown,yama,apparmor,bpf"
```

> [!NOTE]
> AppArmor hooks cover network sockets and packet operations, necessitating `CONFIG_NET=y` and `CONFIG_INET=y`.

### 6.2 Defense Disabled (`configs/features/apparmor-disabled.config`)
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
./scripts/build_kernel.sh --arch arm64 --feature apparmor

# x86_64 Build
./scripts/build_kernel.sh --arch x86_64 --feature apparmor
```

### 7.3 QEMU Automated Verification
```bash
# ARM64 Test
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-apparmor/arch/arm64/boot/Image --test test_apparmor --timeout 60

# x86_64 Test
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-apparmor/arch/x86/boot/bzImage --test test_apparmor --timeout 60
```
