# EVM (Extended Verification Module) Metadata & XATTR Integrity Protection

## 1. Overview & Background

**EVM (Extended Verification Module)** is a kernel integrity subsystem merged in Linux 3.2. It provides **cryptographic integrity verification (HMAC or digital signatures) over extended security attributes (xattrs) and core inode metadata**, defending against offline manipulation and unauthorized permission tampering.

While IMA (Integrity Measurement Architecture) verifies file body contents (`security.ima`), EVM works symbiotically to eliminate the **file metadata attack surface**:
1. **Defense Against Privilege Escalation via Metadata Forgery**:
   - Prevents an attacker from injecting unauthorized capabilities (`security.capability` with `CAP_SETUID`) or altering ownership (`i_uid` set to 0) on unprivileged executables without touching the file content.
2. **Cryptographic Binding via HMAC-SHA256**:
   - Computes a keyed HMAC over `security.ima`, `security.selinux`, `security.apparmor`, `security.capability`, and POSIX inode attributes (UID, GID, Mode, Inode number) using a protected key in the kernel keyring, storing the result in the `security.evm` attribute.
3. **Fail-Closed Runtime Enforcement**:
   - If any protected attribute or ownership field is altered without recalculating a valid signature using the kernel's private/HMAC key, the kernel denies access and modification immediately (`-EPERM` or `-EACCES`).

---

## 2. Real-World Analogy: Notarized Deed with Embossed Notary Seal

The operational model of `EVM` mirrors **an embossed notary seal binding the contract body, signatory list, and official stamp into an indivisible legal instrument**:

```
[ IMA Alone (Content Verification Only: Vulnerable to Signature Forgery) ]
  Adversary:            "I did not modify a single line in the contract body (/bin/lab_tool)!"
  Adversary Operation:  "Instead, I stamp an unauthorized 'Unlimited Power of Attorney' seal
                         (security.capability: CAP_SETUID) on the signature page!"
  Outcome:              Because IMA only checks the text, the forged capability is trusted,
                        giving the attacker immediate root access!

[ IMA + EVM Integrated (Content + Stamps + Ownership Bound by Embossed Wax Seal) ]
  Adversary:            "Injecting CAP_SETUID capability onto /bin/lab_tool!"
  EVM Guard:            "Hold on! File metadata has been modified without authentication:
                         1. Observed Metadata: [security.ima + security.capability + UID 1000]
                         2. HMAC computed with kernel master key: [ffffffff...]
                         3. Stored notary seal (security.evm): [a1b2c3d4...]
                         4. HMAC mismatch detected! Unauthorized metadata tampering!"
  EVM Guard:            "Operation denied immediately (-EPERM: Operation not permitted)!"

  Final Result: Both the binary content and all associated security privileges remain immutable!
```

---

## 3. Core Architecture & Internal Mechanisms

### 3.1 Protected Metadata Composition

EVM calculates an HMAC across the following composite tuple:

$$\text{HMAC} = \text{HMAC-SHA256}(K_{\text{evm}}, \text{XATTRs} \parallel \text{Inode\_Metadata})$$

| Category | Field | Security Purpose |
| :--- | :--- | :--- |
| **Security XATTRs** | `security.ima` | IMA file content cryptographic hash |
| | `security.selinux` | SELinux process/object security context |
| | `security.apparmor` | AppArmor profile confinement label |
| | `security.smack` | SMAP access control label |
| | `security.capability` | POSIX file capabilities (`CAP_SETUID`, etc.) |
| **Inode Metadata** | `i_uid` | File owner user ID |
| | `i_gid` | File owner group ID |
| | `i_mode` | File permission bits and file type |
| | `i_ino` | Filesystem-internal inode number |
| | `i_generation` | Inode generation counter (prevents replay attacks) |

---

### 3.2 SecurityFS Control Node & Initialization

EVM exposes its state and enables key activation via `/sys/kernel/security/evm`:

```bash
/sys/kernel/security/evm
# Bitmask values:
# 1 = EVM_INIT_HMAC (HMAC symmetric key initialized)
# 2 = EVM_INIT_X509 (X.509 asymmetric digital signature initialized)
```

- During early userspace boot, key management utilities (`keyctl`) load the encrypted `evm-key` into the kernel master keyring and signal activation by writing to `/sys/kernel/security/evm`.

---

### 3.3 VFS Hook Interception

When an application modifies attributes or opens files, EVM intercepts the operation:

```c
/* kernel source: security/integrity/evm/evm_main.c */
int evm_inode_setxattr(struct dentry *dentry, const char *xattr_name,
                       const void *xattr_value, size_t xattr_value_len)
{
    /* 1. Check if the target xattr is protected by EVM */
    if (!evm_protected_xattr(xattr_name))
        return 0;

    /* 2. Pre-verify current security.evm integrity */
    if (evm_verify_current_integrity(dentry) != 0)
        return -EPERM; /* Refuse update if previous signature is broken */

    return 0;
}

void evm_inode_post_setxattr(struct dentry *dentry, ...)
{
    /* 3. Atomically compute new HMAC-SHA256 and update security.evm */
    evm_update_evmxattr(dentry, ...);
}
```

---

## 4. Interactive Architecture Simulator

The interactive simulator below demonstrates the cryptographic binding of inode metadata and security xattrs, the HMAC-SHA256 verification workflow, and the containment of capability injection and UID forgery attacks:

<iframe src="../../assets/diagrams/evm/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. Attack Vectors & Lab Structure

### 5.1 Target Driver (`/proc/vuln_evm`)

- **Source File**: `labs/31-evm/vuln_evm.c`
- **Proc Interface**: `/proc/vuln_evm` (permissions `0666`)
- **Control Commands**:
  - `echo 'mode permissive' > /proc/vuln_evm`: Set Mode 0 (Permissive mode: audit violations while allowing operations)
  - `echo 'mode enforce' > /proc/vuln_evm`: Set Mode 1 (Enforce mode: deny operations with `-EPERM` on HMAC mismatch)
  - `echo 'test valid' > /proc/vuln_evm`: Test legitimate metadata matching reference `security.evm` HMAC
  - `echo 'test tampered_cap' > /proc/vuln_evm`: Test injected unauthorized `security.capability` (CAP_SETUID)
  - `echo 'test tampered_uid' > /proc/vuln_evm`: Test altered inode ownership (UID 0)
  - `echo 'run_bench' > /proc/vuln_evm`: Execute in-kernel automated benchmark and verification suite

---

### 5.2 Userland PoC Exploit (`exploit_evm`)

- **Source File**: `labs/31-evm/exploit.c`
- **Execution Workflow**:
  1. **Pre-flight Checks**: Verify `/sys/kernel/security/evm` and active LSM stack.
  2. **Phase 1 (Permissive Mode Verification)**:
     - Confirms that unauthorized capability injection and ownership modification are permitted (ALLOWED).
  3. **Phase 2 (Enforce Mode Verification)**:
     - Valid metadata succeeds (GRANTED).
     - Capability tampering and UID modifications are strictly blocked with `-EPERM`.

---

### 5.3 In-Guest Test Runner (`test_evm`)

- **Source File**: `labs/31-evm/test.sh` (installed to `/bin/test_evm` in rootfs)
- **Validation Steps**:
  1. Ensure `securityfs` is mounted and inspect `/sys/kernel/security/evm`.
  2. Confirm presence of `/proc/vuln_evm`.
  3. Run `/bin/exploit_evm` as unprivileged user `lab` (UID 1000).
  4. Inspect kernel `dmesg` for standard EVM audit records (`type=1800 audit(evm): ...`).

---

## 6. Kconfig Configuration Comparison

### 6.1 Defense Enabled (`configs/features/evm.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_EVM=y
CONFIG_EVM_ATTR_FSUUID=y
CONFIG_EVM_ADD_XATTRS=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 6.2 Defense Disabled (`configs/features/evm-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=n
CONFIG_EVM=n
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
./scripts/build_kernel.sh --arch arm64 --feature evm

# x86_64 Build
./scripts/build_kernel.sh --arch x86_64 --feature evm
```

### 7.3 QEMU Automated Verification
```bash
# ARM64 Test
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-evm/arch/arm64/boot/Image --test test_evm --timeout 60

# x86_64 Test
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-evm/arch/x86/boot/bzImage --test test_evm --timeout 60
```
