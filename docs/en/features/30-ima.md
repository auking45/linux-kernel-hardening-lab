# IMA (Integrity Measurement Architecture) & Runtime Appraisal

## 1. Overview & Background

**IMA (Integrity Measurement Architecture)** is an established kernel subsystem introduced in Linux 2.6.30. It provides cryptographic certainty regarding the state of local files before they are read, mapped, or executed by **measuring file contents (SHA-256), appraising them against reference golden values, and enforcing execution denial on tampered binaries**.

While standard access control mechanisms (DAC, MAC) enforce boundary restrictions between users and domains, they cannot determine whether a binary or configuration file itself has been modified offline, injected with malicious payloads, or altered by an attacker:
1. **Cryptographic Measurement**:
   - As files (`execve`, kernel modules, firmware) are accessed, IMA computes their SHA-256 digest and records the event in the kernel runtime measurement list.
2. **Hardware Root of Trust (TPM PCR 10 Extension)**:
   - Measurement events cryptographically extend **PCR 10 (Platform Configuration Register)** within a physical or virtual TPM:
   $$\text{PCR}_{10}^{\text{new}} = \text{SHA256}(\text{PCR}_{10}^{\text{old}} \parallel \text{File\_Hash})$$
   - This provides an immutable basis for Remote Attestation.
3. **Runtime Appraisal & Containment (Fail-Closed)**:
   - IMA verifies calculated digests against trusted reference values stored in the file's extended attributes (`security.ima` xattr). If a hash mismatch is detected, execution is aborted immediately with `-EACCES`.
4. **Flexible Policy Subsystem**:
   - In-kernel rules loaded into `/sys/kernel/security/ima/policy` define granular evaluation criteria across binaries, libraries, and appraisal modes (`log` vs `enforce`).

---

## 2. Real-World Analogy: Armored Cash Carrier Digital Seals

The architecture of `IMA` directly parallels **tamper-evident digital security seals and inspection checkpoints on armored cash transport containers**:

```
[ Traditional DAC/MAC Environment (Unverified Cargo: Driver ID checked, box unchecked) ]
  Courier (System Process): "I am delivering the cash lockbox (/bin/trusted_app) to the vault!"
  Guard (Kernel DAC):       "You have valid credentials (UID 0 / Root). Entrance granted."
  Outcome:                  Along the transit route, an adversary swapped the cash with counterfeit notes.
                            Without verifying the container contents, the vault becomes contaminated!

[ IMA Measurement & Appraisal (Cryptographic Fingerprint Inspection at Entry Gate) ]
  Courier (System Process): "Delivering the cash lockbox (/bin/trusted_app) to the vault!"
  IMA Guard (Kernel Hook):  "Halt! Before entry, we calculate the exact cryptographic hash of the box contents:
                             1. Computed Hash: [sha256:e3b0c442...]
                             2. The measurement is permanently sealed into the hardware safe (TPM PCR 10).
                             3. Comparing with the official manifest seal (security.ima xattr)..."

  [Scenario A: Untampered Original Box]
  IMA Guard:                "Manifest seal and computed hash match 100%! Entry authorized (ret = 0)."

  [Scenario B: 1-Byte Tampered Box]
  IMA Guard:                "Alarm! Hash mismatch detected (Tamper Alert)!
                             1. Dispatched integrity violation audit (type=1800 audit: invalid-hash).
                             2. ima_appraise=enforce is active: Vault access denied immediately (-EACCES)!"

  Final Result: Even with superuser privileges, a tampered binary is blocked from execution!
```

---

## 3. Core Architecture & Internal Mechanisms

### 3.1 SecurityFS Interface & Runtime Structures

IMA exposes operational metrics and policy control via `/sys/kernel/security/ima/`:

```bash
/sys/kernel/security/ima/
├── ascii_runtime_measurements    # Human-readable list of all measured files and PCR extensions
├── runtime_measurements_count    # Cumulative count of measurement entries recorded
├── violations                    # Cumulative count of integrity violations (e.g. concurrent writes)
└── policy                        # Control endpoint for loading appraisal and measurement rules
```

- **`ascii_runtime_measurements` Entry Format**:
  ```text
  10 <template-hash> ima-ng sha256:<file-hash> <file-path>
  ```
  - `10`: Target TPM PCR register index.
  - `ima-ng`: Extended template including algorithm identifier, hash digest, and pathname.

---

### 3.2 Runtime Appraisal Modes

The appraisal subsystem operates under configurable modes controlled via kernel boot parameters (`ima_appraise=...`):

1. **`ima_appraise=off`**:
   - Appraisal checks are disabled completely.
2. **`ima_appraise=log` (Baseline)**:
   - Integrity violations and hash mismatches generate audit warnings (`cause=invalid-hash`), but the kernel permits the binary to execute (`return 0`).
3. **`ima_appraise=enforce` (Hardened)**:
   - Any file failing hash or signature verification is denied execution immediately (`-EACCES`).
4. **`ima_appraise=fix`**:
   - Re-computes and writes updated hashes to `security.ima` upon file close, facilitating golden image provisioning.

---

### 3.3 Kernel Hook Pipeline

When an application invokes execution or file mapping, IMA intercepts the operation:

```c
/* kernel source: security/integrity/ima/ima_main.c */
int ima_bprm_check(struct linux_binprm *bprm)
{
    int ret;

    /* 1. Evaluate whether file matches active measurement/appraisal policy */
    ret = ima_must_measure(bprm->file, MAY_EXEC, BPRM_CHECK);
    if (ret < 0)
        return 0;

    /* 2. Compute SHA-256 digest and extend TPM PCR 10 */
    ima_store_measurement(iint, bprm->file, ...);

    /* 3. Validate against security.ima extended attribute */
    return ima_appraise_measurement(iint, bprm->file, ...);
}
```

- **BPRM_CHECK**: Validates binary executables passed to `execve()`.
- **FILE_CHECK**: Validates files opened via `sys_openat()`.
- **MMAP_CHECK**: Validates executable shared libraries loaded with `PROT_EXEC`.

---

## 4. Interactive Architecture Simulator

The interactive simulator below visualizes the SHA-256 hash calculation pipeline, TPM PCR 10 register extension, and the behavioral divergence between Log mode and Enforce mode upon detecting a tampered executable:

<iframe src="../../assets/diagrams/ima/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. Attack Vectors & Lab Structure

### 5.1 Target Driver (`/proc/vuln_ima`)

- **Source File**: `labs/30-ima/vuln_ima.c`
- **Proc Interface**: `/proc/vuln_ima` (permissions `0666`)
- **Control Commands**:
  - `echo 'mode log' > /proc/vuln_ima`: Set Mode 0 (Log mode: record audit events while allowing execution)
  - `echo 'mode enforce' > /proc/vuln_ima`: Set Mode 1 (Enforce mode: deny execution with `-EACCES` on hash mismatch)
  - `echo 'test valid' > /proc/vuln_ima`: Verify intact binary matching reference golden hash
  - `echo 'test tampered' > /proc/vuln_ima`: Test tampered binary with mismatched hash
  - `echo 'run_bench' > /proc/vuln_ima`: Execute in-kernel automated benchmark and verification suite

---

### 5.2 Userland PoC Exploit (`exploit_ima`)

- **Source File**: `labs/30-ima/exploit.c`
- **Execution Workflow**:
  1. **Pre-flight Checks**: Verify `/sys/kernel/security/ima/runtime_measurements_count` and `violations`.
  2. **Phase 1 (Log Mode Verification)**:
     - Confirms that tampered binary execution generates violations while succeeding (ALLOWED).
  3. **Phase 2 (Enforce Mode Verification)**:
     - Confirms valid binary succeeds (GRANTED).
     - Confirms tampered binary is blocked with `-EACCES`.

---

### 5.3 In-Guest Test Runner (`test_ima`)

- **Source File**: `labs/30-ima/test.sh` (installed to `/bin/test_ima` in rootfs)
- **Validation Steps**:
  1. Ensure `securityfs` is mounted and inspect `/sys/kernel/security/ima`.
  2. Confirm presence of `/proc/vuln_ima`.
  3. Run `/bin/exploit_ima` as unprivileged user `lab` (UID 1000).
  4. Inspect kernel `dmesg` for standard IMA audit records (`type=1800 audit(ima): ...`).

---

## 6. Kconfig Configuration Comparison

### 6.1 Defense Enabled (`configs/features/ima.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_DEFAULT_HASH_SHA256=y
CONFIG_IMA_WRITE_POLICY=y
CONFIG_IMA_READ_POLICY=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 6.2 Defense Disabled (`configs/features/ima-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=n
CONFIG_IMA=n
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
./scripts/build_kernel.sh --arch arm64 --feature ima

# x86_64 Build
./scripts/build_kernel.sh --arch x86_64 --feature ima
```

### 7.3 QEMU Automated Verification
```bash
# ARM64 Test
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-ima/arch/arm64/boot/Image --test test_ima --timeout 60

# x86_64 Test
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-ima/arch/x86/boot/bzImage --test test_ima --timeout 60
```
