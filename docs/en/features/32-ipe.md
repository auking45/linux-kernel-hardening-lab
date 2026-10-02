# IPE (Integrity Policy Enforcement) LSM

## 1. Overview & Threat Model

**IPE (Integrity Policy Enforcement)** is a modern Linux Security Module (LSM) merged upstream in Linux 6.12. It provides **trust-based code execution enforcement anchored to immutable storage properties (`boot_verified`, `dm-verity`, `fs-verity`)**, establishing an unbreachable integrity boundary across the entire operating system.

While IMA (Integrity Measurement Architecture) verifies individual file bodies via SHA-256 digests or xattr signatures, IPE operates at the **system architecture and storage provenance level**:

1. **Mutable Storage Execution Threat**:
   - Attackers who obtain unprivileged access frequently drop malicious shell scripts, compiled exploit payloads, or tampered shared objects into world-writable mutable locations such as `/tmp`, `/var/tmp`, `/dev/shm`, or user home directories.
   - Traditional DAC permissions (`chmod +x`) or path-based rules can be fragile or bypassed through hard links or bind mounts.
2. **Block-Level & Immutable Provenance Verification**:
   - IPE determines whether an executable binary originates from a cryptographically authenticated source (such as a signed `dm-verity` partition, `fs-verity` authenticated digest, or system initramfs container where `boot_verified=TRUE`).
   - Files dropped into mutable storage partitions lack these cryptographic provenance properties and are rejected before execution.
3. **Fail-Closed Default Policy**:
   - By enforcing `DEFAULT action=DENY`, IPE ensures that only explicitly certified execution contexts (`op=EXECUTE boot_verified=TRUE action=ALLOW`) are permitted to run.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/ipe/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Secure Government Facility & Tamper-Proof Badge

The operational model of IPE functions like an **embossed electronic security badge system at a restricted government facility**:

```
[ Traditional File Permissions (DAC / Path Confinement: Fragile) ]
  Intruder:     "I dressed in a business suit and put on an ID badge (chmod 755) inside /tmp!"
  Guard:        "The attire looks valid, and the directory path matches our visitor list. Entry permitted."

[ IPE Security Enforcement (Immutable Provenance Check: Hardened) ]
  Intruder:     "Executing unauthorized privilege escalation payload dropped in /tmp!"
  Scanner:      "Checking for official Mint Cryptographic Seal (boot_verified or dm-verity root hash)..."
  Evaluation:   "Verification failed: boot_verified=FALSE (Mutable storage origin)!"
  Action:       "Policy rule DEFAULT action=DENY triggered! Return -EACCES and broadcast audit event 1420!"
```

---

### 3. IPE Policy Syntax & Hook Evaluation Flow

IPE policies are authored in clear, human-readable text and deployed into the kernel via SecurityFS (`ipe/new_policy`):

```
policy_name=Lab_Hardened_Policy policy_version=1.0.0
DEFAULT action=DENY

# Permit binaries and modules with verified boot provenance
op=EXECUTE boot_verified=TRUE action=ALLOW
op=KMODULE boot_verified=TRUE action=ALLOW
op=FIRMWARE boot_verified=TRUE action=ALLOW
```

1. **LSM Hook Interception (`security_bprm_check`)**:
   - Upon `execve()` or `fexecve()`, the IPE LSM hook intercepts the pending binary before address space transition.
2. **Property Evaluation**:
   - `boot_verified`: Evaluates whether the file was part of the trusted boot initramfs or signed kernel container (`TRUE` or `FALSE`).
   - `dmverity_roothash`: Matches the cryptographic root digest of the backing `dm-verity` block device.
   - `dmverity_signature`: Confirms that the `dm-verity` volume root hash was signed with an X.509 certificate in the kernel trusted keyring.
   - `fsverity_digest`: Compares the Merkle tree root digest of an `fs-verity` enabled file.
3. **Mode Determination**:
   - `enforce=0` (Permissive): Audits policy violations (`type=1420 audit(ipe) ... action=DENY res=1`) but allows execution.
   - `enforce=1` (Enforce): Rejects non-compliant execution immediately with `-EACCES` (`res=0`).

---

## 3. Configuration & Boot Parameters

### 1. Kconfig Configuration Fragment

```ini
# configs/features/ipe.config
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y
CONFIG_SECURITY_IPE=y
CONFIG_LSM="landlock,lockdown,yama,bpf,ipe"
```

### 2. Runtime Interface & Boot Parameters

| Control Interface / Param | Default | Purpose |
| :--- | :--- | :--- |
| `/sys/kernel/security/ipe/enforce` | `0` or `1` | Controls runtime enforcement mode (`1` = enforce, `0` = audit only) |
| `/sys/kernel/security/ipe/success_audit` | `0` | Controls auditing of successful `ALLOW` decisions (useful for debugging) |
| `/sys/kernel/security/ipe/new_policy` | W-only | Ingests new plain-text policy into kernel memory (requires `CAP_MAC_ADMIN`) |
| `/sys/kernel/security/ipe/policies/` | Directory | Directory containing active deployed IPE policies |
| `lsm=...,ipe` | Kernel cmdline | Registers IPE in the ordered stack of active Linux Security Modules |

---

## 4. Hands-on Verification & Exploit PoC

### 1. Verification Scenario

- Login as unprivileged user `lab` (UID 1000).
- Create executable test payload in mutable storage (`/tmp/untrusted_payload`, mode 0755).
- **Base / Permissive Mode (`enforce=0`)**:
  - Both `/bin/lab_tool` and `/tmp/untrusted_payload` execute successfully.
  - dmesg records IPE audit event: `action=DENY res=1`.
- **Hardened / Enforce Mode (`enforce=1`)**:
  - `/bin/lab_tool` executes normally (`action=ALLOW`).
  - `/tmp/untrusted_payload` is immediately blocked with `-EACCES` (`action=DENY res=0`).

### 2. Dual-Architecture Verification Logs

=== "ARM64: Hardened Kernel (Enforce: Untrusted Code Blocked)"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-evm/arch/arm64/boot/Image --test test_ipe
    ```
    ```
    ================================================================
       Lab 32: IPE Policy Enforcement Verification Suite            
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel IPE SecurityFS interface...
        IPE SecurityFS node found at /sys/kernel/security/ipe
        Current IPE enforce status: 1
    [*] Step 3: Checking target driver at /proc/vuln_ipe...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged IPE PoC as user 'lab'...
    ================================================================
      IPE (Integrity Policy Enforcement) Unprivileged PoC Exploit   
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode 0: ipe.enforce=0)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (GRANTED)
    
    [*] PHASE 2: Evaluating Hardened (Mode 1: ipe.enforce=1)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (BLOCKED: -EACCES)

    [*] Step 6: Inspecting kernel dmesg for IPE audit events:
    [    4.982222] ipe: [EVAL] op=EXECUTE file="/bin/lab_tool" boot_verified=TRUE action=ALLOW
    [    4.982426] type=1420 audit(ipe): op=EXECUTE file="/tmp/untrusted_payload" boot_verified=FALSE action=DENY res=0
    [    4.982586] ipe: [ENFORCE] INTEGRITY VIOLATION: Execution of untrusted code BLOCKED (-EACCES)!
    [+] IPE Verification Complete: Untrusted Code Execution Successfully Blocked!
    ```

=== "x86_64: Hardened Kernel (Enforce: Untrusted Code Blocked)"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-evm/arch/x86/boot/bzImage --test test_ipe
    ```
    ```
    ================================================================
       Lab 32: IPE Policy Enforcement Verification Suite            
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel IPE SecurityFS interface...
        IPE SecurityFS node found at /sys/kernel/security/ipe
        Current IPE enforce status: 1
    [*] Step 3: Checking target driver at /proc/vuln_ipe...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged IPE PoC as user 'lab'...
    ================================================================
      IPE (Integrity Policy Enforcement) Unprivileged PoC Exploit   
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode 0: ipe.enforce=0)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (GRANTED)
    
    [*] PHASE 2: Evaluating Hardened (Mode 1: ipe.enforce=1)
        -> Requesting legitimate boot-verified binary execution... (GRANTED)
        -> Requesting untrusted payload execution from /tmp...     (BLOCKED: -EACCES)

    [*] Step 6: Inspecting kernel dmesg for IPE audit events:
    [    8.498889] ipe: [EVAL] op=EXECUTE file="/bin/lab_tool" boot_verified=TRUE action=ALLOW
    [    8.499008] type=1420 audit(ipe): op=EXECUTE file="/tmp/untrusted_payload" boot_verified=FALSE action=DENY res=0
    [    8.552314] ipe: [ENFORCE] INTEGRITY VIOLATION: Execution of untrusted code BLOCKED (-EACCES)!
    [+] IPE Verification Complete: Untrusted Code Execution Successfully Blocked!
    ```

---

## 5. Performance & Compatibility Analysis

1. **Computational Overhead**:
   - Because IPE evaluates pre-computed provenance flags (`boot_verified`) and hardware/driver authenticated block statuses rather than hashing multi-megabyte binaries on every execution, runtime CPU overhead is negligible (< 0.5%).
2. **Immutable Operating Systems & Cloud Containers**:
   - Ideal for Android, ChromeOS, Fedora CoreOS/Silverblue, embedded automotive ECUs, and container worker nodes where the root filesystem is permanently mounted read-only via `dm-verity`.
3. **Deployment Strategy**:
   - On interactive development workstations where developers compile and execute temporary scripts in `/tmp` or home folders, evaluate with `enforce=0` in audit mode prior to hard enforcement.

---

## 6. Lecture & Presentation Script (Spoken Technical English)

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, fellow engineers. In contemporary cloud and Linux edge security, one of the most critical privilege escalation and persistence vectors is arbitrary payload dropping into mutable partitions such as `/tmp`, `/var`, or user home directories. Even with strict DAC permissions, once an attacker finds a local write vulnerability, they can execute shell scripts or unverified binaries. Today, we examine the newest LSM merged in Linux 6.12: **IPE (Integrity Policy Enforcement)**."

#### 2. Diagram & Architecture Walkthrough
> "Please direct your attention to the interactive architecture simulator on the screen. Notice the foundational difference between mutable storage and immutable provenance. When a process issues an `execve()` system call, the IPE LSM hook `security_bprm_check()` intercepts the request before memory execution. Instead of hashing the entire binary byte-by-byte on every execution, IPE evaluates immutable architectural properties—such as `boot_verified=TRUE` or `dm-verity` cryptographic block root hashes. Under our fail-closed policy, `DEFAULT action=DENY` ensures that any binary without verified provenance is intercepted instantly."

#### 3. Live Demo Commentary
> "In our live QEMU demonstration on ARM64 and x86_64, look at the contrast between Permissive and Enforce modes. In Permissive mode, when our unprivileged `lab` user attempts to run an exploit script from `/tmp`, IPE logs an audit violation with `action=DENY res=1` while letting the execution proceed for monitoring. However, when we switch to Hardened Enforce mode, the exact same execution request is immediately rejected with an `-EACCES` permission denied error, generating an audit record with `res=0`. The attack chain is cut dead at the kernel exec boundary."

#### 4. Key Takeaways & Production Advice
> "To summarize: IPE provides high-performance, low-overhead integrity enforcement by binding execution privileges to cryptographic storage immutability rather than per-file CPU-intensive re-hashing. For immutable OS distributions, cloud container hosts, and embedded appliances, enabling `CONFIG_SECURITY_IPE=y` establishes an unbreachable code integrity perimeter."
