# Kexec Restrictions & Hardening

## 1. Overview & Threat Model

**Kexec Restrictions & Hardening (`CONFIG_KEXEC`, `CONFIG_KEXEC_FILE`, `kexec_load_disabled`)** is a critical kernel defense architecture designed to govern the kexec mechanism—which enables an existing Linux system to transfer control to a new kernel directly without hardware reboot or firmware (UEFI/BIOS) re-initialization—thereby **preventing rootkit injection, arbitrary kernel substitution, and Secure Boot bypass attacks**.

In standard Linux configurations, the kexec system call was originally built for kernel diagnostics, crash dump generation (`kdump`), and rapid reboots. However, without strict constraints, it exposes an extraordinarily hazardous attack surface:

1. **Subverting Root of Trust via Arbitrary Memory Injection**:
   - `kexec_load(2)` accepts raw userspace memory segment buffer pointers directly to load the target kernel.
   - It performs zero cryptographic signature checks or integrity verification. An attacker who gains temporary root or `CAP_SYS_BOOT` privilege can immediately kexec a malicious, trojanized kernel or shellcode.
   - This attack bypasses hardware TPM measurement, UEFI Secure Boot verification chains, and IMA integrity validations, granting persistent, undetectable control over the host.
2. **Dual-Syscall Bifurcation**:
   - `kexec_load`: Userspace segment pointers, inherently unverified and dangerous.
   - `kexec_file_load`: Kernel loads the target binary from a file descriptor and enforces cryptographic PE/PKCS#7 signature verification against trusted keyrings (`CONFIG_KEXEC_SIG_FORCE`).
3. **Permanent One-Way Security Latch**:
   - Setting `/proc/sys/kernel/kexec_load_disabled` to `1` shuts down all kexec system calls system-wide.
   - Handled via `proc_dointvec_minmax` with `.extra1 = SYSCTL_ONE, .extra2 = SYSCTL_ONE`. Once locked to `1`, it cannot be switched back to `0` without a full hardware reboot.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/kexec-restrict/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: High-Security Facility Emergency Egress Shutter

The kexec hardening mechanism closely parallels **the emergency egress shutter and biometric airlock in a high-security defense facility**:

```
[ Unrestricted State (Raw kexec_load Allowed) ]
  Intruder:  "I stole an access badge (CAP_SYS_BOOT)! I will open the emergency egress gate and roll in my unauthorized replacement manager!"
  Gate:      "Accepting raw suitcases (userspace segments) with no luggage inspection. Granting immediate central control!" (Security Compromise)

[ One-Way Security Latch (kernel.kexec_load_disabled = 1) ]
  Officer:   "Immediately after routine startup, flip the master emergency gate latch to '1' (dropping steel shutters and physical interlocks)!"
  Intruder:  "Sending kexec commands to force the gate open!"
  Gate:      "One-way latch engaged! Even authorized managers cannot reopen the shutter without a physical facility power cycle (-EPERM blocked)!"

[ File-Based Signature Enforcement (kexec_file_load + CONFIG_KEXEC_SIG_FORCE) ]
  Intruder:  "Submitting a modified, unsigned replacement kernel image file!"
  Gatekeeper:"Verifying cryptographic signature against trusted facility key vault (.builtin_trusted_keys)!"
  Verdict:   "Digital signature missing or untrusted (-EKEYREJECTED blocked)!"
```

---

### 3. Kexec Defense Policy & State Matrix

| Defense Mechanism | Configuration & Flags | Enforcement Logic | Block Reason & Error Code | Security Assurance |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Kexec Block** | `CONFIG_LOCKDOWN_LSM`<br>(Integrity/Confidentiality) | Blocks userspace segment-based `sys_kexec_load` calls completely | `-EPERM`<br>(Lockdown Hook) | Eliminates arbitrary memory injection; prevents Secure Boot bypass |
| **Mandatory Signatures** | `CONFIG_KEXEC_SIG=y`<br>`CONFIG_KEXEC_SIG_FORCE=y` | Validates PE/PKCS#7 cryptographic signatures against trusted keyrings | `-EKEYREJECTED` | Prevents execution of unsigned, modified, or rogue kernels |
| **One-Way Sysctl Latch** | `kernel.kexec_load_disabled=1`<br>(One-Way Sysctl Latch) | Shuts down entry to all kexec syscalls across the entire system | `-EPERM` | 100% eliminates runtime kexec attack surface; cannot be undone to 0 |
| **Unhardened Default** | `kexec_load_disabled=0`<br>No signature enforcement | Permits arbitrary unsigned kexec with `CAP_SYS_BOOT` | None (Vulnerable) | Critical risk of persistent kernel substitution upon privilege escalation |

---

## 3. Kernel Configurations & Hardening Flags

### 1. Hardening Kconfig (`configs/features/kexec-restrict.config`)

```ini
# Linux Kernel Hardening Lab - Kexec Restrictions Feature Config
CONFIG_KEXEC_CORE=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_KEXEC_SIG=y
CONFIG_KEXEC_SIG_FORCE=y
```

- `CONFIG_KEXEC_CORE=y`: Enables core kexec subsystem foundations.
- `CONFIG_KEXEC_FILE=y`: Provides the safe, file descriptor-based `kexec_file_load` syscall.
- `CONFIG_KEXEC_SIG=y`: Integrates kernel cryptographic signature verification.
- `CONFIG_KEXEC_SIG_FORCE=y`: Strictly forbids loading any kernel image lacking a valid signature, returning `-EKEYREJECTED`.

### 2. Runtime Sysctl One-Way Latch Activation

Deployable via init scripts or `/etc/sysctl.d/99-kexec.conf`:

```bash
# Permanently disable kexec loading (transition from 0 to 1; cannot be reverted)
sysctl -w kernel.kexec_load_disabled=1
```

---

## 4. Hands-on Lab: `labs/40-kexec-restrict`

### 1. Lab Components

1. **Target Driver (`labs/40-kexec-restrict/vuln_kexec.c`)**:
   - Registered at `/proc/vuln_kexec` (0666) to simulate and test kexec constraints:
     - `load_raw`: Simulates raw userspace memory segment `kexec_load`.
     - `load_file signed`: Simulates authenticated `kexec_file_load`.
     - `load_file unsigned`: Simulates unverified `kexec_file_load`.
     - `set_disabled 1`: Engages the permanent one-way latch.
     - `set_disabled 0`: Attempts reversal (rejected with `-EPERM`).
     - `set_lockdown <integrity|confidentiality|none>`: Toggles simulated lockdown levels.
2. **Exploit PoC Binary (`labs/40-kexec-restrict/exploit.c`)**:
   - Stage 1: Demonstrates unhardened raw `kexec_load` vulnerability.
   - Stage 2: Validates Kernel Lockdown LSM blocking raw `kexec_load` (`-EPERM`).
   - Stage 3: Evaluates signature validation (`-EKEYREJECTED` for unsigned vs allowed for signed).
   - Stage 4: Verifies the permanent one-way latch and subsequent system-wide kexec lockout.
3. **Automated Test Runner (`labs/40-kexec-restrict/test.sh`)**:
   - Evaluates system sysctl, checks driver presence, runs PoC, and verifies dmesg security logs.

---

### 2. Execution Guide

```bash
# 1. Launch QEMU virtual machine
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=x86_64

# 2. Inspect kexec sysctl status
cat /proc/sys/kernel/kexec_load_disabled

# 3. Run automated verification suite
/bin/test_kexec_restrict
```

### 3. Expected Test Output

```text
================================================================
   Lab 40: Kexec Restrictions & Hardening Verification Suite    
   Kernel: 6.12.109 on x86_64                                   
================================================================

[*] Step 1: Inspecting kernel kexec_load_disabled parameter...
    kernel.kexec_load_disabled: 0

[*] Step 2: Inspecting Kernel Lockdown LSM status...
    lockdown status: [none] integrity confidentiality

[*] Step 3: Checking target driver at /proc/vuln_kexec...
[+] Target driver detected.

[*] Step 4: Querying driver status report...
=== Linux Kexec Restrictions & Hardening Status ===
kexec_load_disabled      : 0 (ENABLED)
CONFIG_KEXEC_SIG_FORCE   : ENABLED (Mandatory Signature)
Simulated Lockdown Level : none
Total Execution Attempts : 0
Raw kexec_load Attempts  : 0 (Blocked: 0)
File kexec Attempts      : 0 (Blocked: 0)
Allowed Kernel Boots     : 0
====================================================

[*] Step 5: Running Kexec Restrictions PoC...
===============================================================
   Linux Kexec Restrictions & Hardening Evaluation PoC         
===============================================================

[*] Stage 1: Testing Raw Segment kexec_load Attack...
[!] VULNERABLE: Raw kexec_load succeeded! Malicious kernel code could execute.

[*] Stage 2: Enabling Simulated Kernel Lockdown (Integrity Mode)...
[+] Retrying raw kexec_load under Lockdown...
[+] DEFENSE SUCCESS: Raw kexec_load blocked under Lockdown! (errno=1: Operation not permitted)

[*] Stage 3: Testing File-based kexec Signature Enforcement...
[+] Attempting unsigned kexec_file_load...
[+] DEFENSE SUCCESS: Unsigned image rejected! (errno=129: Key was rejected by service)
[+] Attempting signed kexec_file_load with valid cryptographic signature...
[+] SUCCESS: Authenticated signed kernel image verified and accepted.

[*] Stage 4: Testing Permanent One-Way Security Latch...
[+] Engaging security latch (set_disabled 1)...
[+] Attempting to revert security latch back to 0 (set_disabled 0)...
[+] DEFENSE SUCCESS: One-way latch enforced! Reversion forbidden (errno=1: Operation not permitted)
[+] Attempting any kexec operation while latch is locked...
[+] DEFENSE SUCCESS: All kexec calls locked out system-wide! (errno=1: Operation not permitted)

[*] Final Driver Diagnostics Report:
=== Linux Kexec Restrictions & Hardening Status ===
kexec_load_disabled      : 1 (DISABLED (One-way latch active))
CONFIG_KEXEC_SIG_FORCE   : ENABLED (Mandatory Signature)
Simulated Lockdown Level : integrity
Total Execution Attempts : 5
Raw kexec_load Attempts  : 2 (Blocked: 1)
File kexec Attempts      : 3 (Blocked: 2)
Allowed Kernel Boots     : 2
====================================================
[+] Kexec Restrictions verification complete.

[*] Step 6: Inspecting kernel dmesg for kexec hardening events:
[   42.102144] kexec_restrict: [VULNERABLE] Raw kexec_load allowed! Arbitrary kernel code execution possible.
[   42.103102] kexec_restrict: Simulated lockdown level set to 'integrity'
[   42.103890] kexec_restrict: [BLOCKED] Raw kexec_load prohibited under Kernel Lockdown (integrity) (-EPERM)
[   42.104612] kexec_restrict: [BLOCKED] Unsigned kexec image rejected (CONFIG_KEXEC_SIG_FORCE / Lockdown) (-EKEYREJECTED)
[   42.105340] kexec_restrict: [ALLOWED] Signed kernel image verified and accepted for kexec.
[   42.106012] kexec_restrict: [SYSCTL] kexec_load_disabled set to 1. Latch locked permanently.
[   42.106880] kexec_restrict: [LATCH REJECTED] Cannot reset kexec_load_disabled back to 0! (-EPERM)
[   42.107550] kexec_restrict: [BLOCKED] kexec rejected: kernel.kexec_load_disabled = 1 (-EPERM)

================================================================
   Lab 40 Test Complete: Verified Kexec Restrictions            
================================================================
```

---

## 5. Security Checklist & Best Practices

| Control Measure | Recommended Value | Security Guarantee |
| :--- | :--- | :--- |
| **Mandate File-Based Kexec** | `CONFIG_KEXEC_FILE=y` | Prohibits raw userspace memory pointers; routes loading through VFS |
| **Mandate Digital Signatures** | `CONFIG_KEXEC_SIG_FORCE=y` | Rejects unsigned, unverified, or tampered kernels (`-EKEYREJECTED`) |
| **Engage One-Way Sysctl Latch** | `sysctl kernel.kexec_load_disabled=1` | Permanently disables kexec post-boot; prevents runtime circumvention |
| **Enforce Kernel Lockdown** | `lockdown=integrity` | Disallows raw kexec_load and MSR tampering at the hardware boundary |
| **Least Privilege Enforcement** | Strip `CAP_SYS_BOOT` | Isolates containers and unprivileged daemons from initiating reboots |
