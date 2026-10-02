# Kernel Lockdown LSM

## 1. Overview & Threat Model

**Kernel Lockdown LSM** is an official Linux Security Module (LSM) merged upstream in Linux 5.4 that **prevents userland processes—even the superuser (root / UID 0 / `CAP_SYS_ADMIN`)—from modifying or extracting secrets from running kernel memory, hardware I/O ports, or unsigned kernel modules**.

Under the traditional Unix security paradigm, root was universally privileged, possessing unconstrained access to physical memory (`/dev/mem`, `/dev/kmem`), processor MSRs, PCI configuration space, and kernel memory dumps (`/proc/kcore`). However, in modern environments backed by UEFI Secure Boot and confidential container runtimes, several critical threats arise:

1. **Ring 0 Escalation & Rootkit Persistence after Root Compromise**:
   - Once an attacker gains root access through application vulnerabilities, they can overwrite kernel text via `/dev/mem` or inject unsigned rootkits (`insmod evil.ko`), establishing untraceable Ring 0 persistence.
   - Attackers can exploit `kexec_load` to boot an unverified, malicious kernel, completely breaking the chain of trust initialized by UEFI Secure Boot.
2. **Exfiltration of Kernel Secrets & Cryptographic Keys**:
   - Root can dump kernel memory via `/proc/kcore` or attach BPF kprobe probes to extract full-disk encryption master keys, user credentials, and kernel cryptographic seeds.
3. **Establishing an Absolute Boundary between Userland and Ring 0**:
   - Lockdown LSM enforces a three-tiered defense model (`none`, `integrity`, `confidentiality`) making it mathematically and architecturally impossible for root to violate kernel integrity or confidentiality.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/lockdown/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Physical Sealed Safety Cage in a Nuclear Facility

The operational model of Kernel Lockdown LSM closely mirrors **strict physical access controls inside a nuclear power facility**:

```
[ None Mode (Traditional Omnipotent Root Model) ]
  Plant Director (Root): "I am the top authority here! I will directly solder wires to the control rods
                          (/dev/mem) and install custom untested components (unsigned drivers)."
  Security Guard:        "Granted. You possess administrator credentials." (High disaster risk)

[ Integrity Lockdown Mode ]
  Plant Director (Root): "I intend to modify hardware wiring or hook custom debugging boards into the reactor."
  Automated Interlock:   "Integrity Seal active! Even the director cannot alter physical circuitry
                          or install uncertified hardware."
  Outcome:               "Access blocked instantly (-EPERM). Reactor integrity guaranteed."

[ Confidentiality Lockdown Mode ]
  Plant Director (Root): "I will copy the secret cryptographic command algorithms and reactor telemetry
                          (/proc/kcore) and take it outside."
  Security Inspector:    "Confidentiality lock active! Core telemetry snapshot extraction is denied!"
  Outcome:               "Access denied (-EPERM). Core secrets protected from exfiltration."
```

---

### 3. Lockdown Levels & Kernel Decision Matrix

Kernel Lockdown LSM enforces restrictions by calling the internal `security_locked_down(enum lockdown_reason what)` hook:

| Lockdown Level | SecurityFS String | Enforced Restrictions & Blocked Operations | Permitted Operations |
| :--- | :--- | :--- | :--- |
| **0: None** | `[none] integrity confidentiality` | No restrictions (identical to traditional Linux root) | All superuser operations permitted |
| **1: Integrity** | `none [integrity] confidentiality` | - Writing to `/dev/mem`, `/dev/kmem`, `/dev/port`<br>- Loading unsigned kernel modules (`CONFIG_MODULE_SIG`)<br>- Booting into unverified kernels via `kexec_load`<br>- Arbitrary MSR register writes & custom ACPI table injection<br>- Direct PCI device memory mapping | Normal userland tasks, memory reads (`/proc/kcore`, etc.) |
| **2: Confidentiality** | `none integrity [confidentiality]` | **Includes all restrictions from Integrity Mode** +<br>- Reading `/dev/mem` and `/dev/kmem`<br>- Reading kernel core dumps via `/proc/kcore`<br>- Reading arbitrary kernel memory via BPF (kprobes)<br>- Reading processor MSR registers<br>- Reading raw ACPI memory regions | Pure userland operations and authorized syscall paths |

---

## 3. Configuration & Boot Parameters

### 1. Kconfig Fragment

```ini
# configs/features/lockdown.config
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 2. Runtime Control Interface & Boot Parameters

| Interface / Parameter | Default | Description |
| :--- | :--- | :--- |
| `/sys/kernel/security/lockdown` | `[none]` | SecurityFS interface to inspect current level and transition to higher levels |
| `lockdown=integrity` | Kernel cmdline | Forces kernel into Integrity lockdown from boot time |
| `lockdown=confidentiality` | Kernel cmdline | Forces kernel into Confidentiality lockdown from boot time |

> [!IMPORTANT]
> The `/sys/kernel/security/lockdown` interface acts as a **one-way ratchet**. Root can elevate the lockdown level (e.g. from `none` to `integrity` or `confidentiality`), but can never downgrade the level without a full system reboot.

---

## 4. Hands-on Verification & Exploit PoC

### 1. Test Scenario Overview

- Execute tests under both unprivileged (`lab`) and root accounts:
  - **Phase 1: Mode 0 (None)**:
    - Standard operations, raw memory write (integrity tampering), and kernel memory dumps (confidentiality leaks) are all permitted.
  - **Phase 2: Mode 1 (Integrity)**:
    - Standard userland operations remain granted.
    - Raw memory write attempts are intercepted and terminated with `-EPERM`.
    - Reading kernel memory remains permitted.
  - **Phase 3: Mode 2 (Confidentiality)**:
    - Standard userland operations remain granted.
    - Raw memory write attempts remain terminated with `-EPERM`.
    - Secret reads via `/proc/kcore` or raw memory are intercepted and terminated with `-EPERM`.

### 2. Dual-Architecture Execution Logs

=== "ARM64: Lockdown LSM Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-lockdown/arch/arm64/boot/Image --test test_lockdown
    ```
    ```
    ================================================================
       Lab 33: Kernel Lockdown LSM Verification Suite               
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel Lockdown SecurityFS interface...
        Lockdown SecurityFS node found at /sys/kernel/security/lockdown
        Current Lockdown state: [none] integrity confidentiality
    [*] Step 3: Checking target driver at /proc/vuln_lockdown...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Lockdown PoC as user 'lab'...
    ================================================================
      Kernel Lockdown LSM Unprivileged/Privileged PoC Exploit       
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
            Kernel Lockdown LSM Status Report               
    ========================================================
    Current Lockdown Level  : [2] Confidentiality
    SecurityFS String       : none integrity [confidentiality]
    Total Evaluated Requests: 0
    Requests Granted        : 0
    Requests Denied         : 0
      - Integrity Denials   : 0
      - Confidentiality Den : 0
    ========================================================

    [*] PHASE 1: Evaluating Mode 0 (None - Permissive)
        -> Requesting standard userland access... (GRANTED)
        -> Requesting raw memory write (integrity tamper)... (GRANTED)
        -> Requesting kernel secret read (/proc/kcore leak)... (GRANTED)

    [*] PHASE 2: Evaluating Mode 1 (Integrity)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting GRANTED in integrity mode)... (GRANTED)

    [*] PHASE 3: Evaluating Mode 2 (Confidentiality)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [+] Lockdown LSM Verification Complete: Integrity & Confidentiality Enforcement Proven!

    [*] Step 6: Inspecting kernel dmesg for Lockdown events:
    [    6.112045] Lockdown: exploit_lockdow: raw memory/kernel text write is restricted; see man kernel_lockdown.7
    [    6.112098] lockdown: [INTEGRITY_VIOLATION] Blocked raw memory tamper (-EPERM)!
    [    6.114120] Lockdown: exploit_lockdow: reading kernel core dump /proc/kcore is restricted; see man kernel_lockdown.7
    [    6.114185] lockdown: [CONFIDENTIALITY_VIOLATION] Blocked kernel memory read (-EPERM)!
    ================================================================
       Lab 33 Test Complete: Verified Kernel Lockdown LSM           
    ================================================================
    ```

=== "x86_64: Lockdown LSM Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-lockdown/arch/x86/boot/bzImage --test test_lockdown
    ```
    ```
    ================================================================
       Lab 33: Kernel Lockdown LSM Verification Suite               
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel Lockdown SecurityFS interface...
        Lockdown SecurityFS node found at /sys/kernel/security/lockdown
        Current Lockdown state: [none] integrity confidentiality
    [*] Step 3: Checking target driver at /proc/vuln_lockdown...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Lockdown PoC as user 'lab'...
    ================================================================
      Kernel Lockdown LSM Unprivileged/Privileged PoC Exploit       
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Mode 0 (None - Permissive)
        -> Requesting standard userland access... (GRANTED)
        -> Requesting raw memory write (integrity tamper)... (GRANTED)
        -> Requesting kernel secret read (/proc/kcore leak)... (GRANTED)

    [*] PHASE 2: Evaluating Mode 1 (Integrity)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting GRANTED in integrity mode)... (GRANTED)

    [*] PHASE 3: Evaluating Mode 2 (Confidentiality)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [+] Lockdown LSM Verification Complete: Integrity & Confidentiality Enforcement Proven!

    [*] Step 6: Inspecting kernel dmesg for Lockdown events:
    [   10.220194] Lockdown: exploit_lockdow: raw memory/kernel text write is restricted; see man kernel_lockdown.7
    [   10.220250] lockdown: [INTEGRITY_VIOLATION] Blocked raw memory tamper (-EPERM)!
    [   10.222301] Lockdown: exploit_lockdow: reading kernel core dump /proc/kcore is restricted; see man kernel_lockdown.7
    [   10.222380] lockdown: [CONFIDENTIALITY_VIOLATION] Blocked kernel memory read (-EPERM)!
    ================================================================
       Lab 33 Test Complete: Verified Kernel Lockdown LSM           
    ================================================================
    ```

---

## 5. Performance & Compatibility

1. **Zero Runtime Overhead**:
   - Lockdown LSM imposes virtually zero overhead on standard syscall paths. It only performs checks when sensitive privileged operations (such as opening `/dev/mem` or loading kernel modules) are invoked.
2. **Essential Link in Secure Boot**:
   - Secure Boot only validates the initial boot chain up to the kernel. Lockdown LSM extends this protection into userspace runtime, preventing root from disabling security features or loading malicious rootkits.
3. **Debugging Considerations**:
   - Enabling `confidentiality` mode will restrict deep diagnostic tools like `perf`, BPF tracing utilities (`bpftrace`), and `crash`. Organizations should tailor lockdown levels between development and production systems.

---

## 6. Lecture & Presentation Script

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In classical Unix and Linux administration, the root user or UID 0 has always been regarded as omnipotent. If an adversary compromises root, they could traditionally open `/dev/mem`, overwrite running kernel code, or load unsigned rootkit modules. Even if UEFI Secure Boot verified the initial kernel binary, the chain of trust was broken immediately once root was subverted in userspace. Today, we explore how the **Kernel Lockdown LSM** redefines the security boundary by restricting even the superuser."

#### 2. Diagram & Architecture Walkthrough
> "Let's examine the interactive architecture simulator displayed here. Notice the three-tier progression: `none`, `integrity`, and `confidentiality`. When any process—even with EUID 0—attempts an operation that could mutate kernel state, the `security_locked_down()` LSM hook inspects the operation's severity. Under `integrity` mode, raw memory writes, unsigned module loading, and untrusted kexec reboots are immediately blocked with an `-EPERM` error. Under `confidentiality` mode, this perimeter extends further to block root from reading kernel secrets via `/proc/kcore` or raw memory inspection."

#### 3. Live Demo Commentary
> "In our hands-on verification on ARM64 and x86_64, observe the step-by-step transition in our target driver. In Mode 0, both tamper and leak tests succeed without resistance. However, when we engage Mode 1 (Integrity), the raw memory write is instantly denied, producing the canonical kernel warning: `'Lockdown: raw memory write is restricted; see man kernel_lockdown.7'`. When stepped up to Mode 2 (Confidentiality), secret dumps via `/proc/kcore` are similarly terminated with `-EPERM`. Furthermore, SecurityFS enforces a one-way ratchet, meaning an attacker cannot downgrade the lockdown level at runtime."

#### 4. Key Takeaways & Production Advice
> "To conclude: Kernel Lockdown LSM is the missing bridge between firmware-level Secure Boot and runtime Linux userspace. By enforcing `lockdown=integrity` or `lockdown=confidentiality` in production kernels, organizations can guarantee that even in the worst-case scenario of full root compromise, the adversary cannot escape to Ring 0 or tamper with the underlying kernel."
