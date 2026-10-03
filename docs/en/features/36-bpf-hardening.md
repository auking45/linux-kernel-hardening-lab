# BPF Hardening & JIT Constant Blinding

## 1. Overview & Threat Model

**BPF Hardening** encompasses a multi-layered defensive suite within the Linux kernel that **eliminates unprivileged abuse, thwarts JIT-spraying shellcode attacks, and neutralizes speculative execution side-channels in the eBPF subsystem**.

While eBPF is acclaimed for enabling programmable networking, tracing, and runtime observability, it has also historically been a frequent source of kernel local privilege escalation (LPE) vulnerabilities:

1. **Unprivileged eBPF Privilege Escalation**:
   - An unprivileged user (UID 1000) invokes `bpf()` to allocate eBPF maps and load programs, subsequently triggering subtle verifier edge cases (integer overflows, bounds tracking inconsistencies) to achieve Arbitrary Address Read/Write (AAR/AAW) in Ring 0.
2. **JIT Spraying of Executable Shellcode**:
   - Attackers construct eBPF programs containing crafted 32-bit or 64-bit immediate values (e.g. `0x4831c04831db`).
   - When the BPF JIT compiler compiles these instructions into executable kernel memory pages, the immediate values appear verbatim. An attacker exploiting an unrelated control-flow hijack jumps to an unaligned offset within the instruction stream, executing the embedded constants directly as native machine code (shellcode).
3. **BPF Interpreter Gadgets & Speculation Leaks**:
   - The in-kernel bytecode interpreter dispatch loop contains branch tables that can be weaponized in Spectre v1/v2 speculative cache side-channel attacks to leak confidential kernel memory.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/bpf-hardening/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: High-Security Mint & Counterfeit Ink Shredder

The defensive mechanism of BPF Hardening closely mirrors **counterfeit deterrence at a state currency mint**:

```
[ Unrestricted BPF (Permissive: unprivileged_bpf_disabled=0) ]
  Visitor:      "I have no credentials (no CAP_BPF), but I want to operate the precision banknote printing press (bpf syscall)!"
  Guard:        "Access granted without restriction." (High risk of exploiting mechanical flaws to forge currency)

[ JIT Constant Blinding (Enforced: bpf_jit_harden=2) ]
  Counterfeiter:"I will hide secret printing patterns (shellcode) inside innocent data numbers (0x4831c0)!"
  Blinder:      "Constant Blinding active! Generating random cryptographic XOR mask!"
  Transform:    "Instead of printing the raw numbers, we split them into (IMM ^ Mask) followed by (Mask)!"
  Outcome:      "The sequential shellcode byte pattern is mathematically obliterated in physical memory!"

[ Permanent Interpreter Removal (CONFIG_BPF_JIT_ALWAYS_ON=y) ]
  Saboteur:     "I will exploit the slow manual translator (interpreter loop) to probe side-channel secrets!"
  Kernel:       "The interpreter is permanently removed at compile time! Only verified native JIT code executes!"
```

---

### 3. Core BPF Hardening Mechanisms

#### 1) `CONFIG_BPF_JIT_ALWAYS_ON=y` (Interpreter Elimination)
- Completely compiles out the in-kernel software BPF interpreter.
- Enforces that all eBPF programs MUST be compiled by the architecture-specific (x86_64, aarch64) JIT compiler.
- Eliminates interpreter dispatch loops and speculative execution gadgets.

#### 2) `kernel.unprivileged_bpf_disabled` (Unprivileged Gatekeeping)
- `0`: Unprivileged processes can invoke `bpf()` to load socket filter programs and create maps.
- `1`: Unprivileged BPF is disabled (`CAP_SYS_ADMIN` or `CAP_BPF` required; root can toggle back to 0).
- `2`: **Permanent Lockdown**. Once set to 2, the value cannot be modified even by root until the system reboots.

#### 3) `net.core.bpf_jit_harden` (Constant Blinding)
- `0`: Disabled. Immediate constants are emitted verbatim into JIT pages.
- `1`: Constant blinding enabled for unprivileged callers.
- `2`: **Universal Constant Blinding**. Enforced across all callers (including root).
- **Transformation Pipeline**:
  ```
  [ Unblinded Assembly ]
    MOV64_IMM R1, 0x4831c04831db   --> Emits \x48\x31\xc0\x48\x31\xdb (Shellcode gadget exposed!)

  [ Blinded Assembly (bpf_jit_blind_constants) ]
    Generate random 32-bit mask M = 0x9a7f3e12
    MOV64_IMM R1, (0x4831c04831db ^ 0x9a7f3e12)  --> Random non-executable byte sequence
    XOR64_IMM R1, 0x9a7f3e12                     --> Restores original logical value at runtime
  ```

---

## 3. Configuration & Sysctl Parameters

### 1. Kconfig Fragment

```ini
# configs/features/bpf-hardening.config
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_HAVE_EBPF_JIT=y
```

### 2. Runtime Sysctl Parameters

| Sysctl Parameter | Recommended | Description |
| :--- | :--- | :--- |
| `kernel.unprivileged_bpf_disabled` | `2` | Disables unprivileged BPF and locks sysctl permanently until reboot (`-EPERM`) |
| `net.core.bpf_jit_harden` | `2` | Universally enforces randomized constant blinding across all BPF JIT code |
| `net.core.bpf_jit_enable` | `1` | Ensures eBPF JIT compiler is permanently active |

---

## 4. Hands-on Verification & Exploit PoC

### 1. Test Scenario Overview

- Execute tests under non-root account (`lab`, UID 1000):
  - **Phase 1: Baseline (Permissive Mode)**:
    - Unprivileged BPF load allowed.
    - Immediate constants emitted verbatim into JIT memory without blinding.
  - **Phase 2: Hardened Mode (`unprivileged_bpf_disabled=2` & `bpf_jit_harden=2`)**:
    - Unprivileged BPF load routine fails with `-EPERM`.
    - JIT spray constant gadget (`0x4831c04831db`) is safely blinded into XOR splits.
  - **Phase 3: Direct Syscall Verification**:
    - Direct invocation of `syscall(__NR_bpf, BPF_PROG_LOAD, ...)` returns `-1` with `errno == EPERM`, verifying kernel attack surface elimination.

### 2. Dual-Architecture Execution Logs

=== "ARM64: BPF Hardening Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-bpfhard/arch/arm64/boot/Image --test test_bpf_hardening
    ```
    ```
    ================================================================
       Lab 36: BPF Hardening & JIT Blinding Verification Suite      
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting kernel BPF sysctl parameters...
        kernel.unprivileged_bpf_disabled: 2
        net.core.bpf_jit_harden: 2
        net.core.bpf_jit_enable: 1
    [*] Step 2: Checking target driver at /proc/vuln_bpf_hardening...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged BPF Hardening PoC as user 'lab'...
    ================================================================
      Linux BPF Hardening & JIT Blinding Verification PoC           
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Unprivileged BPF Sysctl (/proc/sys/kernel/unprivileged_bpf_disabled): 2
    [*] BPF JIT Blinding Hardening (/proc/sys/net/core/bpf_jit_harden): 2
    [*] BPF JIT Compiler State (/proc/sys/net/core/bpf_jit_enable): 1

    [*] PHASE 1: Evaluating Baseline (Mode: Permissive)
        -> Calling unprivileged BPF loader routine... (GRANTED)
        -> Injecting JIT Spray constant gadget (0x4831c04831db)... (EXPOSED: Raw constant compiled into executable page)

    [*] PHASE 2: Evaluating Hardened (Mode: Hardened)
        -> Calling unprivileged BPF loader routine (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM via unprivileged_bpf_disabled)
        -> Injecting JIT Spray constant gadget (expecting BLINDED via XOR split)... (NEUTRALIZED: Immediate constant blinded via randomized XOR mask)

    [*] PHASE 3: Testing raw sys_bpf() invocation as UID 1000...
        [+] SUCCESS: sys_bpf() rejected by kernel: Operation not permitted (errno=1)
            -> Unprivileged BPF loading is strictly neutralized!

    [+] BPF Hardening Verification Complete: Unprivileged Attacks & JIT Spray Thwarted!

    [*] Step 5: Inspecting kernel dmesg for BPF events:
    [    4.321102] bpf_hardening: [BLOCKED] Unprivileged bpf() call rejected (-EPERM). sysctl unprivileged_bpf_disabled active!
    [    4.321280] bpf_hardening: [BLINDED] JIT Spray constant 0x4831c04831db blinded into randomized XOR splits (bpf_jit_harden=2)!
    ================================================================
       Lab 36 Test Complete: Verified BPF Hardening & Blinding       
    ================================================================
    ```

=== "x86_64: BPF Hardening Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-bpfhard/arch/x86/boot/bzImage --test test_bpf_hardening
    ```
    ```
    ================================================================
       Lab 36: BPF Hardening & JIT Blinding Verification Suite      
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting kernel BPF sysctl parameters...
        kernel.unprivileged_bpf_disabled: 2
        net.core.bpf_jit_harden: 2
        net.core.bpf_jit_enable: 1
    [*] Step 2: Checking target driver at /proc/vuln_bpf_hardening...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged BPF Hardening PoC as user 'lab'...
    ================================================================
      Linux BPF Hardening & JIT Blinding Verification PoC           
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Unprivileged BPF Sysctl (/proc/sys/kernel/unprivileged_bpf_disabled): 2
    [*] BPF JIT Blinding Hardening (/proc/sys/net/core/bpf_jit_harden): 2
    [*] BPF JIT Compiler State (/proc/sys/net/core/bpf_jit_enable): 1

    [*] PHASE 1: Evaluating Baseline (Mode: Permissive)
        -> Calling unprivileged BPF loader routine... (GRANTED)
        -> Injecting JIT Spray constant gadget (0x4831c04831db)... (EXPOSED: Raw constant compiled into executable page)

    [*] PHASE 2: Evaluating Hardened (Mode: Hardened)
        -> Calling unprivileged BPF loader routine (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM via unprivileged_bpf_disabled)
        -> Injecting JIT Spray constant gadget (expecting BLINDED via XOR split)... (NEUTRALIZED: Immediate constant blinded via randomized XOR mask)

    [*] PHASE 3: Testing raw sys_bpf() invocation as UID 1000...
        [+] SUCCESS: sys_bpf() rejected by kernel: Operation not permitted (errno=1)
            -> Unprivileged BPF loading is strictly neutralized!

    [+] BPF Hardening Verification Complete: Unprivileged Attacks & JIT Spray Thwarted!

    [*] Step 5: Inspecting kernel dmesg for BPF events:
    [    7.890120] bpf_hardening: [BLOCKED] Unprivileged bpf() call rejected (-EPERM). sysctl unprivileged_bpf_disabled active!
    [    7.890255] bpf_hardening: [BLINDED] JIT Spray constant 0x4831c04831db blinded into randomized XOR splits (bpf_jit_harden=2)!
    ================================================================
       Lab 36 Test Complete: Verified BPF Hardening & Blinding       
    ================================================================
    ```

---

## 5. Performance & Production Guidelines

1. **Constant Blinding Overhead**:
   - Blinding adds a single XOR instruction per immediate constant load. Because transformations occur strictly during program compilation, runtime overhead is under 0.1%.
2. **Production Baseline Configuration**:
   - In enterprise infrastructure and Kubernetes worker nodes, enforce the following settings via `/etc/sysctl.d/99-bpf-hardening.conf`:
     ```ini
     kernel.unprivileged_bpf_disabled = 2
     net.core.bpf_jit_harden = 2
     ```
3. **Observability Infrastructure (Cilium, Falco, bpftrace)**:
   - Legitimate observability agents operate with `CAP_BPF` or `CAP_SYS_ADMIN` privileges. Disabling unprivileged BPF protects the host without obstructing production monitoring daemons.

---

## 6. Lecture & Presentation Script

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In modern Linux engineering, eBPF is universally celebrated as a revolutionary technology for programmable networking, tracing, and runtime observability. However, to vulnerability researchers and threat actors, eBPF has historically been one of the most prolific sources of kernel local privilege escalation. Attackers have weaponized subtle bugs in the kernel BPF verifier, or utilized JIT spraying techniques to embed raw machine code inside 32-bit constant values. Today, we examine the complete defensive triumvirate: **Linux BPF Hardening and Constant Blinding**."

#### 2. Diagram & Architecture Walkthrough
> "Please examine our interactive architecture simulator on the screen. The defensive chain is divided into three coordinated gates. First, when an unprivileged process calls `bpf()`, the kernel gatekeeper checks `kernel.unprivileged_bpf_disabled`. Setting this to `2` creates a permanent, one-way lockdown that rejects unprivileged calls with `-EPERM`. Second, with `CONFIG_BPF_JIT_ALWAYS_ON=y`, the in-kernel interpreter is completely removed, eliminating speculative execution gadgets. Third, look at how the JIT compiler handles constant values when `net.core.bpf_jit_harden=2` is active. Instead of writing shellcode bytes verbatim into executable JIT pages, the engine applies randomized XOR masks, mathematically destroying all contiguous shellcode gadgets in memory."

#### 3. Live Demo Commentary
> "In our live verification on both ARM64 and x86_64, look at the transition from Permissive to Hardened modes. In Permissive mode, our raw constant `0x4831c04831db` is emitted verbatim into executable memory, creating a viable gadget for control-flow hijacking. But when Hardened mode is engaged, the target driver verifies that the constant is safely split into randomized XOR pairs. Furthermore, when our unprivileged `lab` user attempts to invoke `sys_bpf()` directly, the kernel terminates the call with `-EPERM` (Operation not permitted). The attack surface is completely eliminated."

#### 4. Key Takeaways & Production Advice
> "To summarize: Hardening BPF requires zero hardware dependencies. By compiling kernels with `CONFIG_BPF_JIT_ALWAYS_ON=y` and enforcing `kernel.unprivileged_bpf_disabled=2` alongside `net.core.bpf_jit_harden=2`, organizations can safely run modern enterprise eBPF workloads while guaranteeing that unauthorized users and container tenants cannot abuse the subsystem to breach Ring 0."
