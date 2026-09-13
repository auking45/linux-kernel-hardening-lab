# CONFIG_SHADOW_CALL_STACK: ARM64 Shadow Call Stack & ROP Mitigation

## 1. Overview & Threat Model

### 1.1 Addressed Threat: Stack Return Address Overwriting & ROP Attacks
- **Return Address Hijacking on Call Stacks**:
  - Traditional C calling conventions mix local stack buffers, spilled registers, frame pointers, and return addresses onto a single call stack (`SP`).
  - When an attacker triggers a stack buffer overflow, they can overwrite the saved return address (`LR` / Link Register on ARM64, `RIP` on x86) with an arbitrary code address or Return-Oriented Programming (ROP) gadgets.
- **Dangers of Return-Oriented Programming (ROP)**:
  - While `W^X` (`CONFIG_STRICT_KERNEL_RWX`) prevents executing shellcode directly on the stack, ROP bypasses this by chaining together existing instruction sequences (`gadgets`) ending with a `ret` instruction to achieve arbitrary kernel privilege escalation (such as invoking `commit_creds()`).
- **Shortcomings of Stack Canaries**:
  - `CONFIG_STACKPROTECTOR` inserts a randomized guard value before the return address. However, if the canary is leaked via an infoleak vulnerability, or if an attacker utilizes non-linear indexed writes (`buffer[offset] = value`), the canary can be bypassed without detection.

### 1.2 Defense Philosophy: Shadow Call Stack (SCS)
- **Backward-Edge Control Flow Integrity (CFI)**:
  - Guarantees that function returns (`ret`) can only branch to legitimate, unaltered caller addresses.
  - **Dual-Stack Architecture**:
    1. **Regular Stack (`SP`)**: Houses mutable local variables, spill registers, and frame pointers.
    2. **Shadow Call Stack (`x18`)**: Strictly reserves an isolated memory region storing only pristine return addresses (`x30`/`LR`).
  - Even if an attacker obliterates the normal stack memory, function epilogues completely ignore the saved `LR` on `SP`, restoring `x30` exclusively from the pristine shadow stack pointed to by `x18`.

---

## 2. Kernel Internal Architecture

### 2.1 AArch64 `x18` Platform Register Dedication
- The ARM64 ABI designates register `x18` as a **Platform Register**.
- The Linux kernel is compiled with `-ffixed-x18`, preventing GCC/Clang from ever allocating `x18` for regular variables or register spills.
- When creating each kernel thread, an isolated shadow stack allocation (`SCS_SIZE`, typically 4KB–16KB) is mapped. When that task runs on a CPU, `x18` holds the current top of its shadow stack.

### 2.2 Prologue and Epilogue Assembly Transformations

=== "SCS Enabled (Hardened: Dual-Stack Isolation)"

    ```armasm
    ; [Function Prologue]
    str   x30, [x18], #8          ; 1. Push pristine LR (x30) onto shadow stack at x18; post-increment x18
    stp   x29, x30, [sp, #-32]!   ; 2. Save FP and LR to regular stack (kept for unwinders/debuggers)
    mov   x29, sp                 ; 3. Establish frame pointer

    ; [Execution: Buffer overflow overwrites [sp, #8] with malicious target address]

    ; [Function Epilogue]
    ldr   x30, [x18, #-8]!        ; 1. [KEY DEFENSE] Restore pristine LR exclusively from shadow stack (x18)!
    ldp   x29, xzr, [sp], #32     ; 2. Pop regular stack; discard corrupted LR into zero register (xzr)
    ret                           ; 3. Safely return using pristine LR (x30) -> ROP chain thwarted!
    ```

=== "SCS Disabled (Base: Single Vulnerable Stack)"

    ```armasm
    ; [Function Prologue]
    stp   x29, x30, [sp, #-32]!   ; Store FP and LR only on regular stack (SP)
    mov   x29, sp

    ; [Execution: Buffer overflow overwrites [sp, #8] with malicious target address]

    ; [Function Epilogue]
    ldp   x29, x30, [sp], #32     ; [VULNERABILITY] Corrupted LR is loaded directly into x30!
    ret                           ; Branches into attacker's hijacked target address -> Control seized!
    ```

### 2.3 Interactive Architecture Diagram

Experience the AArch64 dual-stack interaction and ROP mitigation sequence using the interactive map below:

<iframe src="../../../assets/diagrams/shadow-call-stack/architecture.html" width="100%" height="700px" style="border:none; border-radius:12px; margin: 16px 0; background: #0f172a;" title="Shadow Call Stack Architecture Map"></iframe>

---

## 3. Configuration & Kconfig Setup

### 3.1 Toolchain and Kernel Requirements
- **Compiler**: Clang >= 7.0 or GCC >= 12.0.0 (must support `-fsanitize=shadow-call-stack -ffixed-x18`).
- **Architecture**: ARM64 (`ARCH_SUPPORTS_SHADOW_CALL_STACK=y`).
- **Tracer compatibility**: Must satisfy `DYNAMIC_FTRACE_WITH_ARGS` or `!FUNCTION_GRAPH_TRACER`.

### 3.2 Kconfig Fragment

```kconfig
# /configs/features/shadow-call-stack.config
CONFIG_SHADOW_CALL_STACK=y
```

Base / Vulnerable comparison fragment:
```kconfig
# /configs/features/shadow-call-stack-disabled.config
# CONFIG_SHADOW_CALL_STACK is not set
```

---

## 4. Hands-on Verification & Exploit PoC

This lab verifies defenses using both a **real-world C exploit PoC executed by an unprivileged user (`lab`, UID 1000) against `/proc/vuln_scs`** and LKDTM standard backward-edge CFI tests:

1. **[Test 1/2] Real-World Kernel SCS Exploit PoC (`/bin/exploit_shadow_call_stack`)**:
   - The test function in `vuln_scs.c` (`vulnerable_scs_worker()`) uses `__no_stack_protector` to isolate SCS evaluation from Stack Protector canary interference.
   - **Base Kernel**: Saved `LR` is overwritten with `scs_hijacked_target`, causing execution to branch into the hijack function and panic upon return.
   - **Hardened Kernel**: Even though the regular stack is smashed, `x18` restores the genuine `LR`, allowing safe return to `vuln_scs_write` (`[+] DEFENSE ACTIVE: Returned safely to vuln_scs_write!`).
2. **[Test 2/2] Upstream LKDTM Standard Test (`CFI_BACKWARD`)**:
   - Triggers backward-edge return address manipulation inside debugfs.

---

### 4.1 One-Click Verification Commands & Runtime Logs

=== "ARM64: Hardened (Enabled: x18 Return Integrity - Recommended)"

    ```bash
    # Run Hardened ARM64 kernel with SCS verification
    ./scripts/run_lab.sh --arch arm64 --feature shadow-call-stack --test test_shadow_call_stack
    ```

    **Runtime Verification Log (SCS Defense Active)**:
    ```text
    =========================================================
      [Test 1/2] Real-World Kernel Shadow Call Stack Exploit PoC
      Target:       /proc/vuln_scs (Return Address / LR Hijack)
      Exploit:      /bin/exploit_shadow_call_stack
      Runner:       lab (UID 1000, non-privileged)
    =========================================================
    [*] Launching stack overwrite payload against 32-byte worker target...
    [*] If CONFIG_SHADOW_CALL_STACK is active, pristine LR restored from x18!

    =========================================================
      Linux Kernel Hardening Lab - Shadow Call Stack PoC
      Target Architecture: aarch64 (ARM64)
      Current User: UID = 1000 (non-root)
    =========================================================
    [*] Target hijack function address: 0xffff80008032ac34
    [*] Kernel SCS status reported:     ENABLED
    [*] Buffer size: 32 bytes
    [*] Prepared overflow payload: 64 bytes
    [*] Injecting payload into /proc/vuln_scs...
    [*] [Hardened Kernel Expected]: Epilogue restores pristine LR from x18 -> Safe return.
    [*] [Vulnerable Kernel Expected]: Epilogue restores corrupted LR from stack -> Hijacked control flow!

    [+] write() returned successfully (64 bytes written).

    [*] Write completed without process crash!
    [+] DEFENSE ACTIVE: Function returned safely to caller.
    [+] Shadow Call Stack protected the Link Register from being overwritten.

    [    1.387005] [vuln_scs] Interface /proc/vuln_scs created (target: 0xffff80008032ac34, SCS=1)
    [    2.510878] [vuln_scs] Write received: 64 bytes from PID 47 (exploit_shadow_)
    [    2.511152] [vuln_scs] Calling vulnerable_scs_worker(target=0xffff80008032ac34)...
    [    2.511226] [vuln_scs] vulnerable_scs_worker: saved stack LR = ffff80008032ae4c, target = ffff80008032ac34
    [    2.511259] [vuln_scs] Overwriting saved stack LR with target address...
    [    2.511289] [vuln_scs] Epilogue executing: if SCS is active, x18 restores true LR...
    [    2.511332] [vuln_scs] [+] DEFENSE ACTIVE: Returned safely to vuln_scs_write!
    [    2.511354] [vuln_scs] [+] Shadow Call Stack (x18) thwarted return address hijacking!

    =========================================================
      [Test 2/2] Triggering LKDTM CFI_BACKWARD Test
      Kernel Architecture: aarch64
      Kernel Release:      6.12.109
    =========================================================
    [*] Triggering checked stack return address redirection via LKDTM...

    [    1.386523] lkdtm: No crash points registered, enable through debugfs
    [    2.648968] lkdtm: Performing direct entry CFI_BACKWARD
    [    2.650366] lkdtm: Attempting unchecked stack return address redirection ...
    [    2.650561] lkdtm: ok: redirected stack return address.
    [    2.650599] lkdtm: Attempting checked stack return address redirection ...
    [    2.650701] lkdtm: Eek: return address mismatch! ffff80008032a338 != ffff80008032a278
    [    2.650852] lkdtm: ok: control flow unchanged.
    ```
    > **Analysis:** Despite 64 bytes overwriting the regular stack frame, `ldr x30, [x18, #-8]!` fetched the genuine return address (`ffff80008032ae4c`) from `x18`. The exploit was neutralized, and LKDTM confirmed `Eek: return address mismatch!` with `ok: control flow unchanged.`

=== "ARM64: Base (Disabled: Control Flow Hijacked)"

    ```bash
    # Run unprotected base ARM64 kernel
    ./scripts/run_lab.sh --arch arm64 --feature shadow-call-stack-disabled --test test_shadow_call_stack
    ```

    **Runtime Verification Log (Hijack Confirmed)**:
    ```text
    =========================================================
      [Test 1/2] Real-World Kernel Shadow Call Stack Exploit PoC
      Target:       /proc/vuln_scs (Return Address / LR Hijack)
      Exploit:      /bin/exploit_shadow_call_stack
      Runner:       lab (UID 1000, non-privileged)
    =========================================================
    [*] Target hijack function address: 0xffff800080312304
    [*] Kernel SCS status reported:     DISABLED
    [*] Buffer size: 32 bytes
    [*] Prepared overflow payload: 64 bytes
    [*] Injecting payload into /proc/vuln_scs...
    [*] [Hardened Kernel Expected]: Epilogue restores pristine LR from x18 -> Safe return.
    [*] [Vulnerable Kernel Expected]: Epilogue restores corrupted LR from stack -> Hijacked control flow!

    [    1.250084] [vuln_scs] [!] =========================================================
    [    1.252367] [vuln_scs] [!] CONTROL FLOW HIJACKED: Successfully executed scs_hijacked_target()!
    [    1.253111] [vuln_scs] [!] Overwritten stack return address (LR) was branched to by 'ret'.
    [    1.255882] [vuln_scs] [!] Shadow Call Stack is NOT active on this kernel (Vulnerable Baseline).
    [    1.256355] [vuln_scs] [!] =========================================================
    [    1.257173] Kernel panic - not syncing: vuln_scs: Control flow hijacking confirmed via smashed stack return address
    [    1.258823] CPU: 0 UID: 1000 PID: 47 Comm: exploit_shadow_ Not tainted 6.12.109 #2
    [    1.260114] Call trace:
    [    1.260607]  dump_backtrace+0x90/0xe8
    [    1.261638]  show_stack+0x18/0x24
    [    1.261950]  dump_stack_lvl+0x34/0x8c
    [    1.262484]  dump_stack+0x18/0x24
    [    1.263725]  panic+0x388/0x39c
    [    1.264051]  vulnerable_scs_worker+0x0/0x54
    [    1.264289]  scs_hijacked_target+0x0/0x58
    ```
    > **Analysis:** On the base kernel, `ret` executed with the corrupted `x30` loaded directly from the regular stack, transferring execution into `scs_hijacked_target()`. This proves that without SCS, stack buffer overflows result in full ROP hijacking.

---

### 4.2 Architecture Comparison: ARM64 vs x86_64 ROP Defenses

| Feature | ARM64 (AArch64) | x86_64 (AMD64) |
| :--- | :--- | :--- |
| **Return Address Register** | Dedicated Link Register `x30` (`LR`) | Pushed directly to stack (`RSP`) by `call` |
| **Return Instruction** | `ret` (semantic equivalent to `br x30`) | `ret` (pops from stack into `RIP`) |
| **Software Shadow Stack** | **Supported** (Dedicated `x18` platform register) | **Unsupported** (Register starvation / pressure) |
| **Hardware Shadow Stack** | ARMv8.3-A PAC (Pointer Auth) & BTI (Task 6-3) | **Intel CET Shadow Stack** (`ssp` register, Task 6-2) |
| **Design Philosophy** | Fast compiler-inserted register-relative loads | Hardware MMU page tokens and CPU MSRs |

---

## 5. Performance & Overhead Analysis

- **CPU Overhead**:
  - Adds two fast memory instructions per non-leaf function: `str x30, [x18], #8` (1 cycle) and `ldr x30, [x18, #-8]!` (1 cycle).
  - Overall kernel execution benchmark shows **less than 0.5% runtime overhead**, making it standard in Android production kernels.
- **Memory Overhead**:
  - Each kernel thread allocates one dedicated vmalloc page (4KB–16KB) bounded by guard pages to prevent shadow stack overflows.

---

## 6. Presentation Script & Speaking Guide

### 6.1 Presentation Script (Korean & English)

```text
[Hook - The limits of Stack Canaries]
"When defending against stack overflows, developers often rely solely on Stack Canaries.
 But canaries can be bypassed if an attacker finds an infoleak or uses non-linear memory writes.
 If return addresses share the same stack as mutable buffers, ROP remains an ever-present danger."

[Diagram - The Vault Analogy]
"ARM64 resolves this with the Shadow Call Stack.
 Storing your home keys inside the living room means an intruder who breaks in gets the keys too.
 SCS takes return address keys and locks them inside an isolated vault pointed to exclusively by register x18.
 Even if an attacker smashes the regular stack to pieces, the CPU only uses the pristine key inside x18 to return."

[Live Demo - Real-World Exploit Comparison]
"We demonstrated this live in QEMU.
 On the base kernel, our 128-byte payload hijacked the Link Register into scs_hijacked_target.
 But with CONFIG_SHADOW_CALL_STACK enabled, the exact same attack was neutralized:
 the epilogue retrieved the pristine LR from x18, allowing safe and uninterrupted execution."
```

### 6.2 Key Presentation Phrases

| English Phrase | Context & Delivery Tip |
| :--- | :--- |
| **"decouple return addresses from mutable stack frames"** | Emphasizes the fundamental architectural value of the dual-stack design |
| **"guarantees airtight backward-edge CFI"** | Uses formal security terminology for academic or technical audiences |
| **"simply discards the corrupted stack value in favor of x18"** | Graphically illustrates how the epilogue neutralizes the attack |
| **"completely closes the door on ROP gadget chaining"** | Concludes the security impact of defeating return address tampering |
| **"dedicates the architectural x18 platform register"** | Explains the hardware/ABI reason why ARM64 natively excels at SCS |
