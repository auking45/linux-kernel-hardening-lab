# x86 IBT & Shadow Stack (Hardware-Enforced Control Flow Integrity via Intel CET)

## 1. Overview and Background

In computer systems security, memory corruption vulnerabilities have evolved from direct shellcode injection into sophisticated code-reuse attacks, primarily ROP (Return-Oriented Programming) and JOP/COP (Jump/Call-Oriented Programming).

1. **Backward-Edge Hijacking (ROP)**:
   - Exploits stack buffer overflows to overwrite the function frame's return address.
   - Executes attacker-controlled gadget chains via function epilogue `ret` instructions.
2. **Forward-Edge Hijacking (JOP/COP)**:
   - Exploits heap overflows or Use-After-Free (UAF) to corrupt function pointers inside kernel structures (e.g., `file_operations`, `proto_ops`).
   - Diverts execution flow during indirect calls (`call *%rax`, `jmp *%rax`) to arbitrary gadget entrypoints.

Software-only CFI solutions introduce significant linking overhead and runtime performance penalties. To solve this at the silicon level, Intel introduced **Intel CET (Control-flow Enforcement Technology)** starting with 11th Gen Core (Tiger Lake) and 3rd Gen Xeon Scalable processors.

The Linux kernel (6.x+) harnesses Intel CET to deploy two primary hardware-assisted defenses:
- **Kernel IBT (`CONFIG_X86_KERNEL_IBT=y`)**: Forward-edge indirect branch tracking enforced via the `endbr64` instruction.
- **User-space Shadow Stack (`CONFIG_X86_USER_SHADOW_STACK=y`)**: Backward-edge hardware-isolated secondary stack protecting return addresses against ROP.

---

## 2. Real-World Analogy: Security Gates & Dual-Ledger Accounting

Intel CET's operational model can be understood as high-security checkpoint screening and dual-entry bookkeeping:

1. **Intel IBT (Security Scanner Gates)**:
   - **Baseline Kernel (Pre-CET)**: A guard opens any door based strictly on a handwritten slip of paper (function pointer). If an attacker substitutes the destination slip with an address leading to a boiler room, the guard blindly complies.
   - **Hardened Kernel (IBT Active)**: Every legitimate door has an 'ENDBR64' electronic scanner installed at the threshold. The moment an indirect jump occurs, the CPU transitions into a heightened alert state (`WAIT_FOR_ENDBRANCH`). If the first instruction at the destination is not an `endbr64` scanner, the CPU instantly sounds the `#CP` alarm (Control Protection Exception) and halts execution.
2. **User Shadow Stack (Dual Vault Ledgers)**:
   - **Baseline Kernel (Single Stack)**: Departure and return records are kept on an open table (Main Data Stack) accessible to anyone. An attacker can overwrite the return log to divert staff to a trapdoor upon return (`ret`).
   - **Hardened Kernel (Shadow Stack Active)**: In addition to the main table, a tamper-proof duplicate ledger is maintained inside a secure hardware vault (`SSP` register). Upon return (`ret`), both entries are compared. If a discrepancy exists, the process is immediately terminated via `SIGSEGV`.

---

## 3. Core Architecture and Operating Principles

### 3.1 Intel IBT (Indirect Branch Tracking)

```text
[ Indirect Call: call *%rax ]
             │
             ▼
   [ CPU State Machine ]
    WAIT_FOR_ENDBRANCH
             │
     ┌───────┴───────┐
     ▼               ▼
[ Next Instruction ]  [ Next Instruction ]
    == endbr64           != endbr64
  (0xf3 0f 1e fa)
     │               │
     ▼               ▼
[ State: IDLE ]     [ #CP Exception ]
Execution continues  Vector 21 (CP_ENDBR)
                    -> do_kernel_cp_fault
                    -> ibt=warn (warn) or BUG()
```

1. **CPU State Transitions**:
   - `IDLE`: Normal instruction execution.
   - `WAIT_FOR_ENDBRANCH`: Triggered immediately upon an indirect call (`call *%reg`, `call *(%mem)`) or indirect jump (`jmp *%reg`).
   - If the instruction at the destination address is `endbr64` (mnemonic bytes: `f3 0f 1e fa`), the CPU returns to `IDLE` state and proceeds normally.
   - If the instruction is NOT `endbr64`, the CPU raises a hardware `#CP` exception (Control Protection, Vector 21, Error Code 3: `CP_ENDBR`).
2. **Kernel & Toolchain Synergy**:
   - Compilers (GCC/Clang) inject `endbr64` at all valid indirect branch targets when built with `-fcf-protection=branch`.
   - Kernel `objtool` analyzes symbol tables and seals unreferenced static functions by replacing redundant `endbr64` instructions with NOPs at boot time.
   - The kernel activates `MSR_IA32_S_CET` (`CET_ENDBR_EN`) and sets `CR4.CET`.
   - The `#CP` handler (`arch/x86/kernel/cet.c`) handles violations. When `ibt=warn` is provided, it dumps a stack trace, clears FRED/IDT WFE flags, and allows execution to continue.

### 3.2 Intel User-Space Shadow Stack (SHSTK)

```text
       Normal User Memory                    Hardware Isolated Space
┌───────────────────────────┐       ┌───────────────────────────┐
│     Main Data Stack       │       │    User Shadow Stack      │
│   (RSP - Variables/Data)  │       │  (SSP - Return Addrs Only)│
├───────────────────────────┤       ├───────────────────────────┤
│ [Local Variables]         │       │                           │
│ [Saved RBP]               │       │                           │
│ [Return Address: 0x401234]│       │ [Return Address: 0x401234]│
└───────────────────────────┘       └───────────────────────────┘
              ▲                                   ▲
              │                                   │
              └───────────────┬───────────────────┘
                              │
                    [ ret Instruction ]
                     Pop RSP & Pop SSP
                     Hardware Comparison
                              │
                      ┌───────┴───────┐
                      ▼               ▼
                 Matched          Mismatched (ROP Detected)
                 Proceed          Hardware #CP (CP_RET)
                                  -> SIGSEGV (SEGV_CPERR)
```

1. **Hardware Shadow Stack Pointer (`SSP`)**:
   - The CPU maintains an independent hardware register `SSP` (`MSR_IA32_PL3_SSP`) dedicated exclusively to return addresses.
   - Shadow stack pages are mapped with special page-table protection attributes (`PTE.SHSTK`), preventing standard user-space write operations (`mov`, `memcpy`).
2. **Synchronous Call / Ret Verification**:
   - `call`: Automatically pushes the return address to both the normal data stack (`RSP`) and the shadow stack (`SSP`).
   - `ret`: Pops return addresses from both stacks and compares them. Any mismatch (e.g., smashed stack return address) immediately triggers `#CP` (`CP_RET` = 1) resulting in `SIGSEGV` with `SEGV_CPERR`.
3. **User Control Interface**:
   - Controlled via `arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK)` (0x5001).
   - Dynamic stack modifications (e.g., setjmp/longjmp) utilize architectural instructions such as `INCSSP` and restricted `WRSS`.

### 3.3 x86 Intel CET vs ARM64 BTI & PAC Comparison

| Feature Category | x86_64 Intel CET | ARM64 Hardware CFI (Lab 15 Preview) |
| :--- | :--- | :--- |
| **Forward-Edge CFI** | **Intel IBT** (`CONFIG_X86_KERNEL_IBT`) | **ARM64 BTI** (`CONFIG_ARM64_BTI_KERNEL`) |
| **Landing Instruction** | `endbr64` (`0xf3 0f 1e fa`) | `bti c` / `bti j` / `bti jc` |
| **Forward Trap Vector** | `#CP` (Control Protection, Vector 21) | Branch Target Exception (`ESR_EL1.EC = 0x34`) |
| **Backward-Edge CFI** | **Intel Shadow Stack** (`SSP`) | **ARM64 PAC** (`pacia`/`autia`) & **Clang SCS** (`x18`) |
| **Protection Principle** | Isolated hardware secondary stack (`SSP`) | Cryptographic pointer authentication code tags |
| **Backward Trap Action** | `#CP` (`CP_RET`) -> `SIGSEGV` | Pointer Authentication Trap (`ESR_EL1.EC = 0x1c`) |

---

## 4. Hands-on Lab and Verification Architecture

The lab environment consists of four integrated components:

1. **Vulnerable Kernel Target Driver (`/proc/vuln_ibt`, mode 0666)**:
   - Built directly into the kernel image via `drivers/misc/vuln_ibt.o`.
   - Reading `/proc/vuln_ibt` provides telemetry on Kernel IBT, Shadow Stack, CPU hardware flags, and disassembles the first 4 bytes of target function entry points.
   - Supports commands: `echo legit > /proc/vuln_ibt` and `echo noendbr > /proc/vuln_ibt`.
2. **User-Space PoC Binary (`/bin/exploit_ibt_shstk`)**:
   - Runs as non-root user `lab` (UID 1000).
   - Validates `arch_prctl(ARCH_SHSTK_ENABLE)` shadow stack syscall support.
   - Tests legitimate vs missing-ENDBR indirect branch targets.
3. **Automated Test Runner (`/bin/test_ibt_shstk`)**:
   - Invoked during QEMU automated boot via `lab_test=test_ibt_shstk`.
   - Evaluates PoC execution and triggers LKDTM `CFI_BACKWARD` return address checks.

---

## 5. Lab Verification and Comparative Telemetry

### 5.1 x86_64 Hardened Environment (`ibt-shstk`)

```text
=========================================================
  [Test 1/2] Real-World Intel CET / IBT & SHSTK Exploit PoC
  Target:       /proc/vuln_ibt
  Exploit:      /bin/exploit_ibt_shstk
  Runner:       lab (UID 1000, non-privileged)
=========================================================
[*] Launching user-space PoC to test Shadow Stack and IBT...

=========================================================
  Linux Kernel Hardening Lab - Intel CET / IBT & SHSTK PoC
  Target Architecture: x86_64
  Current User:        UID = 1000 (non-root)
=========================================================

---------------------------------------------------------
  [Test 1/2] User-space Shadow Stack Activation (arch_prctl)
---------------------------------------------------------
[*] Calling arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK = 0x1)...
[*] arch_prctl returned: -1 (errno=95: Operation not supported)
[+] HARDENED KERNEL CONFIRMED: Syscall ARCH_SHSTK_ENABLE is recognized
    and supported by kernel (CONFIG_X86_USER_SHADOW_STACK=y).
    (Current CPU/hypervisor lacks Intel CET SHSTK MSR hardware feature).

---------------------------------------------------------
  [Test 2/2] Kernel Indirect Branch Tracking (IBT) / ENDBR
---------------------------------------------------------
[*] Kernel IBT Config:       ENABLED
[*] User Shadow Stack Config:ENABLED
[*] HW IBT Supported:        NO
[*] HW SHSTK Supported:      NO
[*] Compiler ENDBR Detected: YES (0xfa1e0ff3)
[*] Legit Target Address:    0xffffffff819580a0
[*] No-ENDBR Target Address: 0xffffffff819580d0

[Step 2A] Triggering legitimate indirect call (with ENDBR64)...
[+] Result: LEGIT_SUCCESS (Total calls: 1)

[Step 2B] Triggering indirect call to target lacking ENDBR64...
[*] Result: NOENDBR_EXECUTED (Total calls: 2)
[+] DEFENSE ACTIVE: Kernel compiled with -fcf-protection=branch (CONFIG_X86_KERNEL_IBT=y).
[+] Valid indirect targets require ENDBR64 instruction (0xfa1e0ff3).
[*] Toolchain/objtool IBT hardening verified (QEMU CPU CET hardware emulation pending).

=========================================================
  Intel CET / IBT & Shadow Stack Verification Complete
=========================================================
```

### 5.2 x86_64 Baseline Environment (`ibt-shstk-disabled`)

```text
=========================================================
  [Test 1/2] Real-World Intel CET / IBT & SHSTK Exploit PoC
  Target:       /proc/vuln_ibt
  Exploit:      /bin/exploit_ibt_shstk
  Runner:       lab (UID 1000, non-privileged)
=========================================================
[*] Launching user-space PoC to test Shadow Stack and IBT...

=========================================================
  Linux Kernel Hardening Lab - Intel CET / IBT & SHSTK PoC
  Target Architecture: x86_64
  Current User:        UID = 1000 (non-root)
=========================================================

---------------------------------------------------------
  [Test 1/2] User-space Shadow Stack Activation (arch_prctl)
---------------------------------------------------------
[*] Calling arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK = 0x1)...
[*] arch_prctl returned: -1 (errno=22: Invalid argument)
[-] BASELINE DETECTED: Kernel returned EINVAL (Syscall option unknown).
    CONFIG_X86_USER_SHADOW_STACK is disabled in this kernel.

---------------------------------------------------------
  [Test 2/2] Kernel Indirect Branch Tracking (IBT) / ENDBR
---------------------------------------------------------
[*] Kernel IBT Config:       DISABLED
[*] User Shadow Stack Config:DISABLED
[*] HW IBT Supported:        NO
[*] HW SHSTK Supported:      NO
[*] Compiler ENDBR Detected: NO
[*] Legit Target Address:    0xffffffff81958080
[*] No-ENDBR Target Address: 0xffffffff819580a0

[Step 2A] Triggering legitimate indirect call (with ENDBR64)...
[+] Result: LEGIT_SUCCESS (Total calls: 1)

[Step 2B] Triggering indirect call to target lacking ENDBR64...
[*] Result: NOENDBR_EXECUTED (Total calls: 2)
[!] VULNERABLE: Kernel compiled with -fcf-protection=none.
[!] Indirect call to un-instrumented target succeeded without restriction.

=========================================================
  Intel CET / IBT & Shadow Stack Verification Complete
=========================================================
```

---

## 6. Kernel Configuration and Troubleshooting

### 6.1 Kconfig Directives

```ini
# Common Intel CET support
CONFIG_X86_CET=y

# Kernel forward-edge Indirect Branch Tracking (requires -fcf-protection=branch)
CONFIG_X86_KERNEL_IBT=y

# User-space hardware Shadow Stack support
CONFIG_X86_USER_SHADOW_STACK=y

# Crash & vulnerability test framework
CONFIG_LKDTM=y
```

### 6.2 Boot Commandline Parameters

- `ibt=warn`:
  - When `#CP` occurs due to missing ENDBR, emits a warning calltrace and clears FRED/IDT WFE state rather than crashing immediately with `BUG()`.
- `ibt=off`:
  - Explicitly clears `X86_FEATURE_IBT` at boot time, disabling hardware IBT validation.

---

## 7. Attack Surface & Limitations

1. **Coarse-Grained CFI Limitations**:
   - Intel IBT is coarse-grained: any function beginning with `endbr64` is considered a valid target, regardless of its prototype signature.
   - Attackers can still redirect indirect calls to other legitimate functions that start with `endbr64`.
2. **FineIBT Mitigation**:
   - Modern kernels introduce FineIBT (`CONFIG_X86_KERNEL_IBT` + Clang kCFI), chaining hardware `endbr64` checks with software 32-bit type hash validation.
3. **Data-Only Attacks**:
   - Shadow stacks exclusively protect return addresses; local variables and heap pointers remain susceptible to corruption, necessitating complementary defenses (e.g., `STACKPROTECTOR_STRONG`, `HARDENED_USERCOPY`).

---

## 8. Interactive Architecture Diagram

Inspect the interactive visual simulation of Intel CET state transitions:
- [Intel CET Architecture Diagram](file:///home/auking45/repos/linux-kernel-hardening-lab/docs/assets/diagrams/ibt-shstk/architecture.html)

