# Stack Protector (`CONFIG_STACKPROTECTOR_STRONG`)

In-depth mechanism analysis and hands-on verification of compiler-injected stack canaries protecting kernel function return addresses against buffer overflows.

---

## 1. Overview & Threat Model

- **Target Vulnerabilities**:
  - Stack-based buffer overflows.
  - Manipulation of saved frame pointers (SFP) and function return addresses (RIP / LR).
  - Return-Oriented Programming (ROP) gadget execution leading to Ring 0 privilege escalation.
- **Attack Scenario & Threat Vectors**:
  - Unbounded memory copy routines (`memcpy`, `strcpy`, off-by-one loop indexing) inside kernel drivers or system calls.
  - Attacker overwrites beyond the boundary of local arrays toward higher memory addresses.
  - When the function reaches its epilogue, execution branches to an attacker-controlled return address.

---

## 2. Architecture & Mechanism

### 2.1 Interactive System Map (Archify Diagram)

Use the interactive controls below to explore the **normal execution flow**, **buffer overflow defense sequence**, and **register differences between x86_64 and ARM64**:

<div class="archify-container">
  <iframe src="../../assets/diagrams/stack-protector/architecture.html" width="100%" height="450px" frameborder="0"></iframe>
</div>

---

### 2.2 Defense Sequence Diagram (Mermaid)

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker Exploit Payload
    participant Stack as Stack Frame
    participant Epilogue as Function Epilogue
    participant Guard as CPU Register Reference (%gs:40 / __stack_chk_guard)
    participant Panic as __stack_chk_fail() [Panic Handler]

    Note over Stack: [Local Buffer] [Canary (Random)] [Saved FP] [Return Address]
    Attacker->>Stack: Overflow buffer boundary (Canary corrupted)
    Epilogue->>Stack: Load Canary from stack
    Epilogue->>Guard: Load reference Guard from register
    Epilogue->>Epilogue: XOR comparison (Canary ^ Guard)
    alt Value Matches (Legitimate Return)
        Epilogue->>Epilogue: Safe return to caller
    else Value Mismatch (Tampering Detected)
        Epilogue->>Panic: Immediate call to __stack_chk_fail()
        Panic->>Panic: Kernel Panic and execution halted
    end
```

---

### 2.3 Architecture-Specific Assembly Implementation

#### (1) x86_64 Assembly Mechanism

The compiler reads a random value from the `%gs` segment register (Per-CPU storage offset `0x40`) during prologue and validates it during epilogue:

```nasm
; [x86_64 Function Prologue: Canary Insertion]
pushq   %rbp
movq    %rsp, %rbp
subq    $0x50, %rsp
movq    %gs:40, %rax          ; Load canary from Per-CPU segment
movq    %rax, -8(%rbp)        ; Store immediately before return address
xorl    %eax, %eax            ; Clear temporary register to prevent leak

; ... Function body execution ...

; [x86_64 Function Epilogue: Canary Verification]
movq    -8(%rbp), %rax        ; Load canary from stack
xorq    %gs:40, %rax          ; Compare with master canary
jne     .L_stack_chk_fail     ; Branch to failure handler if non-zero
leave
ret

.L_stack_chk_fail:
call    __stack_chk_fail      ; Trigger kernel panic
```

#### (2) ARM64 (aarch64) Assembly Mechanism

ARM64 loads the guard value from global symbol `__stack_chk_guard` and stores it relative to the stack pointer:

```nasm
; [ARM64 Function Prologue: Canary Insertion]
stp     x29, x30, [sp, -80]!  ; Save FP(x29) and LR(x30)
mov     x29, sp
adrp    x8, __stack_chk_guard
ldr     x8, [x8, :lo12:__stack_chk_guard]
str     x8, [sp, 72]          ; Store canary on stack

; ... Function body execution ...

; [ARM64 Function Epilogue: Canary Verification]
ldr     x9, [sp, 72]          ; Load canary from stack
subs    x8, x8, x9            ; Compare values
b.ne    .L_panic_branch       ; Branch on mismatch
ldp     x29, x30, [sp], 80    ; Restore registers and return
ret

.L_panic_branch:
bl      __stack_chk_fail      ; Call panic handler
```

---

## 3. Configuration & Options (Kconfig)

### 3.1 GCC / Clang Compiler Protection Levels

| Flag                           | Target Functions                                                | Security Level         | Overhead            |
| :----------------------------- | :-------------------------------------------------------------- | :--------------------- | :------------------ |
| `-fno-stack-protector`         | Disabled                                                        | None                   | 0% (Baseline)       |
| `-fstack-protector`            | Functions with `char` arrays >= 8 bytes only                    | Low                    | < 0.1%              |
| **`-fstack-protector-strong`** | **Any array, or any local variable address reference (`&val`)** | **High (Recommended)** | **< 0.5%**          |
| `-fstack-protector-all`        | Every function regardless of structure                          | Extreme                | ~5-10% (Suboptimal) |

### 3.2 Linux Kernel Kconfig Configuration

```kconfig
# /configs/features/stack-protector.config
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
# CONFIG_STACKPROTECTOR_ALL is not set
```

- `CONFIG_STACKPROTECTOR_STRONG=y` selectively protects functions with potential memory exposure while maintaining runtime overhead under 0.5%.

---

## 4. Hands-on Verification

Verification using LKDTM `CORRUPT_STACK` trigger to intentionally induce a stack overflow, contrasting the runtime behavior between Base and Hardened kernels.

### 4.1 One-Click Verification Commands

=== "x86_64: Hardened (Enabled - Recommended)"

    ```bash
    ./scripts/run_lab.sh --arch x86_64 --feature stack-protector --test test_stack_protector
    ```

    **Runtime Verification Log (Attack Intercepted)**:
    ```text
    =========================================================
      Triggering LKDTM CORRUPT_STACK Test
      Kernel Architecture: x86_64
      Kernel Release:      6.12.109
    =========================================================
    [*] Injecting stack corruption payload...
    [    1.892031] lkdtm: Performing direct entry CORRUPT_STACK
    [    1.892842] lkdtm: attempting bad stack write ...
    [    1.893601] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: lkdtm_CORRUPT_STACK+0x4a/0x60
    [    1.894812] CPU: 0 PID: 68 Comm: sh Not tainted 6.12.109-hardened #1
    [    1.895521] Call Trace:
    [    1.895842]  <TASK>
    [    1.896120]  dump_stack_lvl+0x48/0x70
    [    1.896614]  panic+0x140/0x310
    [    1.897011]  __stack_chk_fail+0x15/0x20
    [    1.897410]  lkdtm_CORRUPT_STACK+0x4a/0x60
    ```
    > **Analysis:** The function epilogue detected canary corruption and invoked `__stack_chk_fail()`, preventing ROP execution through immediate kernel panic.

=== "x86_64: Base (Disabled - Vulnerable)"

    ```bash
    ./scripts/run_lab.sh --arch x86_64 --feature stack-protector-disabled --test test_stack_protector
    ```

    **Runtime Verification Log (Unchecked Crash)**:
    ```text
    =========================================================
      Triggering LKDTM CORRUPT_STACK Test
      Kernel Architecture: x86_64
      Kernel Release:      6.12.109
    =========================================================
    [*] Injecting stack corruption payload...
    [    2.104201] lkdtm: Performing direct entry CORRUPT_STACK
    [    2.104910] lkdtm: attempting bad stack write ...
    [    2.105700] general protection fault, probably for non-canonical address 0x4141414141414141: 0000 [#1] PREEMPT SMP
    [    2.106912] RIP: 0010:0x4141414141414141
    ```
    > **Analysis:** With canary disabled, execution jumps directly to attacker input (`0x4141414141414141`), generating a raw general protection fault.

=== "ARM64: Hardened (Enabled)"

    ```bash
    ./scripts/run_lab.sh --arch arm64 --feature stack-protector --test test_stack_protector
    ```

    **Runtime Verification Log (ARM64 Kernel Panic)**:
    ```text
    =========================================================
      Triggering LKDTM CORRUPT_STACK Test
      Kernel Architecture: aarch64
      Kernel Release:      6.12.109
    =========================================================
    [*] Injecting stack corruption payload...
    [    2.012491] lkdtm: Performing direct entry CORRUPT_STACK
    [    2.013102] lkdtm: attempting bad stack write ...
    [    2.013910] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: lkdtm_CORRUPT_STACK+0x3c/0x50
    [    2.014901] CPU: 0 PID: 65 Comm: sh Not tainted 6.12.109-arm64-hardened #1
    [    2.015702] Call trace:
    [    2.016012]  dump_backtrace+0x94/0xec
    [    2.016420]  show_stack+0x18/0x24
    [    2.016812]  dump_stack_lvl+0x48/0x60
    [    2.017210]  panic+0x144/0x320
    [    2.017611]  __stack_chk_fail+0x18/0x24
    [    2.018012]  lkdtm_CORRUPT_STACK+0x3c/0x50
    ```

---

## 5. Performance & Overhead Analysis

- **CPU Overhead**: Measured under **0.3% ~ 0.5%** in standard Linux server and I/O workloads.
- **Binary Size Impact**: Kernel `.text` segment grows by approximately **1.2% ~ 1.5%**.
- **Production Recommendation**: High-impact mitigation with negligible cost; strongly recommended as a mandatory baseline across cloud, server, Android, and embedded deployments.

---

## 6. Lecture & Presentation Script (English Speaking Practice)

This section provides a realistic first-person presentation script and essential technical speaking phrases for engineering seminars, technical interviews, and conference talks.

### 6.1 Full Speaking Script

#### Part 1: Opening Hook & Problem Statement
> "Hello everyone. Today, let's take a deep dive into one of the most fundamental yet critical defenses in the Linux kernel: **Stack Protector Strong**, or `CONFIG_STACKPROTECTOR_STRONG`."
>
> "Think about what happens when a kernel driver performs an unbounded memory copy on the stack. Without any protection, an attacker can simply overflow a local buffer, smash through the saved frame pointer, and overwrite the function's return address. When that function returns, the CPU doesn't go back to the caller—it jumps straight into the attacker's ROP gadgets in Ring 0. That is an instant privilege escalation. So, how does the kernel prevent this?"

#### Part 2: Diagram & Architecture Walkthrough
> "If you look at our interactive system map above, notice where the **Stack Canary** sits. It is positioned right between the local buffers and the saved frame pointer."
>
> "Here is how it works under the hood: during the function prologue, the compiler inserts assembly instructions that fetch a random 64-bit secret from a protected CPU register—specifically `%gs:40` on x86_64, or `__stack_chk_guard` on ARM64—and places it right onto the stack."
>
> "Now, look at the epilogue. Right before the function returns, the CPU loads the canary from the stack and XORs it against the original register value. If an overflow occurred, that canary value is already corrupted. The XOR result is non-zero, the equality check fails, and instead of returning to a hijacked address, the kernel immediately jumps to `__stack_chk_fail()`, triggering a panic and halting execution on the spot."

#### Part 3: Live Demo Commentary
> "Let's see this in action in our QEMU environment. First, we run a kernel with stack protection disabled and trigger the LKDTM `CORRUPT_STACK` test."
>
> "Notice the output: the kernel doesn't catch the corruption. Instead, it crashes with a raw general protection fault because RIP was overwritten with our dummy attacker value, `0x4141414141414141`. If this were a real exploit, the attacker would have control."
>
> "Now, let's switch to our hardened kernel with `CONFIG_STACKPROTECTOR_STRONG=y`. When we run the exact same test, watch the console: `Kernel panic - not syncing: stack-protector: Kernel stack is corrupted`. The canary intercepted the buffer overflow before the CPU could execute a single hijacked instruction."

#### Part 4: Key Takeaways & Trade-offs
> "To wrap up: why do we specifically use `-fstack-protector-strong` instead of `-all`? Because `-strong` intelligently targets only the functions that actually have arrays or take address references of local variables. This gives us nearly the exact same security coverage as `-all`, but keeps the CPU overhead under 0.5%."
>
> "In modern production systems—whether it's cloud hypervisors or Android devices—this is an absolute, non-negotiable baseline defense. Thank you."

---

### 6.2 Key Presentation Phrases & Speaking Patterns

| Intent / Context | Recommended Spoken Phrase | Usage & Delivery Notes |
| :--- | :--- | :--- |
| **Transitioning to Architecture** | *"Under the hood, ..."* / *"If we look under the hood..."* | Natural transition when moving into low-level internals or assembly. |
| **Describing Memory Corruption** | *"smash through ~"* / *"overwrite the return address"* | Vivid, idiomatic description of buffer overflows bypassing boundaries. |
| **Emphasizing Immediate Mitigation** | *"halt execution on the spot"* / *"intercept the attack"* | Highlights the immediate fail-safe nature of the panic handler. |
| **Discussing Engineering Decisions** | *"When considering the trade-offs..."* | Effective segue when weighing CPU overhead against security benefits. |
| **Concluding with Strong Recommendation** | *"an absolute, non-negotiable baseline defense"* | Authoritative closing statement for production readiness. |
