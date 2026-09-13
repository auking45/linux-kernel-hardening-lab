# CONFIG_GCC_PLUGIN_STACKLEAK: Kernel Stack Erasing & Information Leak Defense

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/stackleak/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="STACKLEAK Architecture Diagram"></iframe>
</div>

---

## 1. Overview & Threat Model

### 1.1 The Threat: Residual Stack Information Leaks & KASLR Defeat

- **Kernel Stack Reuse and Residual Data**:
  - In the Linux kernel, tasks share a dedicated, fixed-size kernel stack (typically 16KB `THREAD_SIZE` on x86_64 and ARM64).
  - When a system call finishes execution and returns to user space (Syscall Exit), the kernel restores the stack pointer (`RSP`/`SP`) to its baseline level, but it does not wipe the underlying memory pages.
  - Sensitive internal data left behind during syscall processing—such as kernel function pointers, struct addresses, and cryptographic fragments—remains resident on the stack memory.
- **Kernel Information Leaks via Uninitialized Stack Variables**:
  - If a subsequent system call executes a code path where local variables or structs are left uninitialized, those variables map directly over the lingering data from previous system calls.
  - When an attacker triggers an uninitialized read that gets copied to user space via `copy_to_user()`, kernel text or data addresses are exposed, completely defeating **KASLR (Kernel Address Space Layout Randomization)**.
  - Armed with the leaked kernel base address, attackers can compute gadget offsets and craft functional Return-Oriented Programming (ROP) payloads.

### 1.2 The Hotel Room Cleaning Metaphor

- **Intuitive Analogy**:
  - Think of the kernel stack as a **hotel room** occupied sequentially by different guests (system calls).
  - **Before Hardening (Base Kernel)**: Guest A (system call 1) checks out, inadvertently leaving confidential corporate documents (kernel pointers) inside the desk drawer. The hotel does not clean the room before checking in Guest B (the attacker's system call 2). Guest B opens the drawer (uninitialized stack read) and steals the confidential documents.
  - **With STACKLEAK Hardening**: The instant Guest A checks out, a dedicated housekeeping crew (`stackleak_erase`) enters the room and sterilizes every touched drawer from `lowest_stack` up to the top with fresh white sheets and indelible poison (`0xffffffffffff4111` / `-0xBEEF`). Whichever drawer Guest B opens, they encounter only poison.

---

## 2. Kernel Internal Architecture

### 2.1 GCC Compiler Plugin Instrumentation (`stackleak_track_stack`)

- **Real-Time Tracking of Lowest Stack Watermark**:
  - `CONFIG_GCC_PLUGIN_STACKLEAK` functions at compile time via a GCC compiler plugin (`scripts/gcc-plugins/stackleak_plugin.c`).
  - For every kernel function with a stack frame greater than or equal to `CONFIG_STACKLEAK_TRACK_MIN_SIZE` (default: 100 bytes), the plugin inserts a tracking call:

    ```c
    void __used stackleak_track_stack(void)
    {
        unsigned long sp = current_stack_pointer;

        if (sp < current->lowest_stack &&
            sp >= stackleak_task_low_bound(current)) {
            current->lowest_stack = sp;
        }
    }
    ```

  - The `lowest_stack` member within `struct task_struct` dynamically tracks the lowest depth reached by the kernel stack during the active system call.

### 2.2 Syscall Exit Erasing Routine (`stackleak_erase`)

- **Syscall Exit Assembly Hook**:
  - Immediately before control returns to user space, the architecture-specific syscall exit assembly (`arch/x86/entry/calling.h`, `arch/arm64/kernel/entry.S`) invokes `stackleak_erase()`.
- **Stack Erasing Logic (`__stackleak_erase`)**:

  ```c
  static __always_inline void __stackleak_erase(bool on_task_stack)
  {
      const unsigned long task_stack_low = stackleak_task_low_bound(current);
      const unsigned long task_stack_high = stackleak_task_high_bound(current);
      unsigned long erase_low, erase_high;

      erase_low = stackleak_find_top_of_poison(task_stack_low,
                                               current->lowest_stack);
      erase_high = on_task_stack ? current_stack_pointer : task_stack_high;

      __stackleak_poison(erase_low, erase_high, STACKLEAK_POISON);

      /* Reset lowest_stack watermark for the next syscall */
      current->lowest_stack = task_stack_high;
  }
  ```

- **Definition of `STACKLEAK_POISON`**:
  - Defined in `include/linux/stackleak.h` as `#define STACKLEAK_POISON -0xBEEF`.
  - On 64-bit architectures, this sign-extends to **`0xffffffffffff4111`**.
  - This constant resides within the canonical hole / unmapped virtual memory, ensuring that any accidental pointer dereference triggers an instantaneous Page Fault rather than allowing arbitrary memory corruption.

### 2.3 Defense Against Kernel Stack Clash / Exhaustion

- `stackleak_task_low_bound(current)` marks the boundary just above `STACK_END_MAGIC` (0x57ac6e9d) at the bottom of the stack page.
- In the event of deep recursion or malicious stack allocation attempts, `stackleak_track_stack()` prevents uncontrolled stack growth from corrupting neighboring task structures and thread info blocks.

---

## 3. Hands-on Lab & Exploit PoC

### 3.1 Vulnerable Target Driver (`vuln_stackleak.c`)

- Exposes `/proc/vuln_stackleak` with world-writable permissions (mode `0666`):
  - **Write Operation (Stack Imprinting)**: Allocates a deep stack frame (>100 bytes), writes kernel function addresses into the stack memory, and exits the syscall.
  - **Read Operation (Uninitialized Leak Attempt)**: Allocates a 512-byte uninitialized buffer (`uninit_stack`) that overlaps previous stack frames, and copies raw stack bytes back to user space via `copy_to_user()`.

### 3.2 Dual-Arch Verification & Live Output Comparison

```bash
# 1. Base Kernel (Vulnerable Baseline)
./scripts/run_lab.sh --arch x86_64 --feature stackleak-disabled --test test_stackleak

# 2. Hardened Kernel (STACKLEAK Active)
./scripts/run_lab.sh --arch x86_64 --feature stackleak --test test_stackleak
```

=== "Base Kernel (Vulnerable: KASLR Infoleak Succeeded)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - STACKLEAK Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] STACKLEAK Metric (/proc/<pid>/stack_depth): Not present (Disabled)

    [*] Step 1: Triggering kernel stack imprinting via write()...
        Write completed. Syscall exit returned to userspace.

    [*] Step 2: Reading uninitialized kernel stack via read()...
        Received 512 bytes of kernel stack memory.

    [*] Step 3: Analyzing leaked stack memory contents:
        Total Words Sampled:  64
        Poison Matches:       0 (STACKLEAK_POISON = 0xffffffffffff4111)
        Kernel Pointer Leaks: 32

    =========================================================
    [!] VULNERABILITY CONFIRMED: KASLR BYPASS VIA STACK LEAK
    [!] Leaked Kernel Function Pointer: 0xffffffff812356c0
    [!] Kernel stack was NOT poisoned on syscall exit.
    [!] Attackers can calculate kernel slide & defeat KASLR!
    =========================================================
    ```
    > **Analysis:** On the unhardened baseline kernel, residual kernel text addresses persisted across system call boundaries. The unprivileged exploit binary easily computed the kernel base address, defeating KASLR.

=== "Hardened Kernel (Mitigated: STACKLEAK Active)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - STACKLEAK Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] STACKLEAK Metric (/proc/48/stack_depth): 672
    [*] STACKLEAK Runtime Sysctl (/proc/sys/kernel/stack_erasing): 1

    [*] Step 1: Triggering kernel stack imprinting via write()...
        Write completed. Syscall exit returned to userspace.

    [*] Step 2: Reading uninitialized kernel stack via read()...
        Received 512 bytes of kernel stack memory.

    [*] Step 3: Analyzing leaked stack memory contents:
        Total Words Sampled:  64
        Poison Matches:       64 (STACKLEAK_POISON = 0xffffffffffff4111)
        Kernel Pointer Leaks: 0

    =========================================================
    [+] DEFENSE ACTIVE: STACKLEAK MITIGATION VERIFIED!
    [+] Stack memory contains 64 STACKLEAK_POISON values (-0xBEEF).
    [+] All residual stack data was wiped on syscall exit.
    [+] Kernel pointer leakage completely blocked!
    =========================================================
    ```
    > **Analysis:** With STACKLEAK active, every used byte on the stack was overwritten with `0xffffffffffff4111` upon syscall exit. The uninitialized read returned purely poison values, rendering KASLR bypass impossible.

---

### 3.3 LKDTM Self-Test Verification (`STACKLEAK_ERASING`)

LKDTM provides direct in-kernel verification of the stack erasing logic:

```bash
echo STACKLEAK_ERASING > /sys/kernel/debug/provoke-crash/DIRECT
```

- **Hardened Kernel dmesg**:
  ```text
  [    5.471970] lkdtm: Performing direct entry STACKLEAK_ERASING
  [    5.473268] lkdtm: stackleak stack usage:
  [    5.473268]   high offset: 168 bytes
  [    5.473268]   current:     344 bytes
  [    5.473268]   lowest:      944 bytes
  [    5.473268]   tracked:     944 bytes
  [    5.473268]   untracked:   128 bytes
  [    5.473268]   poisoned:    15136 bytes
  [    5.473268]   low offset:  8 bytes
  [    5.473530] lkdtm: OK: the rest of the thread stack is properly erased
  ```
- **Base Kernel dmesg**:
  ```text
  [   12.190412] lkdtm: Performing direct entry STACKLEAK_ERASING
  [   12.190981] XFAIL: stackleak is not enabled (CONFIG_GCC_PLUGIN_STACKLEAK=n)
  ```

---

## 4. Runtime Administration & Telemetry

### 4.1 `/proc/<pid>/stack_depth` Metric

- Available when `CONFIG_STACKLEAK_METRICS=y`.
- Exposes maximum kernel stack consumption in bytes for current and prior system calls, providing essential telemetry for capacity planning.

### 4.2 `/proc/sys/kernel/stack_erasing` Runtime Switch

- Available when `CONFIG_STACKLEAK_RUNTIME_DISABLE=y`.
  - `1` (default): Stack erasing actively enforced on syscall exit.
  - `0`: Stack erasing temporarily bypassed (useful for isolated performance benchmarks).

---

## 5. Performance & Overhead Analysis

- **CPU Overhead**:
  - Erasing cost is proportional strictly to the **actual stack depth consumed (`lowest_stack` to `task_stack_high`)**, rather than the entire 16KB stack allocation.
  - Typical system workloads experience approximately **~1% CPU overhead**, making it suitable for security-conscious server and enterprise deployments.
- **Memory Overhead**:
  - Adds only two pointer fields (`lowest_stack` and `prev_lowest_stack`, 8 bytes each) to `struct task_struct`, resulting in virtually zero memory footprint increase.

---

## 6. Presentation Script & Vocabulary

### 6.1 Presentation Script (English & Korean)

```text
[Step 1: Hook - The Hotel Room & Abandoned Stack Data]
"Imagine checking out of a hotel room leaving confidential documents in a nightstand drawer,
 and housekeeping never cleans the room before the next guest arrives.
 That is precisely the default state of the Linux kernel stack.
 When a system call exits, residual kernel pointers remain intact, allowing uninitialized
 reads in subsequent syscalls to completely shatter KASLR."

[Step 2: Metaphor & Architecture - STACKLEAK Poisoning Mechanics]
"CONFIG_GCC_PLUGIN_STACKLEAK acts as an uncompromising automated housekeeping officer.
 It continuously tracks the lowest stack boundary during execution, and the moment a syscall exits,
 it wipes every single used byte with the poison value 0xffffffffffff4111, or -0xBEEF.
 Whatever uninitialized buffer a subsequent syscall inspects, it sees nothing but poison."

[Step 3: Demo & Proof - Live QEMU and LKDTM Validation]
"In our live QEMU verification, an unprivileged user effortlessly extracted kernel pointers on the baseline kernel.
 But with STACKLEAK active, all 64 sampled stack words were reliably wiped with STACKLEAK_POISON,
 blocking the leak entirely. LKDTM kernel self-tests conclusively confirmed that the thread stack was properly erased."
```

### 6.2 Key Presentation Phrases

| English Speaking Phrase                                            | Technical Context & Usage Tip                                                 |
| :----------------------------------------------------------------- | :---------------------------------------------------------------------------- |
| _"erase residual kernel stack data upon syscall exit"_             | Summarizing the core operational trigger of STACKLEAK                         |
| _"track the lowest stack watermark in real-time"_                  | Explaining the function of compiler instrumentation (`stackleak_track_stack`) |
| _"poison the stack with non-canonical values (-0xBEEF)"_           | Highlighting the safety value of the chosen poison constant                   |
| _"preemptively thwart uninitialized stack infoleaks"_              | Emphasizing attack surface reduction against KASLR bypasses                   |
| _"overhead driven strictly by stack depth rather than call count"_ | Articulating why STACKLEAK maintains a negligible ~1% CPU cost                |
