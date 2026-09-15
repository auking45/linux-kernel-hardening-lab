# CONFIG_STRICT_KERNEL_RWX & CONFIG_STRICT_MODULE_RWX: Kernel W^X Permission Separation & Read-Only Invariance

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/strict-rwx/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="CONFIG_STRICT_KERNEL_RWX Architecture Diagram"></iframe>
</div>

---

## 1. Overview & Threat Model

### 1.1 Addressed Threat: Kernel Code Patching and In-Memory Rootkit Injection

- **Vulnerabilities in the Absence of W^X Invariants**:
  - Legacy operating system kernels traditionally mapped their entire memory space with read, write, and execute permissions ($RWX$) for convenience during boot and performance optimization.
  - In this permissive model, an attacker who obtains a single arbitrary write primitive can directly overwrite instructions in the kernel `.text` section (in-memory code patching), overwrite the system call table (`sys_call_table`), or hijack kernel function pointers to achieve persistent rootkit-level control.
- **The W^X (Write XOR Execute) Security Invariant**:
  - A memory page may be writable or executable, but never both simultaneously ($W \cap X = \emptyset$).
  - **Code Section (`.text`)**: Strictly mapped as Read and Execute ($R-X$), preventing runtime instruction modification.
  - **Constant Section (`.rodata`)**: Strictly mapped as Read-Only ($R--$), protecting dispatch tables and critical security constants.
  - **Post-Init Read-Only Section (`__ro_after_init`)**: Mapped as Read-Only ($R--$) permanently after boot initialization completes.
  - **Data/Heap/Stack Sections (`.data`, `.bss`, kmalloc, stack)**: Mapped as Read-Write but non-executable ($RW-$).

### 1.2 Real-World Metaphor: The Rare Manuscript Library Metaphor

- **Metaphor Details**:
  - Consider the kernel virtual address space as a national library's rare manuscript reading room.
  - **Without Hardening (`rodata=off`, W+X allowed)**:
    - Visitors are permitted into the historical document vault (`.text` and `.rodata`) holding permanent markers and correction fluid (arbitrary write permissions).
    - A malicious visitor can easily cross out constitutional clauses and write new fraudulent rules directly on the documents (syscall table hooking and code patching). The security guards (MMU) take no action against writing.
  - **With Hardening Enforced (`CONFIG_STRICT_KERNEL_RWX=y`, `rodata=on`)**:
    - Rare documents (`.rodata`, `.text`) are sealed behind bulletproof display cases ($R--$, $R-X$).
    - The moment anyone presses a pen against the bulletproof casing, an electronic sensor triggers an immediate hardware alarm (MMU Page Fault / CR0.WP) and security guards apprehend the violator (EFAULT returned, write aborted).
    - Visitors can write in the guest sign-in ledger (`.data`, $RW-$), but attempting to proclaim the guest book as law ($X$) results in immediate confiscation.

---

## 2. Kernel Internal Architecture

### 2.1 Hardware MMU Write Protection and Permission Bits

- **x86_64 Control Registers and Page Table Entries**:
  - **CR0.WP (Write Protect Bit, Bit 16)**:
    - When $CR0.WP = 1$, the CPU triggers a Page Fault (`#PF`) with supervisor write violation if code executing in Ring 0 attempts to write to a page marked Read-Only ($R/W = 0$) in its Page Table Entry (PTE).
    - If $CR0.WP = 0$, Ring 0 supervisor code can overwrite any page regardless of the PTE read-only bit, disabling kernel self-protection.
  - **PTE Bit Layout**:
    - Bit 1 ($R/W$): 0 indicates Read-Only, 1 indicates Read/Write.
    - Bit 63 ($NX$/$XD$): No-Execute bit. When set, instruction fetches from data pages are trapped by hardware.
- **ARM64 (AArch64) Architecture Controls**:
  - **Stage 1 Translation Table Descriptor AP[2:1] (Data Access Permissions)**:
    - `0b00`: EL1 Read/Write, EL0 No Access.
    - `0b10`: EL1 Read-Only, EL0 No Access (applied to kernel `.text`, `.rodata`, and `__ro_after_init`).
  - **UXN / PXN (Privileged Execute-Never)**:
    - Data pages are marked with $PXN=1$, preventing instruction execution in kernel EL1.

### 2.2 Boot Lifecycle and `mark_rodata_ro()` Transition

- **Protection Lifecycle Sequence (`init/main.c`)**:
  1. **Early Boot Stage**:
     - During decompression and early page table construction, temporary write permissions are necessary for CPU setup and self-patching.
  2. **`mark_readonly()` Invocation (`init/main.c:1434`)**:
     - Right before launching PID 1, the kernel calls `mark_readonly()`:
     ```c
     /* init/main.c */
     static void mark_readonly(void)
     {
         if (rodata_enabled) {
             mark_rodata_ro();
             rodata_test();
         } else
             pr_info("Kernel memory protection disabled.\n");
     }
     ```
  3. **Execution of `mark_rodata_ro()` (`arch/x86/mm/init_64.c` / `arch/arm64/mm/mmu.c`)**:
     - `.text` section: Locked with `set_memory_ro()` ($R-X$).
     - `.rodata` section: Locked with `set_memory_ro()` and `set_memory_nx()` ($R--$).
     - `__init` section: Unused initialization memory is freed and scrubbed (`free_initmem()`).
  4. **`__ro_after_init` Freezing**:
     - Variables annotated with `__ro_after_init` allow writes during boot initialization, but are permanently changed to $R--$ during `mark_rodata_ro()`.

### 2.3 Module Protection (`CONFIG_STRICT_MODULE_RWX`)

- Dynamically loaded loadable kernel modules (`.ko`) are protected via `kernel/module/strict_rwx.c`.
- `module_enable_ro()` and `module_enable_nx()` enforce $R-X$ for module code, $RW-$ for module data, and $R--$ for module rodata.

---

## 3. Hands-on Lab Implementation

### 3.1 Target Vulnerable Driver (`vuln_strict_rwx.c`)

- Accessible via `/proc/vuln_strict_rwx` (mode 0666):
  - **Telemetry Exposure**:
    - `STRICT_KERNEL_RWX`: Kconfig compile-time status.
    - `RODATA_BOOT_PARAM`: Runtime boot parameter (`rodata=on` vs `rodata=off`).
    - `WX_PROTECTION_STATUS`: Enforcement status (`ENABLED` vs `DISABLED`).
    - Addresses for target symbols: `TARGET_TEXT_ADDR`, `TARGET_RODATA_ADDR`, `TARGET_RO_AFTER_INIT`.
  - **Safe Ring 0 Memory Probing (`copy_to_kernel_nofault`)**:
    - Uses the Linux kernel self-test standard function `copy_to_kernel_nofault()`.
    - Routes page fault exceptions through the kernel exception fixup table (`extable`), returning `-EFAULT` cleanly instead of triggering an unrecoverable kernel panic.

### 3.2 W^X Exploit PoC (`exploit.c`)

- Executed by unprivileged user (`lab`, UID 1000) at `/bin/exploit_strict_rwx`:
  - **Vector 1 (.text Patching)**: Overwrites kernel code with NOP sled instructions (0x90).
  - **Vector 2 (.rodata Overwrite)**: Attempts to corrupt constant table data.
  - **Vector 3 (__ro_after_init Overwrite)**: Attempts to overwrite post-init security flags.
  - **Evaluation**:
    - `Base (rodata=off)`: Writes succeed, confirming vulnerability (`[!] VULNERABILITY CONFIRMED: W^X Memory Protection is DISABLED!`).
    - `Hardened (rodata=on)`: Writes are blocked by MMU, confirming defense (`[+] DEFENSE ACTIVE: CONFIG_STRICT_KERNEL_RWX verified!`).

---

## 4. Dual-Architecture Live Verification

### 4.1 x86_64 Architecture Results

#### Base Kernel (`strict-rwx-disabled`, `rodata=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=off
W^X Protection: DISABLED (rodata=off active)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=off (Disabled)
WX_PROTECTION_STATUS:  DISABLED (Vulnerable W+X)
TARGET_TEXT_ADDR:      0xffffffff813abb50
TARGET_RODATA_ADDR:    0xffffffff8184da38
TARGET_RO_AFTER_INIT:  0xffffffff8198b2f8
TARGET_DATA_ADDR:      0xffffffff81ac2c08
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=off (Disabled)
    W^X Invariant:       DISABLED (Vulnerable W+X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffffffff813abb50 (Expected: R-X)
    .rodata (Const):     0xffffffff8184da38 (Expected: R--)
    __ro_after_init:     0xffffffff8198b2f8 (Expected: R--)
    .data (Variables):   0xffffffff81ac2c08 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffffffff813abb50
    Result: PERMITTED (Writable)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffffffff8184da38
    Result: PERMITTED (Writable)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffffffff8198b2f8
    Result: PERMITTED (Writable)

=========================================================
[!] VULNERABILITY CONFIRMED: W^X Memory Protection is DISABLED!
[!] Kernel .text and .rodata are WRITABLE in supervisor mode.
[!] Rootkits can easily hook syscall tables, patch kernel opcodes,
    and tamper with sensitive security function pointers.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    1.086158] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=0)
[    1.335156] Freeing unused kernel image (initmem) memory: 1484K
[    1.335399] Kernel memory protection disabled.
[    1.778932] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffffffff813abb50...
[    1.779213] [vuln_strict_rwx] [!] CRITICAL: Kernel .text successfully modified! Rootkit code patching confirmed!
[    1.779284] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffffffff8184da38...
[    1.779391] [vuln_strict_rwx] [!] CRITICAL: .rodata value corrupted to 0x55aa55aa11223344!
[    1.779474] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffffffff8198b2f8...
[    1.779515] [vuln_strict_rwx] [!] CRITICAL: __ro_after_init value corrupted to 0xdeaddeaddeaddead!
```

#### Hardened Kernel (`strict-rwx`, `CONFIG_STRICT_KERNEL_RWX=y`, `rodata=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=on
W^X Protection: ACTIVE (CONFIG_STRICT_KERNEL_RWX enabled)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=on (Active)
WX_PROTECTION_STATUS:  ENABLED (Hardened W^X)
TARGET_TEXT_ADDR:      0xffffffff813abb50
TARGET_RODATA_ADDR:    0xffffffff8184da38
TARGET_RO_AFTER_INIT:  0xffffffff8198b2f8
TARGET_DATA_ADDR:      0xffffffff81ac2c08
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=on (Active)
    W^X Invariant:       ENABLED (Hardened W^X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffffffff813abb50 (Expected: R-X)
    .rodata (Const):     0xffffffff8184da38 (Expected: R--)
    __ro_after_init:     0xffffffff8198b2f8 (Expected: R--)
    .data (Variables):   0xffffffff81ac2c08 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffffffff813abb50
    Result: BLOCKED (Read-Only)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffffffff8184da38
    Result: BLOCKED (Read-Only)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffffffff8198b2f8
    Result: BLOCKED (Read-Only)

=========================================================
[+] DEFENSE ACTIVE: CONFIG_STRICT_KERNEL_RWX verified!
[+] Hardware MMU Write Protection (CR0.WP / PTE RO) successfully enforced.
[+] All attempts to modify .text, .rodata, and __ro_after_init were BLOCKED!
[+] Kernel W^X invariant holds: W ∩ X = ∅.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    1.271291] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=1)
[    1.554383] Freeing unused kernel image (initmem) memory: 1484K
[    1.556505] Freeing unused kernel image (rodata/data gap) memory: 424K
[    1.983431] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffffffff813abb50...
[    1.984250] [vuln_strict_rwx] [+] DEFENSE ACTIVE: Kernel .text write blocked by MMU (EFAULT)!
[    1.984314] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffffffff8184da38...
[    1.984417] [vuln_strict_rwx] [+] DEFENSE ACTIVE: .rodata write blocked by MMU (EFAULT)!
[    1.984460] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffffffff8198b2f8...
[    1.984493] [vuln_strict_rwx] [+] DEFENSE ACTIVE: __ro_after_init write blocked by MMU (EFAULT)!
```

---

### 4.2 ARM64 Architecture Results

#### Base Kernel (`strict-rwx-disabled`, `rodata=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=off
W^X Protection: DISABLED (rodata=off active)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=off (Disabled)
WX_PROTECTION_STATUS:  DISABLED (Vulnerable W+X)
TARGET_TEXT_ADDR:      0xffff800080313298
TARGET_RODATA_ADDR:    0xffff8000803c2928
TARGET_RO_AFTER_INIT:  0xffff800080471578
TARGET_DATA_ADDR:      0xffff800080630290
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=off (Disabled)
    W^X Invariant:       DISABLED (Vulnerable W+X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffff800080313298 (Expected: R-X)
    .rodata (Const):     0xffff8000803c2928 (Expected: R--)
    __ro_after_init:     0xffff800080471578 (Expected: R--)
    .data (Variables):   0xffff800080630290 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffff800080313298
    Result: PERMITTED (Writable)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffff8000803c2928
    Result: PERMITTED (Writable)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffff800080471578
    Result: PERMITTED (Writable)

=========================================================
[!] VULNERABILITY CONFIRMED: W^X Memory Protection is DISABLED!
[!] Kernel .text and .rodata are WRITABLE in supervisor mode.
[!] Rootkits can easily hook syscall tables, patch kernel opcodes,
    and tamper with sensitive security function pointers.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.583680] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=0)
[    0.669929] Freeing unused kernel memory: 1088K
[    0.672746] Kernel memory protection disabled.
[    1.156748] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffff800080313298...
[    1.156954] [vuln_strict_rwx] [!] CRITICAL: Kernel .text successfully modified! Rootkit code patching confirmed!
[    1.157025] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffff8000803c2928...
[    1.157098] [vuln_strict_rwx] [!] CRITICAL: .rodata value corrupted to 0x55aa55aa11223344!
[    1.157152] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffff800080471578...
[    1.157187] [vuln_strict_rwx] [!] CRITICAL: __ro_after_init value corrupted to 0xdeaddeaddeaddead!
```

#### Hardened Kernel (`strict-rwx`, `CONFIG_STRICT_KERNEL_RWX=y`, `rodata=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=on
W^X Protection: ACTIVE (CONFIG_STRICT_KERNEL_RWX enabled)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=on (Active)
WX_PROTECTION_STATUS:  ENABLED (Hardened W^X)
TARGET_TEXT_ADDR:      0xffff800080313298
TARGET_RODATA_ADDR:    0xffff8000803c2928
TARGET_RO_AFTER_INIT:  0xffff800080471578
TARGET_DATA_ADDR:      0xffff800080630290
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=on (Active)
    W^X Invariant:       ENABLED (Hardened W^X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffff800080313298 (Expected: R-X)
    .rodata (Const):     0xffff8000803c2928 (Expected: R--)
    __ro_after_init:     0xffff800080471578 (Expected: R--)
    .data (Variables):   0xffff800080630290 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffff800080313298
    Result: BLOCKED (Read-Only)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffff8000803c2928
    Result: BLOCKED (Read-Only)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffff800080471578
    Result: BLOCKED (Read-Only)

=========================================================
[+] DEFENSE ACTIVE: CONFIG_STRICT_KERNEL_RWX verified!
[+] Hardware MMU Write Protection (CR0.WP / PTE RO) successfully enforced.
[+] All attempts to modify .text, .rodata, and __ro_after_init were BLOCKED!
[+] Kernel W^X invariant holds: W ∩ X = ∅.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.486346] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=1)
[    0.555212] Freeing unused kernel memory: 1088K
[    0.975107] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffff800080313298...
[    0.975523] [vuln_strict_rwx] [+] DEFENSE ACTIVE: Kernel .text write blocked by MMU (EFAULT)!
[    0.975586] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffff8000803c2928...
[    0.975645] [vuln_strict_rwx] [+] DEFENSE ACTIVE: .rodata write blocked by MMU (EFAULT)!
[    0.975693] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffff800080471578...
[    0.975730] [vuln_strict_rwx] [+] DEFENSE ACTIVE: __ro_after_init write blocked by MMU (EFAULT)!
```


---

### 4.3 Security Comparison Matrix

| Evaluation Metric | Base (`rodata=off`) | Hardened (`CONFIG_STRICT_KERNEL_RWX=y`) |
| :--- | :--- | :--- |
| **Kernel `.text` Section Permissions** | $RWX$ (Simultaneous write/execute, vulnerable) | **$R-X$ (Read and Execute strictly, write prohibited)** |
| **Kernel `.rodata` Section Permissions** | $RW-$ or $RWX$ (Modifiable constants) | **$R--$ (Hardware MMU enforced read-only)** |
| **`__ro_after_init` Protection** | Writable post-initialization | **Permanently frozen as $R--$ after boot** |
| **Rootkit In-Memory Code Patching** | **Permitted (Syscall hooks feasible)** | **Blocked (Immediate MMU Page Fault `#PF`)** |
| **W^X Invariant ($W \cap X = \emptyset$)** | Violated ($W \cap X \ne \emptyset$) | **Strictly preserved ($W \cap X = \emptyset$)** |
| **Runtime CPU Overhead** | Baseline | **0% (Hardware MMU paging enforced)** |

---

## 5. Trade-offs & Recommendations

### 5.1 Performance and Engineering Considerations
- **TLB Huge Page Splitting**:
  - Large 2MB/1GB pages maximize TLB efficiency, but section boundaries (`.text`, `.rodata`, `.data`) require 4KB splitting.
  - The impact is negligible (<1%) on modern processors and vastly outweighed by the security guarantees.
- **Ftrace / kprobes Dynamic Code Patching**:
  - Dynamic tracing features safely patch code by temporarily modifying page permissions (`text_poke()`) under controlled CPU barriers before restoring $R-X$.

### 5.2 Deployment Recommendations
- Always enable `CONFIG_STRICT_KERNEL_RWX=y` and `CONFIG_STRICT_MODULE_RWX=y` on production systems.
- Never set `rodata=off` in production kernel boot parameters.

---

## 6. Appendix

### 6.1 Technical Presentation Script

> "Good morning, everyone. Today we delve into one of the most foundational security invariants of modern operating systems: W-XOR-X, implemented in the Linux kernel via CONFIG_STRICT_KERNEL_RWX and CONFIG_STRICT_MODULE_RWX.
>
> Historically, operating system kernels mapped their entire virtual memory space with combined read, write, and execute permissions. Under this permissive model, any single arbitrary-write vulnerability allowed attackers or rootkits to overwrite kernel opcodes directly in .text, hijack the system call table, or tamper with security function pointers.
>
> CONFIG_STRICT_KERNEL_RWX enforces the invariant that memory must never be simultaneously writable and executable. Code sections are mapped strictly as Read and Execute (R-X), constant data as Read-Only (R--), and post-initialization structures marked with __ro_after_init are permanently frozen after boot.
>
> In our dual-architecture lab, we demonstrated this mechanism using a custom driver and unprivileged exploit. Under a disabled baseline, memory writes succeed silently, opening the door to rootkits. Under our hardened configuration, the hardware MMU triggers immediate write-protection faults, protecting the kernel's integrity with virtually zero runtime performance cost."

### 6.2 Glossary

- **W^X (Write XOR Execute)**: A security design principle dictating that memory may be writable or executable, but never both simultaneously ($W \cap X = \emptyset$).
- **CONFIG_STRICT_KERNEL_RWX**: Kernel configuration enabling strict page permissions for core kernel `.text` and `.rodata`.
- **CONFIG_STRICT_MODULE_RWX**: Kernel configuration enforcing W^X on dynamically loaded kernel modules.
- **CR0.WP (Write Protect Bit)**: Bit 16 of x86 CR0 control register preventing Ring 0 supervisor code from writing to read-only pages.
- **`__ro_after_init`**: Section attribute for variables writable during kernel init but marked permanently read-only upon boot completion.
- **`copy_to_kernel_nofault()`**: Kernel safe memory copy utility that handles page faults cleanly via exception tables without kernel panic.

