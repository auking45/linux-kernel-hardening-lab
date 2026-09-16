# CONFIG_PAGE_TABLE_CHECK: Runtime Page Table Integrity Verification & Invalid Mapping Detection

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/page-table-check/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="CONFIG_PAGE_TABLE_CHECK Architecture Diagram"></iframe>
</div>

---

## 1. Overview & Threat Model

### 1.1 Targeted Threat: Illegal Double Mapping & Delayed Memory Corruption

- **Limitations of Traditional Linux MM & Delayed Fault Detection**:
  - The Linux virtual memory subsystem prioritizes fast-path allocation throughput, avoiding heavy validation when updating page table entries (PTE, PMD, PUD).
  - Due to kernel race conditions, buggy driver remappings (`remap_pfn_range()`), or Use-After-Free (UAF) page reallocation bugs:
    1. The exact same physical memory frame (PFN) could be mapped twice with Read/Write permissions across two distinct processes (**Illegal Double Mapping**).
    2. Anonymous memory (process heap/stack) and Named/File-backed pages could erroneously share the same physical frame (**Type Confusion & Aliasing**).
  - These memory corruptions typically go undetected at mapping time, surfacing only much later during data corruption or delayed kernel panics, making root-cause analysis difficult and enabling complex exploits.
- **Core Defense Philosophy of `CONFIG_PAGE_TABLE_CHECK`**:
  - Validates ownership and mapping attributes **synchronously** at the exact moment an entry is added to or removed from user page tables.
  - Immediately crashes the kernel (`BUG_ON()`) upon detecting illegal writable double-mappings, anonymous/file overlap, or dangling mappings on page freeing, stopping memory corruption before it spreads.

### 1.2 Intuitive Real-World Analogy: The Land Registry vs Double-Selling Prevention Metaphor

- **Analogy Description**:
  - A physical memory page is a **specific parcel of land**, a Page Table Entry (PTE) is an **official land deed registry entry**, and a process virtual address is the **buyer's title certificate**.
  - **Before Hardening (`page_table_check=off`)**:
    - Overworked clerks at the land registry stamp title deeds without verifying if that specific plot has already been deeded exclusively to another party with full development rights (Read/Write).
    - A fraudulent developer (attacker) can sell the same parcel to multiple parties (double mapping). The crime remains invisible until multiple buyers attempt construction on the same plot, causing delayed chaos.
  - **With Hardening Enforced (`page_table_check=on`)**:
    - Every plot of land is tagged with an automated real-time tracking barcode (`struct page_table_check` atomic counters).
    - When a new deed registration is attempted, the system scans the barcode instantly. If the plot is already designated for exclusive private ownership, an alarm sounds and registry operations are halted (`BUG_ON()`), blocking double-selling before construction begins.

---

## 2. Kernel Internal Architecture

### 2.1 Page Extension Infrastructure (`PAGE_EXTENSION`)

- **`struct page_table_check` Metadata Structure**:
  - Implemented in `mm/page_table_check.c` and allocated inside `page_ext` per physical page (`struct page`):
    ```c
    /* mm/page_table_check.c */
    struct page_table_check {
        atomic_t anon_map_count;  /* Reference count for anonymous mappings */
        atomic_t file_map_count;  /* Reference count for file-backed mappings */
    };
    ```
- **Static Branch Jump Label (`page_table_check_disabled`)**:
  - Controlled via `page_table_check=on` or `CONFIG_PAGE_TABLE_CHECK_ENFORCED=y`. When active, `static_branch_disable(&page_table_check_disabled)` arms the verification hooks with zero branch penalty:
    ```c
    DEFINE_STATIC_KEY_TRUE(page_table_check_disabled);
    EXPORT_SYMBOL(page_table_check_disabled);
    ```

### 2.2 Synchronous Validation Rules

- **Entry Insertion (`page_table_check_set`)**:
  ```c
  /* mm/page_table_check.c */
  static void page_table_check_set(unsigned long pfn, unsigned long pgcnt, bool rw)
  {
      ...
      anon = PageAnon(page);
      for (i = 0; i < pgcnt; i++) {
          struct page_table_check *ptc = get_page_table_check(page_ext);
          if (anon) {
              /* Anonymous pages must never have active file mapping counts */
              BUG_ON(atomic_read(&ptc->file_map_count));
              /* Anonymous pages cannot be mapped as writable by more than one entity */
              BUG_ON(atomic_inc_return(&ptc->anon_map_count) > 1 && rw);
          } else {
              /* File pages must never have active anonymous counts */
              BUG_ON(atomic_read(&ptc->anon_map_count));
              BUG_ON(atomic_inc_return(&ptc->file_map_count) < 0);
          }
      }
  }
  ```
- **Entry Clearing (`page_table_check_clear`)**:
  - Decrements the appropriate counter and triggers `BUG_ON()` if counters become negative or mismatch page type.
- **Page Free Verification (`page_table_check_free`)**:
  - Invoked from `free_pages_prepare()` to assert that both `anon_map_count` and `file_map_count` are zero, catching Use-After-Free dangling mappings immediately upon deallocation.

---

## 3. Hands-on Lab Implementation

### 3.1 Vulnerable Target Driver (`vuln_page_table_check.c`)

- Exposed via `/proc/vuln_page_table_check` (mode 0666):
  - **Kernel Telemetry**:
    - `ARCHITECTURE`: `x86_64` or `arm64 (aarch64)`
    - `CONFIG_PAGE_TABLE_CHECK`: `ENABLED (y)`
    - `STATIC_KEY_STATE`: State of `page_table_check_disabled`
    - `PROTECTION_STATUS`: `ENABLED (Hardened)` vs `DISABLED (page_table_check=off)`
    - Mapping rules matrix (Anonymous RW restriction, Anonymous/File separation).
  - **Probe Handler**:
    - Accepts user virtual addresses and validates static key and verification hook enforcement.

### 3.2 Memory Mapping Verification Exploit PoC (`exploit.c`)

- Executed by unprivileged user `lab` (UID 1000):
  - Creates an anonymous private mapping via `mmap()` and writes magic data (`0x5041474554424C45ULL`, "PAGETBLE").
  - Interacts with `/proc/vuln_page_table_check` to probe page table check activation.
  - Evaluates telemetry to verify active page table monitoring.

### 3.3 In-Guest Verification Runner (`test.sh`)

- Automated test runner `/bin/test_page_table_check`:
  - Test 1: Kernel command-line parameters (`page_table_check=on` vs `page_table_check=off`).
  - Test 2: `/proc/vuln_page_table_check` telemetry inspection.
  - Test 3: Unprivileged execution of `/bin/exploit_page_table_check`.
  - Test 4: `dmesg` security log verification.

---

## 4. Verification Results & Analysis

### 4.1 x86_64 Live Telemetry (Base vs Hardened)

#### [Base] x86_64 Page Table Check Disabled (`page_table_check=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
Page Table Check Status: DISABLED (page_table_check=off active)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             x86_64
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_ENABLED (Checks Bypassed)
PROTECTION_STATUS:        DISABLED (page_table_check=off active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: x86_64
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            x86_64
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_ENABLED (Checks Bypassed)
    Enforcement State:       DISABLED (page_table_check=off active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0x7ff0b480f000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x00007ff0b480f000
    Probe Result:            UNPROTECTED (Page Table Check Inactive / Bypassed)

[!] =========================================================
[!] BASELINE CONFIRMED (CONFIG_PAGE_TABLE_CHECK Disabled):
[!] Page table verification hooks are bypassed (page_table_check=off).
[!] Kernel does not synchronously detect double-mappings or page leaks.
[!] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
[    0.118447] Kernel command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
[    0.120208] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    1.594553] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 0)
[    2.432137]     lab_test=test_page_table_check
[    3.276630] [vuln_page_table_check] Received probe request for user address 0x7ff0b480f000
[    3.276770] [vuln_page_table_check] [!] WARNING: Page Table Check is disabled (page_table_check=off)!
[    3.276839] [vuln_page_table_check] [!] Page table verification hooks bypassed. Memory corruption detection inactive.
```

#### [Hardened] x86_64 Page Table Check Enabled (`page_table_check=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
Page Table Check Status: ACTIVE (page_table_check=on enforced)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             x86_64
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_DISABLED (Checks Armed)
PROTECTION_STATUS:        ENABLED (Hardened - Synchronous verification active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: x86_64
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            x86_64
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_DISABLED (Checks Armed)
    Enforcement State:       ENABLED (Hardened - Synchronous verification active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0x7efc25f8a000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x00007efc25f8a000
    Probe Result:            PROTECTED (Page Table Integrity Enforced by Core MM)

[+] =========================================================
[+] HARDENING VERIFIED (CONFIG_PAGE_TABLE_CHECK Active):
[+] Kernel is actively monitoring PTE/PMD/PUD page tables!
[+] Illegal double-mappings (Anon RW > 1) & file aliasing are prohibited.
[+] UAF lingering mappings during page free will trigger immediate crash.
[+] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
[    0.127950] Kernel command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
[    0.129710] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    0.162573] allocated 2097152 bytes of page_ext
[    1.605843] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 1)
[    2.377685]     lab_test=test_page_table_check
[    3.221274] [vuln_page_table_check] Received probe request for user address 0x7efc25f8a000
[    3.223529] [vuln_page_table_check] [+] DEFENSE ACTIVE: CONFIG_PAGE_TABLE_CHECK is actively enforcing page table integrity!
[    3.223630] [vuln_page_table_check] [+] Synchronous double-map prevention & anonymous/file separation verified.
```

---

### 4.2 ARM64 Live Telemetry (Base vs Hardened)

#### [Base] ARM64 Page Table Check Disabled (`page_table_check=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
Page Table Check Status: DISABLED (page_table_check=off active)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             arm64 (aarch64)
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_ENABLED (Checks Bypassed)
PROTECTION_STATUS:        DISABLED (page_table_check=off active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: arm64 (aarch64)
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            arm64 (aarch64)
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_ENABLED (Checks Bypassed)
    Enforcement State:       DISABLED (page_table_check=off active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0xffffb6c4e000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x0000ffffb6c4e000
    Probe Result:            UNPROTECTED (Page Table Check Inactive / Bypassed)

[!] =========================================================
[!] BASELINE CONFIRMED (CONFIG_PAGE_TABLE_CHECK Disabled):
[!] Page table verification hooks are bypassed (page_table_check=off).
[!] Kernel does not synchronously detect double-mappings or page leaks.
[!] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Kernel command line: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
[    0.000000] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    0.721444] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 0)
[    0.861172]     lab_test=test_page_table_check
[    1.419653] [vuln_page_table_check] Received probe request for user address 0xffffb6c4e000
[    1.419858] [vuln_page_table_check] [!] WARNING: Page Table Check is disabled (page_table_check=off)!
[    1.419890] [vuln_page_table_check] [!] Page table verification hooks bypassed. Memory corruption detection inactive.
```

#### [Hardened] ARM64 Page Table Check Enabled (`page_table_check=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
Page Table Check Status: ACTIVE (page_table_check=on enforced)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             arm64 (aarch64)
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_DISABLED (Checks Armed)
PROTECTION_STATUS:        ENABLED (Hardened - Synchronous verification active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: arm64 (aarch64)
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            arm64 (aarch64)
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_DISABLED (Checks Armed)
    Enforcement State:       ENABLED (Hardened - Synchronous verification active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0xffffb16d2000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x0000ffffb16d2000
    Probe Result:            PROTECTED (Page Table Integrity Enforced by Core MM)

[+] =========================================================
[+] HARDENING VERIFIED (CONFIG_PAGE_TABLE_CHECK Active):
[+] Kernel is actively monitoring PTE/PMD/PUD page tables!
[+] Illegal double-mappings (Anon RW > 1) & file aliasing are prohibited.
[+] UAF lingering mappings during page free will trigger immediate crash.
[+] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Kernel command line: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
[    0.000000] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    0.000000] allocated 2097152 bytes of page_ext
[    1.264390] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 1)
[    1.475725]     lab_test=test_page_table_check
[    2.327193] [vuln_page_table_check] Received probe request for user address 0xffffb16d2000
[    2.327322] [vuln_page_table_check] [+] DEFENSE ACTIVE: CONFIG_PAGE_TABLE_CHECK is actively enforcing page table integrity!
[    2.327349] [vuln_page_table_check] [+] Synchronous double-map prevention & anonymous/file separation verified.
```

---

### 4.3 Security Mapping Rules & Engineering Matrix

| Dimension / Check Rule | Baseline (`page_table_check=off`) | Hardened (`page_table_check=on`) | Security & Architectural Impact |
| :--- | :--- | :--- | :--- |
| **Static Key (`page_table_check_disabled`)** | Enabled (`true`, checks bypassed) | Disabled (`false`, checks armed) | Zero-overhead branch switching via Jump Labels |
| **Anonymous Double-Map (Anon RW > 1)** | **Permitted (Delayed corruption)** | **Trapped (`BUG_ON()` crash)** | Eliminates aliased UAF memory hijacking |
| **Anonymous / File Type Confusion** | **Permitted (Cache corruption)** | **Trapped (`BUG_ON()` crash)** | Enforces strict page structure invariants |
| **Lingering Mappings on Page Free** | Unchecked | Verified via `page_table_check_free()` | Detects dangling PTEs pointing to freed pages |
| **Memory Tracking Structure** | Not tracked | Tracked via `page_ext` atomics | Full physical page ownership accounting |

---

## 5. Global Technical Presentation Script

```text
"Hello everyone, and welcome to this deep-dive into Linux kernel memory integrity. Today, we focus on CONFIG_PAGE_TABLE_CHECK—a vital synchronous hardening feature introduced in modern kernels to prevent illegal page table corruption.

Traditionally, the memory management subsystem defers validation of page mappings to preserve throughput. Unfortunately, kernel race conditions, faulty driver remappings, or Use-After-Free bugs can lead to silent corruption, where the exact same physical memory frame is mapped as writable into two separate address spaces. By the time this double mapping causes an application crash or privilege escalation, the root cause is long gone.

CONFIG_PAGE_TABLE_CHECK completely transforms this paradigm by verifying page table entries synchronously at the exact moment they are added or removed from user page tables. By maintaining atomic tracking counters inside struct page_ext, the kernel guarantees strict invariant rules: anonymous pages can never be mapped writable more than once, and anonymous pages can never alias with named file pages.

If an illegal mapping is attempted, the kernel crashes immediately with BUG_ON(), pinning the corruption to the exact violating code path before any user data is poisoned.

In our lab, we demonstrated how the static key seamlessly arms or bypasses these checks across x86_64 and ARM64, providing robust runtime defense against complex heap and page table exploitation. Thank you."
```

---

## 6. Terminology & Architectural Reference

- **`CONFIG_PAGE_TABLE_CHECK`**:
  - A runtime memory integrity feature introduced in Linux 5.17+ that synchronously checks page table entries (PTE, PMD, PUD) for illegal double-mappings and invalid page sharing.
- **`PAGE_EXTENSION` (`page_ext`)**:
  - A core kernel memory infrastructure that attaches extra debugging and security metadata structures to each physical page frame (`struct page`).
- **Anonymous Page**:
  - Memory allocated dynamically by user processes for heap, stack, or anonymous mappings, backed purely by RAM or swap rather than disk files.
- **Named / File-backed Page**:
  - Memory pages backed by regular filesystem files or block devices, managed via the Linux page cache.
- **Double Mapping**:
  - A condition where a single physical memory frame is mapped to more than one virtual address space simultaneously. When multiple mappings possess write permissions, severe concurrency and privilege issues emerge.
- **`CONFIG_EXCLUSIVE_SYSTEM_RAM`**:
  - A prerequisite Kconfig option ensuring that `/dev/mem` cannot map system RAM directly into user space, guaranteeing page table check metadata consistency.
- **`static_branch_likely()` / `static_key_true`**:
  - Jump label infrastructure in the Linux kernel enabling code modification (NOP/JMP patching) to toggle features at runtime without CPU branch prediction penalties.

