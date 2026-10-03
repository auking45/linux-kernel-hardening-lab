# Strict Devmem & Strict I/O Devmem

## 1. Overview & Threat Model

**Strict Devmem (`CONFIG_STRICT_DEVMEM`) and Strict I/O Devmem (`CONFIG_IO_STRICT_DEVMEM`)** are kernel physical memory access restriction mechanisms that **prevent even privileged users (root / UID 0 / `CAP_SYS_RAWIO`) from mapping or directly modifying physical System RAM and active device I/O memory via the `/dev/mem` character device**.

In traditional Unix systems, `/dev/mem` provided direct byte-level access to the full physical address space, primarily used by legacy X11 servers to control VGA framebuffers and BIOS ROMs. However, in modern threat landscapes, unrestricted `/dev/mem` represents a catastrophic Ring 0 bypass vector:

1. **Ring 0 Compromise via Direct Physical Memory Tampering**:
   - Once an attacker gains root privileges in userspace, they can `mmap()` `/dev/mem` to overwrite running kernel code (`.text`), syscall dispatch tables, or the `task_struct->cred` structure (UID/GID fields) directly in physical RAM, establishing permanent Ring 0 backdoors.
2. **Physical Exfiltration of Secrets and Encryption Keys**:
   - Root can directly dump master full-disk encryption keys (LUKS), kernel entropy pools, and sensitive application memory by reading physical RAM addresses.
3. **Hardware DMA Controller Hijacking**:
   - Attackers can write to the memory-mapped I/O (MMIO) registers of active network cards (NICs) or NVMe controllers, initiating malicious Direct Memory Access (DMA) transfers to corrupt arbitrary kernel buffers.
4. **Two-Tiered Strict Devmem Protection**:
   - `CONFIG_STRICT_DEVMEM=y`: Blocks all access to physical System RAM (`devmem_is_allowed(pfn) == 0`).
   - `CONFIG_IO_STRICT_DEVMEM=y`: Blocks access to MMIO regions actively claimed by kernel drivers (`devmem_is_unconsumed(pfn) == 0`).

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/strict-devmem/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Physical Circuit Firewall in a Bank Data Center

The defense mechanism of Strict Devmem mirrors **physical circuit isolation in a central bank data vault**:

```
[ Disabled Mode (Permissive: CONFIG_STRICT_DEVMEM=n) ]
  Intruder (Root): "Because I hold administrator credentials, I will directly solder wires
                    into the motherboard RAM bus (/dev/mem) and copy memory chips directly!"
  Security:        "Granted. You hold top-tier credentials." (Extreme memory corruption hazard)

[ Strict Devmem Active (CONFIG_STRICT_DEVMEM=y) ]
  Intruder (Root): "Attempting to map physical memory belonging to System RAM (kernel code/data)!"
  Interlock:       "devmem_is_allowed(pfn) triggered! Target physical page frame belongs to System RAM!"
  Action:          "Access blocked immediately (-EPERM)! Physical RAM is completely isolated!"

[ Strict I/O Devmem Active (CONFIG_IO_STRICT_DEVMEM=y) ]
  Intruder (Root): "Attempting to map DMA control registers of an active NVMe storage controller!"
  Interlock:       "devmem_is_unconsumed(pfn) triggered! Hardware resource is actively claimed by driver!"
  Action:          "Access blocked (-EPERM)! Hardware DMA hijacking completely thwarted!"
```

---

### 3. Kernel Verification Algorithms

#### 1) `devmem_is_allowed(unsigned long pfn)`
- When userspace issues `open()`, `mmap()`, `read()`, or `write()` against `/dev/mem`, architecture-specific logic verifies the Page Frame Number (PFN).
- If the target PFN belongs to `System RAM` managed by the kernel page allocator, the check returns `0`, terminating the syscall with `-EPERM`.
- Only unallocated legacy regions outside System RAM (such as BIOS ROM or legacy VGA text buffers at `0xa0000`) remain accessible.

#### 2) `devmem_is_unconsumed(unsigned long pfn)`
- Enforced when `CONFIG_IO_STRICT_DEVMEM=y` is configured.
- Checks whether the target PFN is registered in the kernel's resource tree (`/proc/iomem`) and has been claimed by a kernel driver via `request_mem_region()` or `devm_ioremap_resource()`. If claimed, access returns `0` and is rejected.

---

## 3. Configuration & Interfaces

### 1. Kconfig Fragment

```ini
# configs/features/strict-devmem.config
CONFIG_DEVMEM=y
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y
```

### 2. Interfaces & Control Files

| Interface / File | Type | Description |
| :--- | :--- | :--- |
| `/dev/mem` | Character Device (1:1) | Physical memory character device filtered by `STRICT_DEVMEM` |
| `/proc/iomem` | R-only | System physical address map showing `System RAM`, PCI buses, and driver MMIO ranges |
| `devmem=relaxed` | Kernel cmdline | Boot parameter to temporarily relax `STRICT_DEVMEM` for debugging purposes |

---

## 4. Hands-on Verification & Exploit PoC

### 1. Test Scenario Overview

- Execute tests with root privileges:
  - **Phase 1: Baseline (Permissive Mode)**:
    - Physical System RAM, driver MMIO, and legacy ROM are all accessible.
  - **Phase 2: Mode 1 (Strict RAM - CONFIG_STRICT_DEVMEM=y)**:
    - Physical System RAM access is blocked with `-EPERM`.
    - Driver MMIO and legacy ROM access remain permitted.
  - **Phase 3: Mode 2 (Strict RAM + I/O - CONFIG_IO_STRICT_DEVMEM=y)**:
    - Physical System RAM access is blocked (`-EPERM`).
    - Driver-claimed MMIO access is blocked (`-EPERM`).
    - Unclaimed legacy ROM access is permitted.
  - **Phase 4: Direct /dev/mem Interface Probe**:
    - Programmatically parses `/proc/iomem` for System RAM base and attempts `mmap(/dev/mem)`, verifying kernel rejection with `errno == EPERM`.

### 2. Dual-Architecture Execution Logs

=== "ARM64: Strict Devmem Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-devmem/arch/arm64/boot/Image --test test_strict_devmem
    ```
    ```
    ================================================================
       Lab 37: Strict Devmem & Strict I/O Devmem Verification Suite 
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting /dev/mem device node and /proc/iomem...
    crw-r-----    1 root     kmem        1,   1 Jan  1 00:00 /dev/mem
        System physical memory map preview (/proc/iomem):
        40000000-7fffffff : System RAM
          40080000-413effff : Kernel code
          41570000-41abffff : Kernel data
    [*] Step 2: Checking target driver at /proc/vuln_strict_devmem...
    [+] Target driver detected.

    [*] Step 4: Running Strict Devmem PoC...
    ================================================================
      Strict Devmem & Strict I/O Devmem Verification PoC            
      UID: 0, GID: 0                                                
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
            Linux Strict Devmem Status Report               
    ========================================================
    Strict Devmem Mode      : [2] Strict RAM + Active I/O (2: System RAM & Driver I/O protected)
    System RAM Defense      : ENFORCED (CONFIG_STRICT_DEVMEM=y) (devmem_is_allowed)
    Active I/O Protection   : ENFORCED (CONFIG_IO_STRICT_DEVMEM=y) (devmem_is_unconsumed)
    Total Access Probes     : 0
    Access Requests Granted : 0
    System RAM Denials      : 0 (-EPERM)
    Active I/O Denials      : 0 (-EPERM)
    ========================================================

    [*] PHASE 1: Evaluating Baseline (Mode: Permissive - 0)
        -> Accessing physical System RAM... (GRANTED)
        -> Accessing active driver I/O memory... (GRANTED)
        -> Accessing legacy unclaimed ROM/VGA... (GRANTED)

    [*] PHASE 2: Evaluating Mode 1 (Strict RAM)
        -> Accessing physical System RAM (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Accessing active driver I/O memory (expecting GRANTED)... (GRANTED)
        -> Accessing legacy unclaimed ROM/VGA (expecting GRANTED)... (GRANTED)

    [*] PHASE 3: Evaluating Mode 2 (Strict RAM + I/O)
        -> Accessing physical System RAM (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Accessing active driver I/O memory (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Accessing legacy unclaimed ROM/VGA (expecting GRANTED)... (GRANTED)

    [*] Testing direct /dev/mem mmap() on System RAM (Phys: 0x40000000)...
        [+] SUCCESS: mmap(/dev/mem) to System RAM blocked by kernel: Operation not permitted (errno=1)
            -> CONFIG_STRICT_DEVMEM successfully defended kernel memory!

    [+] Strict Devmem Verification Complete: Physical Memory Protections Proven!

    [*] Step 5: Inspecting kernel dmesg for Strict Devmem events:
    [    4.210450] strict_devmem: [DENIED] Attempted /dev/mem access to System RAM (pfn > 0x100) rejected: -EPERM
    [    4.210480] System RAM protection active: devmem_is_allowed() returned 0!
    [    4.211902] strict_devmem: [DENIED] Attempted /dev/mem access to driver-claimed I/O memory rejected: -EPERM
    [    4.211930] Active I/O memory protection active: devmem_is_unconsumed() returned 0!
    ================================================================
       Lab 37 Test Complete: Verified Strict Devmem Protections     
    ================================================================
    ```

=== "x86_64: Strict Devmem Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-devmem/arch/x86/boot/bzImage --test test_strict_devmem
    ```
    ```
    ================================================================
       Lab 37: Strict Devmem & Strict I/O Devmem Verification Suite 
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting /dev/mem device node and /proc/iomem...
    crw-r-----    1 root     kmem        1,   1 Jan  1 00:00 /dev/mem
        System physical memory map preview (/proc/iomem):
        00001000-0009fbff : System RAM
        00100000-3ffdffff : System RAM
          01000000-01c01fff : Kernel code
          01c02000-023fffff : Kernel data
    [*] Step 2: Checking target driver at /proc/vuln_strict_devmem...
    [+] Target driver detected.

    [*] Step 4: Running Strict Devmem PoC...
    ================================================================
      Strict Devmem & Strict I/O Devmem Verification PoC            
      UID: 0, GID: 0                                                
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode: Permissive - 0)
        -> Accessing physical System RAM... (GRANTED)
        -> Accessing active driver I/O memory... (GRANTED)
        -> Accessing legacy unclaimed ROM/VGA... (GRANTED)

    [*] PHASE 2: Evaluating Mode 1 (Strict RAM)
        -> Accessing physical System RAM (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Accessing active driver I/O memory (expecting GRANTED)... (GRANTED)
        -> Accessing legacy unclaimed ROM/VGA (expecting GRANTED)... (GRANTED)

    [*] PHASE 3: Evaluating Mode 2 (Strict RAM + I/O)
        -> Accessing physical System RAM (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Accessing active driver I/O memory (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Accessing legacy unclaimed ROM/VGA (expecting GRANTED)... (GRANTED)

    [*] Testing direct /dev/mem mmap() on System RAM (Phys: 0x100000)...
        [+] SUCCESS: mmap(/dev/mem) to System RAM blocked by kernel: Operation not permitted (errno=1)
            -> CONFIG_STRICT_DEVMEM successfully defended kernel memory!

    [+] Strict Devmem Verification Complete: Physical Memory Protections Proven!

    [*] Step 5: Inspecting kernel dmesg for Strict Devmem events:
    [    8.110290] strict_devmem: [DENIED] Attempted /dev/mem access to System RAM (pfn > 0x100) rejected: -EPERM
    [    8.110320] System RAM protection active: devmem_is_allowed() returned 0!
    [    8.111812] strict_devmem: [DENIED] Attempted /dev/mem access to driver-claimed I/O memory rejected: -EPERM
    [    8.111840] Active I/O memory protection active: devmem_is_unconsumed() returned 0!
    ================================================================
       Lab 37 Test Complete: Verified Strict Devmem Protections     
    ================================================================
    ```

---

## 5. Performance & Compatibility

1. **Zero Runtime Overhead**:
   - Physical address filtering is evaluated exclusively during `/dev/mem` access calls (`mmap`, `read`, `write`), having 0% impact on normal application runtime performance.
2. **Modern KMS / DRM Display Compatibility**:
   - Modern Linux graphics rely on Kernel Mode Setting (KMS) and Direct Rendering Manager (DRM) drivers rather than userland `/dev/mem` mapping, ensuring zero display regressions.
3. **Diagnostic Considerations**:
   - Low-level physical memory dump tools (`busybox devmem`) will fail to read physical RAM. Developers debugging bare-metal platforms can temporarily supply `devmem=relaxed` on the kernel command line.

---

## 6. Lecture & Presentation Script

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In early Unix architecture, the `/dev/mem` character device was considered a standard feature, allowing direct byte-level mapping of physical address space. However, in modern threat landscapes, unrestricted `/dev/mem` completely obliterates the distinction between user space and kernel space. Even if virtual memory protections like W^X or SMAP are in place, a privileged root user or compromised service can simply open `/dev/mem` and overwrite running kernel text or credentials directly in physical RAM. Today, we investigate **Strict Devmem and Strict I/O Devmem**."

#### 2. Diagram & Architecture Walkthrough
> "Please direct your attention to the interactive architecture simulator on the screen. Notice the physical address classification. When an application attempts to map an address via `/dev/mem`, the kernel invokes two defensive checks. First, `devmem_is_allowed(pfn)` verifies whether the requested page resides within physical `System RAM`. Under `CONFIG_STRICT_DEVMEM=y`, all RAM pages are unconditionally rejected with an `-EPERM` error. Second, `devmem_is_unconsumed(pfn)` checks whether the target MMIO range is actively claimed by a hardware driver. Under `CONFIG_IO_STRICT_DEVMEM=y`, active device registers and DMA control spaces are also isolated, leaving only harmless unclaimed legacy ROMs accessible."

#### 3. Live Demo Commentary
> "In our live demonstration on ARM64 and x86_64, look at the contrast between modes. In Permissive mode, arbitrary physical RAM addresses can be mapped directly into userspace. However, when we evaluate Hardened mode, any attempt to access physical System RAM—such as address `0x40000000` on ARM64 or `0x100000` on x86_64—is immediately intercepted, returning `-EPERM`. Furthermore, our raw syscall probe confirms that `mmap(/dev/mem)` fails with 'Operation not permitted'. The kernel text, creds, and page tables remain completely impenetrable."

#### 4. Key Takeaways & Production Advice
> "To conclude: Enabling `CONFIG_STRICT_DEVMEM=y` and `CONFIG_IO_STRICT_DEVMEM=y` is an indispensable requirement for enterprise systems and cloud hypervisors. It seals off physical backdoors, ensuring that root privileges in userland cannot be translated into Ring 0 kernel compromise through physical memory tampering."
