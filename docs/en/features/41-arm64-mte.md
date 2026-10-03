# ARM64 Memory Tagging Extension (MTE)

## 1. Overview & Threat Model

**ARM64 MTE (`CONFIG_ARM64_MTE`, ARMv8.5-A+)** is a groundbreaking hardware-based security extension that associates **4-bit cryptographic/logical color tags (0x0 to 0xF) with each 16-byte physical memory granule and pointer, performing single-cycle hardware checks on every load/store to permanently neutralize spatial and temporal memory corruption vulnerabilities**.

According to industry vulnerability statistics published by Microsoft, Google, and Chromium Security, approximately 70% of all severe zero-day security vulnerabilities in modern operating systems and browsers stem from C/C++ memory safety violations:

1. **Temporal Safety Violations (Use-After-Free, UAF)**:
   - An application retains a pointer to a heap allocation after it has been returned to the allocator via `free()`.
   - Attackers leverage dangling pointers combined with Heap Spraying to overwrite hijacked memory chunks, replace virtual method tables (`vtable`), and achieve arbitrary code execution.
2. **Spatial Safety Violations (Buffer Overflows & Out-Of-Bounds, OOB)**:
   - Read or write accesses extend past the allocated boundaries of an array or buffer, corrupting neighboring heap chunks, metadata headers, or function pointers.
3. **Hardware-Enforced Zero-Overhead Defense**:
   - Traditional software sanitizers (AddressSanitizer, KASAN) inflict over 100-200% CPU overhead and consume prohibitive memory, making them impractical for production environments.
   - ARM64 MTE stores 4-bit tags directly in dedicated hardware storage (1 tag byte per 32 bytes of physical RAM) and leverages Top-Byte-Ignore (TBI) in bits [59:56] of 64-bit pointers. Memory comparisons occur in silicon at instruction execution speed, imposing less than 1-2% performance overhead.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/arm64-mte/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Smart Hotel Color-Matched Electronic Lock

ARM64 MTE behaves identically to a **high-tech smart hotel's color-coded electronic door card system**:

```
[ Unprotected Legacy State ]
  Intruder:  "I brought an expired room key (Dangling Pointer) with the old room number printed on it!"
  Door Lock: "As long as the room number exists, enter freely!" (Use-After-Free Burglary Occurs)

[ MTE Enabled (Valid Access: Logical Tag == Allocation Tag) ]
  Guest:     "Tapping my authorized purple card (Tag 0xA) on Room Door #10!"
  Sensor:    "Comparing guest card color (0xA) against the door's active electronic color (0xA)!"
  Outcome:   "0xA == 0xA match! Door unlocks instantly with zero latency (Load/Store succeeds)."

[ MTE UAF Defense: Memory Re-Coloring upon Free ]
  Intruder:  "The guest checked out, but I kept a cloned purple card (Tag 0xA) to sneak in later!"
  Hotel:     "The moment the guest checked out (free()), the room lock color automatically randomized to orange (0x3)!"
  Sensor:    "Comparing: Keycard (0xA) != Door Lock (0x3)! Tag mismatch detected!"
  Action:    "Immediate intrusion alarm triggered! (Hardware trap, synchronous SIGSEGV / SEGV_MTESERR, process terminated)!"

[ MTE OOB Defense: Boundary Color Divergence ]
  Intruder:  "Climbing out the window of Room #10 (Tag 0xA) into neighboring Room #11 (Tag 0x7)!"
  Boundary:  "Crossing the 16-byte granule threshold encounters color 0x7! 0xA != 0x7 instantly electrocutes intruder!"
```

---

### 3. MTE Fault Trap Modes Matrix

| Trap Mode | Control Constant (`prctl`) | Hardware Execution Semantics | CPU Overhead | Primary Use Case & Deployment |
| :--- | :--- | :--- | :--- | :--- |
| **Synchronous** | `PR_MTE_TCF_SYNC` | Halts CPU pipeline immediately on tag mismatch; delivers precise `SIGSEGV` with `SEGV_MTESERR` and exact faulting `si_addr` | ~2% | Security auditing, fuzzing, immediate exploit containment |
| **Asynchronous** | `PR_MTE_TCF_ASYNC` | Non-blocking; logs tag mismatches into `TFSR_EL1` accumulator register; delivers deferred `SEGV_MTEAERR` at context switch | < 0.5% | Mobile production (Android), IoT devices, battery-critical telemetry |
| **Asymmetric** | `PR_MTE_TCF_ASYMM` | Synchronous immediate traps for Read operations; asynchronous deferred traps for Write operations | ~1% | Recommended hybrid mode for modern Android 13+ production apps |

---

## 3. Kernel Configurations & Developer Interfaces

### 1. Hardening Kconfig (`configs/features/mte.config`)

```ini
# Linux Kernel Hardening Lab - ARM64 MTE Feature Config
CONFIG_ARM64_MTE=y
CONFIG_ARM64_TAGGED_ADDR_ABI=y
```

- `CONFIG_ARM64_MTE=y`: Activates architectural MTE subsystem support, userland MTE control, and kernel Hardware Tag-Based KASAN (`CONFIG_KASAN_HW_TAGS`).
- `CONFIG_ARM64_TAGGED_ADDR_ABI=y`: Ensures that user pointers passed across syscall boundaries retain their top-byte tags without confusing kernel address translation.

### 2. Userland Activation Workflow

```c
#include <sys/prctl.h>
#include <sys/mman.h>

/* 1. Enable synchronous MTE and tag exclusion mask */
prctl(PR_SET_TAGGED_ADDR_CTRL,
      PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | (0xfffe << PR_MTE_TAG_SHIFT),
      0, 0, 0);

/* 2. Map memory pages with hardware tagging enabled */
void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_MTE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

---

## 4. Hands-on Lab: `labs/41-arm64-mte`

### 1. Lab Components

1. **Target Driver (`labs/41-arm64-mte/vuln_mte.c`)**:
   - Models 16-byte memory granules, 4-bit hardware allocation tags, and Top-Byte-Ignore (TBI) pointer verification.
   - Registered at `/proc/vuln_mte` (0666):
     - `alloc <slot> <size> [tag]`: Allocates a memory slot with a specific 4-bit tag.
     - `access <slot> <offset> <tag>`: Simulates pointer dereferencing with logical tag validation.
     - `free <slot>`: Frees slot and re-colors physical granules to arm UAF detection.
     - `mode <sync|async>`: Switches between synchronous and asynchronous fault handling.
2. **Exploit PoC Binary (`labs/41-arm64-mte/exploit.c`)**:
   - Inspects `AT_HWCAP2` for native hardware `HWCAP2_MTE` capability.
   - Stage 1: Verifies successful access using matching logical and allocation tags (0xA == 0xA).
   - Stage 2: Demonstrates hardware trap upon corrupted/mismatched pointer tag (0xB vs 0xA).
   - Stage 3: Executes heap Use-After-Free attack and demonstrates MTE re-tagging defense (`SEGV_MTESERR`).
   - Stage 4: Simulates heap Out-of-Bounds overflow and verifies adjacent granule trap.
   - Stage 5: Evaluates asynchronous mode execution without instruction pipeline stall.
3. **Automated Test Runner (`labs/41-arm64-mte/test.sh`)**:
   - Detects host architecture, checks driver presence, runs PoC, and inspects dmesg logs.

---

### 2. Execution Guide

```bash
# 1. Launch ARM64 virtual machine (with MTE emulation)
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. Check for CPU MTE hardware support
cat /proc/cpuinfo | grep -i mte

# 3. Execute automated test suite
/bin/test_arm64_mte
```

### 3. Expected Test Output

```text
================================================================
   Lab 41: ARM64 Memory Tagging Extension (MTE) Suite           
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking CPU Architecture and MTE hardware support...
    Architecture: aarch64
[+] Native ARMv8.5+ MTE detected in /proc/cpuinfo!

[*] Step 2: Checking target driver at /proc/vuln_mte...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== ARM64 MTE (Memory Tagging Extension) Status ===
Kernel MTE Support       : CONFIG_ARM64_MTE=y
Current Fault Mode       : Synchronous (PR_MTE_TCF_SYNC)
Granule Size             : 16 bytes (4-bit tag per granule)
Total Allocations        : 0
Valid Tagged Accesses    : 0
UAF Attacks Trapped      : 0
OOB Overflows Trapped    : 0
Active Allocated Slots   :
====================================================

[*] Step 4: Running ARM64 MTE PoC...
===============================================================
   ARM64 Memory Tagging Extension (MTE) Evaluation PoC         
===============================================================

[+] Hardware ARMv8.5+ MTE detected via AT_HWCAP2!
[*] Initial Driver Status:

[*] Stage 1: Allocating Memory with MTE 4-bit Tag (0xA)...
[+] Accessing memory with MATCHING logical tag (0xA)...
[+] SUCCESS: Tag match verified (0xA == 0xA). Memory access granted.

[*] Stage 2: Accessing Memory with MISMATCHED logical tag (0xB vs 0xA)...
[+] DEFENSE SUCCESS: MTE hardware trap triggered! Tag mismatch blocked (errno=14: Bad address)

[*] Stage 3: Simulating Heap Use-After-Free (UAF) Attack...
[+] Freeing memory slot 0 (MTE re-colors physical granules with new tag)...
[+] Attacker attempts to access freed memory using dangling pointer (Tag 0xA)...
[+] DEFENSE SUCCESS: UAF blocked by MTE! Stale tag rejected (-EFAULT / SEGV_MTESERR)

[*] Stage 4: Simulating Out-of-Bounds (OOB) Heap Overflow...
[+] Allocating slot 1 (32 bytes = 2 granules, Tag 0x5)...
[+] Attacker attempts buffer overflow (accessing offset 48, beyond 32-byte boundary)...
[+] DEFENSE SUCCESS: Out-of-bounds overflow caught by MTE! Boundary enforced.

[*] Stage 5: Testing Asynchronous Fault Mode (PR_MTE_TCF_ASYNC)...
[+] Sending mismatched tag access in ASYNC mode...
[+] ASYNC Mode: Trap recorded to TFSR accumulator without halting instruction pipeline.

[*] Final ARM64 MTE Driver Diagnostics Report:
=== ARM64 MTE (Memory Tagging Extension) Status ===
Kernel MTE Support       : CONFIG_ARM64_MTE=y
Current Fault Mode       : Asynchronous (PR_MTE_TCF_ASYNC)
Granule Size             : 16 bytes (4-bit tag per granule)
Total Allocations        : 2
Valid Tagged Accesses    : 1
UAF Attacks Trapped      : 1
OOB Overflows Trapped    : 1
Active Allocated Slots   :
  [Slot 1] Size: 32 B, Granules: 2, Tag: 0x5
====================================================
[+] ARM64 MTE verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for MTE events:
[   58.201412] vuln_mte: Slot 0 allocated 64 bytes (4 granules). Assigned Allocation Tag: 0xA
[   58.202315] vuln_mte: [SYNC FAULT] Tag Mismatch! Logical: 0xB vs Allocation: 0xA at granule 1. Immediate SIGSEGV
[   58.203102] vuln_mte: Slot 0 freed. Granules re-tagged from 0xA to 0xF (UAF Trap Arming)
[   58.203890] vuln_mte: [HARDWARE TRAP - UAF] Dangling pointer access! Logical Tag 0xA != Re-tagged Allocation Tag 0xF. (SEGV_MTESERR)
[   58.204612] vuln_mte: Slot 1 allocated 32 bytes (2 granules). Assigned Allocation Tag: 0x5
[   58.205210] vuln_mte: [HARDWARE TRAP - OOB] Buffer Overflow! Offset 48 >= size 32. MTE Tag mismatch! (SEGV_MTESERR)
[   58.205901] vuln_mte: [ASYNC FAULT] Tag Mismatch recorded to TFSR_EL1 register! Asynchronous exception.

================================================================
   Lab 41 Test Complete: Verified ARM64 Memory Tagging Extension 
================================================================
```

---

## 5. Security Checklist & Best Practices

| Control Measure | Recommended Value | Security Guarantee |
| :--- | :--- | :--- |
| **Enable MTE Subsystem** | `CONFIG_ARM64_MTE=y` | Manages 16-byte granule physical tag storage and exception handling |
| **Enable Tagged Addr ABI** | `CONFIG_ARM64_TAGGED_ADDR_ABI=y` | Supports TBI pointers across userspace-to-kernel syscall boundaries |
| **Production Trap Mode** | `PR_MTE_TCF_ASYNC` or `ASYMM` | Delivers sub-0.5% performance overhead for zero-day memory defense |
| **Development Trap Mode** | `PR_MTE_TCF_SYNC` | Provides pinpoint accuracy (`si_addr`) for immediate UAF/OOB debugging |
| **Hardened Allocator** | Scudo / Hardened Malloc | Automatically re-colors granules on free to eliminate dangling pointers |
