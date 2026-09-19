# KFENCE (Kernel Electric Fence: Sampling Heap Error Detector)

## 1. Overview & Motivation

The Linux kernel heap memory managed by the SLUB allocator represents one of the most critical attack surfaces, frequently suffering from memory safety vulnerabilities including Use-After-Free (UAF, CWE-416) and Out-of-Bounds (OOB, CWE-125/CWE-787) buffer overflows and underflows.

While **KASAN (Kernel Address Sanitizer)** provides comprehensive bug detection during development, it imposes prohibitive costs on production environments:
- **KASAN Limitations**: KASAN dedicates 1/8th of total physical memory to shadow memory and instruments every memory access with compiler instructions. This results in **over 100% memory overhead and a 2x to 3x (200-300%) increase in CPU latency**, making it impossible to run on live customer workloads, Android mobile devices, or high-throughput cloud infrastructure.

Introduced in Linux 5.12 and established as a foundational standard in 6.12 LTS, **KFENCE (Kernel Electric Fence, `CONFIG_KFENCE=y`)** solves this fundamental trade-off as a **low-overhead, sampling-based memory safety error detector tailored for production**:
1. **Probabilistic Sampling**: Rather than inspecting every allocation, KFENCE samples one allocation every configurable period (default 100ms, set to 10ms for this lab) and routes it to a dedicated guard page pool (`__kfence_pool`).
2. **Hardware MMU Guard Pages**: Guarded objects are sandwiched between unmapped, non-present (`PROT_NONE`) guard pages. A single-byte breach beyond the buffer boundary immediately triggers a hardware CPU page fault.
3. **UAF Page Protection**: When a guarded object is released via `kfree()`, its backing page is instantly marked non-present. Any subsequent dangling pointer access is immediately zapped and caught by an MMU fault.
4. **Negligible Overhead**: In production deployments, KFENCE incurs **less than 1% CPU overhead** and requires only a few megabytes of RAM, allowing 24/7 continuous operation in production fleets.

---

## 2. Real-World Analogy: Precision Rollercoaster Spot Checks & Electric Guardrails

The operation of KFENCE can be compared to a **high-speed amusement park safety system**:

```
[ Normal Passenger Trains (Standard SLUB Allocations) ] ──(Full Speed: No Delay)──► [ Normal Operation ]
                                                                       
[ 100ms Interval Alarm: Sample Train Selected ]
                   │
                   ▼
[ Dedicated KFENCE Inspection Track (Guard Page Pool) ]
  ┌─────────────────────────────────────────────────────────────┐
  │ [⚡ High-Voltage Fence] │ [ Test Train (Object) ] │ [⚡ High-Voltage Fence] │
  └───────────┬─────────────────────┬─────────────────────┬─────┘
              │                     │                     │
              ▼                     ▼                     ▼
      (Left Derailment)       (Reaching Out)       (Right Derailment)
      💥 Electric Trip!       ⚡ Alarm Sounds!      💥 Electric Trip!
```

1. **Traditional Kernel (Unattended Track)**:
   - All trains pass unchecked. If a train jumps tracks or if someone boards an already decommissioned empty train (UAF), there are no sensors to detect the issue until a fatal crash occurs.
2. **KASAN (Full Teardown at Every Station)**:
   - Every single train is disassembled and every bolt inspected before departure. It is completely thorough, but throughput slows by 3x, crippling theme park operations.
3. **KFENCE (Periodic Spot Sampling with Electric Fences)**:
   - Every 100ms, one train is diverted onto a specially instrumented track with electric guardrails (MMU guard pages). 99.9% of regular traffic proceeds at full speed with zero latency.
   - If the sample train strays off course by even a single byte, it contacts the electric fence, triggering an instantaneous alarm (`BUG: KFENCE: out-of-bounds`) and recording the incident.

---

## 3. Architecture & Internal Mechanisms

### 3.1 Memory Pool Layout (`__kfence_pool`)

At boot time, KFENCE reserves a contiguous region of physical memory (`mm/kfence/core.c`):

```text
[ Guard Page 0 ] (PROT_NONE, Non-present)
[ Object Page 0] (Guarded Object Slot) ──► Left/Right Alignment + Redzone Canaries
[ Guard Page 1 ] (PROT_NONE, Non-present)
[ Object Page 1] (Guarded Object Slot)
[ Guard Page 2 ] (PROT_NONE, Non-present)
...
[ Guard Page N ] (PROT_NONE, Non-present)
```

- Total pages: `(CONFIG_KFENCE_NUM_OBJECTS * 2) + 1`. With the default pool size of 255 objects, KFENCE occupies only 511 pages (~2MB).
- Guard pages lack the present bit in their page table entries, forcing the MMU to fault on any access attempt.

### 3.2 Allocation Gating Mechanism (`kfence_allocation_gate`)

```text
Timer Tick (kfence_sample_interval interval)
       │
       ▼
atomic_set(&kfence_allocation_gate, 1);
       │
       ▼
SLUB Allocation Request (kmalloc / kmem_cache_alloc)
       │
       ▼
kfence_alloc()
       │
       ├─► allocation_gate == 0: Returns to standard SLUB fastpath
       │
       └─► allocation_gate == 1 (Gate Acquired):
             atomic_set(&kfence_allocation_gate, 0); // Close gate immediately
             kfence_guarded_alloc() -> Allocates object from __kfence_pool
```

### 3.3 Random Left/Right Alignment & OOB Detection

Because objects (e.g. 32 bytes) are smaller than a 4096-byte page, their placement within the page determines the detection boundary:
- **Right Alignment (`!PAGE_ALIGNED`, 50% probability)**: The object is positioned at the very end of the page (`PAGE_SIZE - size`). An overflow of even 1 byte (`buf + size`) hits the right guard page.
- **Left Alignment (`PAGE_ALIGNED`, 50% probability)**: The object is aligned to the page start. An underflow (`buf - 1`) hits the left guard page.
- **Canary Verification**: Unoccupied areas of the object page are filled with canary patterns (`0xAA` / `0xBB`) to detect intra-page memory corruptions upon deallocation.

### 3.4 UAF Trap & Quarantine

1. When a guarded object is released via `kfree(ptr)`, `kfence_guarded_free()` executes.
2. The entire page containing the object is reprotected as `PROT_NONE` via `kfence_protect()`.
3. Any subsequent read or write using a dangling pointer generates an immediate hardware page fault.
4. `kfence_handle_page_fault()` catches the fault, logs `BUG: KFENCE: use-after-free`, and prints cross-referenced allocation and deallocation stack traces.

---

## 4. Interactive Architecture Simulator

The simulator below demonstrates the architectural difference between standard SLUB and KFENCE guard pools during OOB and UAF events:

<iframe src="../../assets/diagrams/kfence/architecture.html" width="100%" height="750px" style="border:none; border-radius:8px; overflow:hidden;"></iframe>

---

## 5. Lab Configuration & Build Guide

### 5.1 Kernel Configuration

```ini
# configs/features/kfence.config
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=10
CONFIG_KFENCE_NUM_OBJECTS=255
CONFIG_LKDTM=y
```

### 5.2 Build & Execution Commands

#### ARM64 (aarch64)
```bash
# Boot hardened kernel with automated test
./scripts/run_lab.sh --arch arm64 --feature kfence --test test_kfence

# Boot baseline kernel for comparison
./scripts/run_lab.sh --arch arm64 --feature kfence-disabled --test test_kfence
```

#### x86_64
```bash
# Boot hardened kernel with automated test
./scripts/run_lab.sh --arch x86_64 --feature kfence --test test_kfence

# Boot baseline kernel for comparison
./scripts/run_lab.sh --arch x86_64 --feature kfence-disabled --test test_kfence
```

---

## 6. Exploit Verification & Analysis

### 6.1 Unprivileged PoC Exploit (`/bin/exploit_kfence`)

Executed as unprivileged user `lab` (UID 1000) against `/proc/vuln_kfence`.

#### Hardened Kernel (`CONFIG_KFENCE=y`) Output
```text
=========================================================
  KFENCE (Kernel Electric Fence) Verification PoC
  UID: 1000 | GID: 1000 | PID: 50
=========================================================
=========================================================
  KFENCE Verification Driver (/proc/vuln_kfence)
=========================================================
Kernel Configuration : CONFIG_KFENCE=y [ENABLED]
Sample Interval      : 10 ms (configurable via kfence.sample_interval)
Protection Status    : ACTIVE (Sampling guard pages & UAF page protection)
Debugfs Interface    : /sys/kernel/debug/kfence/stats
=========================================================

[*] Initial KFENCE bug counter: 0
    [Stats] Current KFENCE Debugfs Counters:
            currently allocated: 2
            total allocations: 14
            total frees: 12
            zombie allocations: 0
            total bugs: 0

[*] Step 1: Triggering Out-of-Bounds (OOB) Probe via Driver
[+] Triggered OOB probe against kernel heap buffer.
    [Stats] Current KFENCE Debugfs Counters:
            total bugs: 1

[*] Step 2: Triggering Use-After-Free (UAF) Probe via Driver
[+] Triggered UAF probe against freed kernel heap object.

[*] Final KFENCE bug counter: 2
    [Stats] Current KFENCE Debugfs Counters:
            total bugs: 2

=========================================================
  Verification Assessment:
  [+] PASS: KFENCE successfully trapped heap errors!
  [+] Total Bugs Caught: 2 (New bugs: +2)
  [+] Memory Protection: ACTIVE (Electric Guard Pages Enforced)
=========================================================
```

#### Kernel Log (`dmesg`)
```text
[   14.238120] ==================================================================
[   14.238240] BUG: KFENCE: out-of-bounds read in trigger_oob_test+0x54/0x9c
[   14.238380] Out-of-bounds read at 0xffff800082f53000 (1B right of kfence-#14):
[   14.238510]  trigger_oob_test+0x54/0x9c
[   14.238620]  vuln_kfence_write+0x68/0xb0
[   14.238710] kfence-#14: 0xffff800082f52fe0-0xffff800082f52fff (size 32, cache kmalloc-32)
[   14.238800] allocated by task 50 on cpu 1 at 14.237890s:
[   14.238910]  alloc_guarded_object+0x44/0xa8
[   14.239020]  trigger_oob_test+0x20/0x9c
[   14.239130] ==================================================================
[   14.258900] ==================================================================
[   14.259010] BUG: KFENCE: use-after-free read in trigger_uaf_test+0x88/0xbc
[   14.259120] Use-after-free read at 0xffff800082f56fe0 (in kfence-#15):
[   14.259230]  trigger_uaf_test+0x88/0xbc
[   14.259340] freed by task 50 on cpu 1 at 14.258710s:
[   14.259450]  kfree+0x78/0x120
[   14.259560]  trigger_uaf_test+0x70/0xbc
[   14.259670] allocated by task 50 on cpu 1 at 14.258410s:
[   14.259780]  alloc_guarded_object+0x44/0xa8
[   14.259890]  trigger_uaf_test+0x20/0xbc
[   14.260000] ==================================================================
```

#### Baseline Kernel Output
```text
=========================================================
  Verification Assessment:
  [-] BASELINE: KFENCE is disabled. Heap OOB/UAF executed silently!
  [-] Memory Protection: NONE (Unchecked SLUB operation)
=========================================================
```

---

## 7. Performance & Production Trade-offs

1. **Production Runtime Overhead**:
   - At a 100ms sample interval, a maximum of 10 allocations per second enter the guard pool.
   - Over 99.99% of allocations only execute a single atomic branch check, keeping **CPU overhead under 0.5%**.
2. **Memory Footprint**:
   - The default pool of 255 objects occupies roughly 2MB, making it ideal for memory-constrained smartphones and IoT devices.
3. **Industry Deployment**:
   - **Google Android Common Kernel (ACK)**: Enabled by default since Android 12 across billions of devices, continually reporting real-world zero-day heap flaws via telemetry.
   - **Google Cloud & Meta**: Widely deployed across fleet infrastructure for kernel bug detection.

---

## 8. FAQ & Troubleshooting

**Q1: Does a KFENCE fault crash the kernel?**
- By default, KFENCE does not panic the kernel. It logs a comprehensive diagnostic report and temporarily unprotects the page to maintain system availability. In high-security systems, `panic_on_warn=1` can be specified to force an immediate reboot.

**Q2: Can the sample interval be adjusted dynamically?**
- Yes. Writing a value in milliseconds to `/sys/module/kfence/parameters/sample_interval` alters the sampling frequency in real time without requiring a reboot.

