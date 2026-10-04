# 02. Process Anatomy and Virtual Address Space (Virtual Address Space)

Every process executed under Linux does not see physical hardware RAM directly, but instead operates inside an isolated, private **64-bit Virtual Address Space** maintained by the Linux kernel and the CPU Memory Management Unit (MMU).

---

## 1. Learning Objectives & Overview

- Understand the 64-bit virtual memory division (128 TB User Space vs. 128 TB Kernel Space) in x86_64 and ARM64 architectures.
- Examine why the non-canonical address hole exists and how CPU hardware enforces segmentation faults on out-of-range references.
- Analyze the 7 foundational process memory segments (`.text`, `.rodata`, `.data`, `.bss`, Heap, mmap, Stack) along with their respective access permissions.
- Validate actual virtual memory area (VMA) mappings using the `/proc/self/maps` pseudo-filesystem.

---

## 2. Interactive Virtual Memory Map Inspector

Click on any segment in the virtual memory tower below to explore its address ranges, access permissions, and underlying security implications:

<div style="width: 100%; height: 600px; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/02-virtual-memory.html" style="width: 100%; height: 100%; border: none;"></iframe>
</div>

---

## 3. 64-bit Virtual Address Space Architecture

Modern 64-bit CPUs do not utilize the entire 64-bit address space ($2^{64} \approx 16 \text{ EB}$), but typically utilize a 48-bit virtual address width ($2^{48} = 256 \text{ TB}$):

```
[0xFFFFFFFFFFFFFFFF] ───────────┐
                                │ Kernel Space (128 TB)
[0xFFFF800000000000] ───────────┘
                                
  ( Non-Canonical Hole )         ~16.7 Million TB Unmapped Gap
                                   (CPU triggers #GP Fault upon access)
                                
[0x00007FFFFFFFFFFF] ───────────┐
                                │ User Space (128 TB)
[0x0000000000000000] ───────────┘
```

1. **Canonical Address Rule**:
   - In 48-bit addressing, bit 47 serves as the sign bit.
   - Bits 48 through 63 must match bit 47 through sign extension.
   - Addresses violating sign extension are non-canonical, producing an immediate hardware exception (#GP).
2. **User vs Kernel Hardware Isolation**:
   - User space (`0x0000000000000000 ~ 0x00007FFFFFFFFFFF`) holds distinct, per-process page tables.
   - Kernel space (`0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF`) is strictly supervisor-only (Ring 0 / EL1), triggering a Page Fault (`#PF`) on unprivileged user access.

---

## 4. Seven Core Memory Segments & the W^X Principle

The Linux kernel strictly partitions access permissions across VMAs to maintain process safety and security:

| Segment | Permissions | Stored Data & Characteristics | Growth Direction |
| :--- | :---: | :--- | :---: |
| **Code / Text** | `r-xp` | Compiled machine instructions, function bodies | Fixed |
| **ROData** | `r--p` | Constant string literals, const global variables | Fixed |
| **Data** | `rw-p` | Initialized global and static variables | Fixed |
| **BSS** | `rw-p` | Uninitialized global variables (Demand Zeroed) | Fixed |
| **Heap** | `rw-p` | Dynamic memory allocation pool (`malloc`, `brk`) | **Grows Up (▲)** |
| **mmap Region** | `r-xp` / `rw-p` | Shared libraries (`libc.so`), anonymous mappings | Dynamic |
| **Stack** | `rw-p` | Function stack frames, local variables, return addresses | **Grows Down (▼)** |

> [!IMPORTANT]
> **The W^X (Write XOR Execute) Principle**:
> Modern kernels prohibit granting simultaneous write (W) and execute (X) privileges on the same page. Writable regions like stack and heap are non-executable (NX/DEP), while executable code regions are strictly write-protected.

---

## 5. Lab Source Code & Live Memory Map Verification

- **Lab Source Code**: [`address_space_demo.c`](../../assets/labs/principles/02-address-space/address_space_demo.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/02-address-space/address_space_demo.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/02-address-space/Makefile)

### 5.1 Inspecting Segment Addresses

```bash
cd labs/principles/02-address-space
make run
```

```
============================================================
 64-bit Process Virtual Address Space Inspection (PID: 12580)
============================================================
[1] Code Segment (.text)       : 0x559e2b101149 (main)
                               : 0x559e2b101230 (dummy_function)
[2] Read-Only Data (.rodata)   : 0x559e2b102008 ("System Security Principles 2026")
[3] Initialized Data (.data)   : 0x559e2b104018 (0x1337)
[4] Uninitialized Data (.bss)  : 0x559e2b104020 (0x0)
[5] Heap Segment (malloc)      : 0x559e2cb032a0 (size=256)
[6] Memory Mapped Region (mmap): 0x7fa28c500000 (page-aligned)
[7] Shared Library (libc)      : 0x7fa28c312e40 (printf)
[8] Stack Segment (RSP area)   : 0x7ffd582a8934 (&local_stack_var)
                               : 0x7ffd582a894c (&argc)
[9] Kernel Space Boundary      : 0xffff800000000000 (x86_64) / 0xffff000000000000 (ARM64)
```

### 5.2 Dumping Raw `/proc/self/maps`

```bash
make run-maps
```

- Correlate output addresses with active VMAs, confirming `r-xp` on binary text, `rw-p` on data/heap, and `[stack] rw-p`.

---

## 6. Summary & Next Chapter

- A process operates within a structured virtual address space featuring segmented permissions.
- In the next chapter, we dissect the dynamic execution region that handles function calls: **[03. Stack Frame Mechanics and Calling Conventions (ABI)](03-stack-frame-and-abi.md)**.
