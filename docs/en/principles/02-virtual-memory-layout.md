# 02. Process Anatomy and Virtual Address Space (Virtual Address Space)

Every process executed under Linux does not see physical hardware RAM directly, but instead operates inside an isolated, private **64-bit Virtual Address Space** maintained by the Linux kernel and the CPU Memory Management Unit (MMU). Focuses on **AArch64 (ARM64)** as the primary architecture for device and mobile system security, with comparative architectural analysis against **x86_64**.

---

## 1. Learning Objectives & Overview

- Understand the 64-bit virtual memory division (User Space vs. Kernel Space) across AArch64 and x86_64 architectures.
- Compare AArch64's dual Translation Table Base Registers (`TTBR0_EL1` vs. `TTBR1_EL1`) against the x86_64 single `CR3` canonical address hole model.
- Analyze the 7 foundational process memory segments (`.text`, `.rodata`, `.data`, `.bss`, Heap, mmap, Stack) along with their respective access permissions.
- Examine how the hardware enforces the **W^X (Write XOR Execute)** security principle.
- Validate live virtual memory area (VMA) mappings using the `/proc/self/maps` pseudo-filesystem.

---

## 2. Interactive Virtual Memory Map Inspector

Click on any segment in the virtual memory tower below to explore its address ranges, access permissions, and underlying security implications:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/02-virtual-memory.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 64-bit Virtual Address Space Architecture: AArch64 vs. x86_64

Modern 64-bit CPUs do not utilize the entire 64-bit address space ($2^{64} \approx 16 \text{ EB}$), but typically utilize a 48-bit virtual address width ($2^{48} = 256 \text{ TB}$):

```
[0xFFFFFFFFFFFFFFFF] ───────────┐
                                │ Kernel Space (Upper Half)
[0xFFFF000000000000] ───────────┘ (AArch64: TTBR1_EL1 / x86_64: CR3 Top Half)
                                
  ( Non-Canonical / Unmapped )   Unmapped Gap (Hardware exception on access)
                                
[0x0000FFFFFFFFFFFF] ───────────┐ (AArch64: TTBR0_EL1)
                                │ User Space (Lower Half)
[0x0000000000000000] ───────────┘
```

### 3.1 AArch64 Hardware Split Architecture (`TTBR0_EL1` vs. `TTBR1_EL1`)

The ARM64 architecture physically bifurcates the translation pipeline at the register level:

1. **`TTBR0_EL1` (Translation Table Base Register 0)**:
   - Holds the base address for the User Space translation table (`0x0000_0000_0000_0000 ~ 0x0000_FFFF_FFFF_FFFF`).
   - During a process context switch, the kernel only swaps `TTBR0_EL1` to point to the incoming process page table.
2. **`TTBR1_EL1` (Translation Table Base Register 1)**:
   - Holds the base address for the Kernel Space translation table (`0xFFFF_0000_0000_0000 ~ 0xFFFF_FFFF_FFFF_FFFF`).
   - Kernel mappings remain permanently bound, eliminating TLB churn and kernel page table thrashing on context switches.
3. **`TCR_EL1` (Translation Control Register)**:
   - Configures the independent address sizes via `T0SZ` and `T1SZ` (e.g., 39-bit, 48-bit, or 52-bit virtual addressing).

### 3.2 x86_64 Canonical Address Rules

On x86_64, a single root register (`CR3`) points to the 4-level (PML4) or 5-level (PML5) paging hierarchy:

- In 48-bit addressing, the upper 16 bits (bits 48–63) must replicate bit 47 via sign extension.
- When bit 47 is `0`, addresses up to `0x00007FFFFFFFFFFF` represent User Space. When bit 47 is `1`, addresses from `0xFFFF800000000000` represent Kernel Space.
- Accessing the ~16.7 million TB unmapped gap between them triggers a General Protection Fault (`#GP Fault`) immediately.

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
| **Stack** | `rw-p` | Function stack frames, local variables, return addresses (LR / RET) | **Grows Down (▼)** |

> [!IMPORTANT]
> **The W^X (Write XOR Execute) Principle**:
> Modern kernels prohibit granting simultaneous write (W) and execute (X) privileges on the same page. Writable regions like stack and heap are non-executable (NX/DEP, ARM: XN / Execute-Never), while executable code regions are strictly write-protected.

---

## 5. Lab Source Code & Live Memory Map Verification

- **Lab Source Code**: [`address_space_demo.c`](../../assets/labs/principles/02-address-space/address_space_demo.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/02-address-space/address_space_demo.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/02-address-space/Makefile)

### 5.1 Inspecting Segment Addresses

=== "AArch64 (Default Target)"
    ```bash
    cd labs/principles/02-address-space
    make run
    ```

    ```
    === Running address_space_demo on aarch64 ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./address_space_demo
    ============================================================
     64-bit Process Virtual Address Space Inspection (PID: 34)
    ============================================================
    [1] Code Segment (.text)       : 0x74fe76c80c30 (main)
                                   : 0x74fe76c80c28 (dummy_function)
    [2] Read-Only Data (.rodata)   : 0x74fe76c80e70 ("System Security Principles 2026")
    [3] Initialized Data (.data)   : 0x74fe76ca0010 (0x1337)
    [4] Uninitialized Data (.bss)  : 0x74fe76ca0018 (0x0)
    [5] Heap Segment (malloc)      : 0x400000a3e2a0 (size=256)
    [6] Memory Mapped Region (mmap): 0x400000b3e000 (page-aligned)
    [7] Shared Library (libc)      : 0x4000008c0410 (printf)
    [8] Stack Segment (RSP area)   : 0x4000007fedb4 (&local_stack_var)
                                   : 0x4000007fedac (&argc)
    [9] Kernel Space Boundary      : 0xffff800000000000 (x86_64) / 0xffff000000000000 (ARM64)
    ```

=== "x86_64 (Comparative Target)"
    ```bash
    cd labs/principles/02-address-space
    make ARCH=x86_64 run
    ```

    ```
    === Running address_space_demo on x86_64 ===
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

- Linux processes execute within an isolated virtual address space comprising text, data, heap, mmap, and stack areas.
- AArch64 achieves robust user/kernel translation isolation via hardware registers `TTBR0_EL1` and `TTBR1_EL1`.
- In the next chapter, we dive into how function stack frames are generated and torn down: **[03. Stack Frame Anatomy and Calling Convention (ABI)](03-stack-frame-and-abi.md)**.
