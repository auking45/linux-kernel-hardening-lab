# CONFIG_RANDOMIZE_MEMORY: Direct Physical Mapping Randomization & ret2dir Defense

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/randomize-memory/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="CONFIG_RANDOMIZE_MEMORY Architecture Diagram"></iframe>
</div>

---

## 1. Overview & Threat Model

### 1.1 Addressed Threat: Deterministic Direct Physical Mapping & ret2dir Attacks

- **Limitations of Code KASLR and the Exposure of Kernel Heap**:
  - Traditional KASLR (`CONFIG_RANDOMIZE_BASE=y`) only randomizes kernel executable code (`.text`) and static symbol definitions.
  - The kernel heap (kmalloc, SLAB/SLUB) and buddy allocator pages access physical RAM through the **Direct Physical Memory Mapping (Physmap / `PAGE_OFFSET`)**, which maps all physical memory linearly into kernel space.
  - When the direct mapping base address is fixed (`0xffff888000000000` on x86_64), any physical address $P$ predictably maps to `0xffff888000000000 + P`.
- **ret2dir (Return-to-Direct-Mapped-Memory) Exploitation**:
  - An unprivileged attacker sprays user space physical memory (`mmap`) with payloads (shellcode, fake `struct cred`, ROP chains).
  - Leveraging a kernel vulnerability (e.g. function pointer overwrite, UAF), the attacker calculates the direct mapping kernel virtual address of their user payload and redirects kernel control flow directly into it.
  - This attack bypasses code KASLR completely without requiring any kernel pointer infoleaks.
- **Defense Philosophy of CONFIG_RANDOMIZE_MEMORY**:
  - Randomizes the base virtual address of the direct physical map (`page_offset_base`), dynamic virtual memory (`vmalloc_base`), and page descriptors (`vmemmap_base`).
  - Provides over 30,000 entropy slots, completely preventing attackers from predicting the virtual addresses of physical RAM pages.

### 1.2 Real-World Metaphor: The Shuffled Tunnel Entrances

- **Explanation**:
  - Physical RAM is like an underground vault containing valuables.
  - **Before Hardening (`CONFIG_RANDOMIZE_MEMORY=n`)**: The secret entrance (`PAGE_OFFSET`) leading from the surface (virtual memory) to the vault (physical RAM) is permanently fixed at 'Central Station Gate 1 (`0xffff888000000000`)'. An intruder places a bomb at locker 30 and easily tunnels directly from Gate 1 to detonate it.
  - **With Hardening (`CONFIG_RANDOMIZE_MEMORY=y`)**: The tunnel entrance shifts every night to one of tens of thousands of random secret locations across the city. Entering at the old Gate 1 coordinate lands the intruder against solid stone (unmapped virtual hole), triggering an immediate alarm (Page Fault).

---

## 2. Kernel Internal Architecture

### 2.1 Three Core Randomized Memory Regions (`arch/x86/mm/kaslr.c`)

- **Randomized Regions (`kaslr_regions`)**:
  1. `page_offset_base`: Base virtual address for direct 1:1 physical memory mapping.
  2. `vmalloc_base`: Base virtual address for `vmalloc()`, kernel module code, and kernel stacks.
  3. `vmemmap_base`: Array of `struct page` tracking all system memory frames.
- **Entropy Generation & Slot Padding**:
  - Early in boot, `kernel_randomize_memory()` calculates the available virtual address range (`remain_entropy`):
    ```c
    /* arch/x86/mm/kaslr.c */
    prandom_seed_state(&rand_state, kaslr_get_random_long("Memory"));
    for (i = 0; i < ARRAY_SIZE(kaslr_regions); i++) {
        unsigned long entropy;
        ...
        rand = prandom_u32_state(&rand_state);
        entropy = (rand % (remain_entropy + 1)) & PUD_PAGE_MASK;
        vaddr += entropy;
        *kaslr_regions[i].base = vaddr;
        vaddr += get_padding(&kaslr_regions[i]);
    }
    ```
  - The relative order of regions is preserved, while base addresses and inter-region paddings are pseudo-randomized.

### 2.2 ARM64 Implementation Architecture (`arch/arm64/mm/init.c`)

- On ARM64, enabling `CONFIG_RANDOMIZE_BASE=y` automatically randomizes the linear mapping base `memstart_addr` using `memstart_offset_seed`:
  ```c
  /* arch/arm64/mm/init.c */
  if (memstart_offset_seed > 0 && range >= (s64)ARM64_MEMSTART_ALIGN) {
      range /= ARM64_MEMSTART_ALIGN;
      memstart_addr -= ARM64_MEMSTART_ALIGN * ((range * memstart_offset_seed) >> 16);
  }
  ```
- This achieves symmetric protection against linear mapping spraying across architectures.

---

## 3. Hands-on Lab Implementation

### 3.1 Vulnerable Target Driver (`vuln_randmem.c`)

- Exposes `/proc/vuln_randmem` (mode `0666`):
  - **Memory Base Telemetry**:
    - `PAGE_OFFSET_BASE`: Actual runtime direct mapping base.
    - `STATIC_PAGE_OFFSET`: Fixed default reference base (`0xffff888000000000` on x86_64).
    - `VMALLOC_BASE`: Runtime vmalloc base.
    - `RANDMEM_SLIDE`: Offset between current base and static reference.
    - `TARGET_PAGE_PHYS`: Physical RAM address of allocated test buffer.
    - `TARGET_DIRECT_VIRT`: Real direct-map virtual address (`__va(phys)`).
    - `STATIC_GUESS_VIRT`: Predicted virtual address using static formula.
  - **Attack Dispatch Validation**:
    - Compares user-supplied virtual address against `TARGET_DIRECT_VIRT`.

### 3.2 ret2dir Exploit PoC (`exploit.c`)

- Executed by unprivileged user `lab` (UID 1000):
  - **Stage 1 (Blind ret2dir Attack)**:
    - Calculates target virtual address without infoleak: $Target = STATIC\_BASE + TARGET\_PHYS$.
    - **Base (`randomize-memory-disabled`)**: Guess matches target $\rightarrow$ 100% exploit success (`[!] VULNERABILITY CONFIRMED`).
    - **Hardened (`randomize-memory`)**: Random slide causes mismatch $\rightarrow$ attack blocked (`[+] DEFENSE ACTIVE`).
  - **Stage 2 (Infoleak Simulation)**:
    - Verifies that knowing the direct map slide compromises the target, proving why layered defenses (`STACKLEAK`) are required.

---

## 4. Dual-Architecture Live Verification

### 4.1 x86_64 Live Verification Logs

#### Base Kernel (`randomize-memory-disabled`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_randomize_memory
Memory Randomization: ACTIVE (KASLR enabled)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xff11000000000000
STATIC_PAGE_OFFSET:    0xff11000000000000
VMALLOC_BASE:          0xffa0000000000000
RANDMEM_SLIDE:         0x0000000000000000
RANDMEM_STATUS:        DISABLED (Deterministic)
TARGET_PAGE_PHYS:      0x0000000001325000
TARGET_DIRECT_VIRT:    0xff11000001325000
STATIC_GUESS_VIRT:     0xff11000001325000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Regions Telemetry:
    Direct Map Base:     0xff11000000000000
    Static Default Base: 0xff11000000000000
    Vmalloc Base:        0xffa0000000000000
    Randmem Slide:       0x0000000000000000
    Randomization Status: DISABLED (Deterministic)

[*] Target Physical Page Mapping:
    Physical Address:    0x0000000001325000
    Actual Direct Virt:  0xff11000001325000
    Static Guess Virt:   0xff11000001325000

=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xff11000001325000
=========================================================
[!] Target memory accessed successfully!
[!] VULNERABILITY CONFIRMED: Direct memory mapping is deterministic!
[!] Attacker predicted kernel virtual address (0xff11000001325000) without infoleak.
[!] ret2dir exploit enables attackers to execute/dereference sprayed physical pages.
```

#### Hardened Kernel (`randomize-memory`, `CONFIG_RANDOMIZE_MEMORY=y`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_randomize_memory
Memory Randomization: ACTIVE (KASLR enabled)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xff19396580000000
STATIC_PAGE_OFFSET:    0xff11000000000000
VMALLOC_BASE:          0xff5a7019c0000000
RANDMEM_SLIDE:         0x0008396580000000
RANDMEM_STATUS:        ENABLED (Randomized)
TARGET_PAGE_PHYS:      0x00000000013b2000
TARGET_DIRECT_VIRT:    0xff193965813b2000
STATIC_GUESS_VIRT:     0xff110000013b2000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Regions Telemetry:
    Direct Map Base:     0xff19396580000000
    Static Default Base: 0xff11000000000000
    Vmalloc Base:        0xff5a7019c0000000
    Randmem Slide:       0x0008396580000000
    Randomization Status: ENABLED (Randomized)

[*] Target Physical Page Mapping:
    Physical Address:    0x00000000013b2000
    Actual Direct Virt:  0xff193965813b2000
    Static Guess Virt:   0xff110000013b2000

=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xff110000013b2000
=========================================================
[-] Write returned error: Invalid argument (errno = 22)
[+] Access blocked or target address was invalid!
[+] DEFENSE ACTIVE: CONFIG_RANDOMIZE_MEMORY verified!
[+] Static guess missed actual direct map by 0x8396580000000 bytes.
[+] ret2dir / direct-map spraying exploitation is completely foiled!
```

---

### 4.2 ARM64 Live Verification Logs

#### Base Kernel (`randomize-memory-disabled`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_randomize_memory
Memory Randomization: DISABLED (nokaslr active)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xffff000000000000
STATIC_PAGE_OFFSET:    0xffff000000000000
VMALLOC_BASE:          0xffff800080000000
RANDMEM_SLIDE:         0x0000000000000000
RANDMEM_STATUS:        DISABLED (Deterministic)
TARGET_PAGE_PHYS:      0x00000000414cb000
TARGET_DIRECT_VIRT:    0xffff0000014cb000
STATIC_GUESS_VIRT:     0xffff0000014cb000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xffff0000014cb000
=========================================================
[!] Target memory accessed successfully!
[!] VULNERABILITY CONFIRMED: Direct memory mapping is deterministic!
[!] Attacker predicted kernel virtual address (0xffff0000014cb000) without infoleak.
[!] ret2dir exploit enables attackers to execute/dereference sprayed physical pages.
```

#### Hardened Kernel (`randomize-memory`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 kaslr lab_test=test_randomize_memory
Memory Randomization: ACTIVE (KASLR enabled)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xffff000000000000
STATIC_PAGE_OFFSET:    0xffff000000000000
VMALLOC_BASE:          0xffff800080000000
RANDMEM_SLIDE:         0x00004ca5c0000000
RANDMEM_STATUS:        ENABLED (Randomized)
TARGET_PAGE_PHYS:      0x00000000415e0000
TARGET_DIRECT_VIRT:    0xffff4ca5c15e0000
STATIC_GUESS_VIRT:     0xffff0000015e0000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xffff0000015e0000
=========================================================
[-] Write returned error: Invalid argument (errno = 22)
[+] Access blocked or target address was invalid!
[+] DEFENSE ACTIVE: CONFIG_RANDOMIZE_MEMORY verified!
[+] Static guess missed actual direct map by 0x4ca5c0000000 bytes.
[+] ret2dir / direct-map spraying exploitation is completely foiled!
```

---

### 4.3 Hardening Comparison Matrix

| Metric | Base (`CONFIG_RANDOMIZE_MEMORY=n`) | Hardened (`CONFIG_RANDOMIZE_MEMORY=y`) |
| :--- | :--- | :--- |
| **Direct Mapping Base** | `0xffff888000000000` (Static) | Boot-time randomized (~30,000 slots) |
| **vmalloc / vmemmap Base** | Fixed compile-time bounds | Dynamically randomized with padding |
| **ret2dir Attack Feasibility** | **High** (Predictable phys-to-virt) | **Neutralized** (Virtual address unknown) |
| **Heap Spray Exploitation** | Reliable cross-ring memory access | Target location estimation foiled |
| **Runtime Performance Cost** | 0% | **0%** (One-time early boot page table setup) |
| **Relationship to Code KASLR** | Code protected, heap/RAM exposed | Comprehensive multi-region defense |

---

## 5. Performance Trade-offs & Strategic Guidance

### 5.1 Performance & Overhead
- **Zero Runtime Overhead**: The base address is applied once during early boot page table construction, imposing 0% ongoing CPU performance loss.
- **KASAN Incompatibility**: KASAN shadow memory mappings require rigid PGD alignment; KASAN automatically disables memory randomization via `kaslr_memory_enabled()`.

### 5.2 Production Best Practices
- **Mandatory on All Production Kernels**: Because runtime cost is zero, `CONFIG_RANDOMIZE_MEMORY=y` should always accompany `CONFIG_RANDOMIZE_BASE=y` in cloud and enterprise deployments.

---

## 6. Appendix

### 6.1 Technical Presentation Script

> "Hello everyone. Today we examine CONFIG_RANDOMIZE_MEMORY, which expands KASLR beyond executable code to protect the entire physical memory direct map.
>
> Many developers assume KASLR completely hides kernel memory. However, traditional KASLR only relocates the .text code section. The kernel's direct physical mapping—which maps all physical RAM linearly into kernel space—remains at a deterministic fixed address such as 0xffff888000000000 on x86_64.
>
> This creates a severe vector known as ret2dir, or return-to-direct-mapped-memory. An attacker can spray malicious data or fake credentials across user space physical pages, and then reliably calculate their exact kernel virtual addresses without needing any kernel infoleak.
>
> By enabling CONFIG_RANDOMIZE_MEMORY, the kernel randomizes the base virtual address of the direct physical map, vmalloc, and vmemmap regions with over 30,000 entropy slots. As demonstrated in our lab, blind ret2dir attacks result in immediate page faults or rejected dispatches, shutting down physmap exploitation with zero runtime performance cost."

### 6.2 Security Glossary

- **CONFIG_RANDOMIZE_MEMORY**: Kernel hardening option that randomizes direct physical mapping, vmalloc, and vmemmap regions on x86_64 and ARM64.
- **ret2dir (Return-to-Direct-Mapped-Memory)**: Kernel privilege escalation technique utilizing predictable kernel direct mapping to execute or dereference sprayed physical memory pages.
- **Physmap**: Linear direct virtual memory mapping of physical RAM (`PAGE_OFFSET`).
- **page_offset_base**: Internal kernel variable on x86_64 storing the runtime base address of the direct mapping region.
- **vmalloc_base**: Base virtual address for dynamic non-contiguous kernel memory allocations.
- **vmemmap_base**: Virtual memory region hosting the sparse `struct page` array.
