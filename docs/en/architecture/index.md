# Kernel Memory Models & Protection Architecture

Analysis of 64-bit virtual memory layout, hardware privilege levels, and defense-in-depth architecture across x86_64 and arm64.

---

## 1. Privilege Level Model Comparison

```mermaid
graph TD
    subgraph x86_64 ["x86_64 Privilege Rings"]
        R3["Ring 3: User Space (Applications)"]
        R0["Ring 0: Kernel Space (Kernel Core, Modules)"]
        R3 -->|"syscall / sysenter"| R0
    end

    subgraph arm64 ["ARM64 Exception Levels"]
        EL0["EL0: User Space (Applications)"]
        EL1["EL1: Kernel Space (OS Kernel)"]
        EL2["EL2: Hypervisor (KVM)"]
        EL3["EL3: Secure Monitor (Firmware)"]
        EL0 -->|"svc (Supervisor Call)"| EL1
    end
```

---

## 2. 64-bit Virtual Address Space Splitting

### 2.1 x86_64 (48-bit / 4-Level Paging)
- `0x0000_0000_0000_0000` ~ `0x0000_7FFF_FFFF_FFFF` (128TB): **User Space**
- `0x0000_8000_0000_0000` ~ `0xFFFF_7FFF_FFFF_FFFF`: Non-canonical hole
- `0xFFFF_8000_0000_0000` ~ `0xFFFF_FFFF_FFFF_FFFF` (128TB): **Kernel Space**
  - Direct mapping (physical memory identity map)
  - vmalloc / ioremap ranges
  - Modules and Kernel Text (`CONFIG_RANDOMIZE_BASE` randomization target)

### 2.2 ARM64 (48-bit VA, TTBR0 vs TTBR1)
- `0x0000_0000_0000_0000` ~ `0x0000_FFFF_FFFF_FFFF`: **TTBR0_EL1** (User Space)
- `0xFFFF_0000_0000_0000` ~ `0xFFFF_FFFF_FFFF_FFFF`: **TTBR1_EL1** (Kernel Space)
- Hardware base registers split lower and upper address spaces directly.

---

## 3. Defense-in-Depth Architecture

```mermaid
flowchart LR
    A["Attack Ingress"] --> B["Layer 1: Boundary Control (Seccomp, Landlock, AppArmor)"]
    B --> C["Layer 2: Control Flow Defense (Stack Canary, kCFI, IBT/BTI)"]
    C --> D["Layer 3: Layout Obfuscation (KASLR, FG-KASLR, Randstruct)"]
    D --> E["Layer 4: Permission Enforcement (SMEP/SMAP, W^X Strict RWX)"]
    E --> F["Layer 5: Fault Containment (KFENCE, Page Table Check)"]
```
