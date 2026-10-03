# ARMv9 Permission Overlay Extension (POE)

## 1. Overview & Threat Model

**ARMv9 POE (`CONFIG_ARM64_POE`, ARMv8.9-A / ARMv9.4-A)** is a transformative hardware security extension that completely decouples memory access permissions from Page Tables, enabling **instantaneous, zero-syscall dynamic access control over intra-process memory compartments via a single CPU register write (`POR_EL0`) in 1 clock cycle**.

Modern userland applications and runtimes (browsers, OpenSSL, databases) routinely execute large collections of third-party libraries, native plugins, and dynamic components within a single monolithic virtual address space:

1. **Intra-Process Lateral Movement Threat**:
   - Attackers exploiting memory corruption bugs in an unprivileged or third-party component (e.g. an image parser or network decoder) can freely read and write the entire process address space.
   - This grants unrestricted access to cryptographic private keys (RSA/AES), authentication session tokens, and executable JIT compilation buffers co-located in the same heap or stack.
2. **Performance Bottlenecks of Legacy `mprotect(2)`**:
   - Traditionally, protecting sensitive data required toggling memory permissions between `PROT_NONE` and `PROT_READ` via `mprotect()`.
   - However, every `mprotect()` invocation requires:
     1. Kernel mode transition (expensive syscall trap).
     2. Modifying Page Table Entries (PTEs) in the kernel page table hierarchy.
     3. Issuing multi-core TLB invalidations (TLB shootdowns / `TLBI` instructions).
   - This consumes thousands of clock cycles per toggle, rendering fine-grained, instantaneous compartmentalization (e.g., locking a vault between individual cryptographic signatures) completely unfeasible.
3. **The ARMv9 POE Silicon Innovation**:
   - Page tables merely assign a static 3-bit or 4-bit Protection Key Index (Keys 0 to 7) to memory pages.
   - The actual read/write/execute rights for each key are determined by the CPU's **`POR_EL0` (Permission Overlay Register EL0)**.
   - Toggling compartment access requires zero syscalls, zero page table walks, and zero TLB shootdowns—taking **1 single CPU clock cycle (`MSR POR_EL0, Xn`)**.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/armv9-poe/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Bank Vault Central Electronic Override Switch

ARMv9 POE functions just like a **bank vault protected by a rapid electronic master switch on the manager's desk**:

```
[ Legacy mprotect Approach ]
  Officer:   "To lock the vault, file a work order with headquarters (Syscall Trap), hire contractors to weld the door shut (PTE Edit), and radio all staff across branches (TLB Shootdown)!"
  Problem:   "Because locking and unlocking takes hours, the vault stays unlocked 99% of the day!" (Intruders can rob it anytime)

[ ARMv9 POE: Permanent Default Lockdown (POR_EL0[Key 1] = NONE) ]
  Officer:   "Click the electronic switch on the desk (`POR_EL0`) down to '0 (NONE)' in a fraction of a second!"
  Intruder:  "Exploiting a vulnerable plugin to read the master vault (Key 1)!"
  Hardware:  "CPU memory controller checks POR_EL0: 'Key 1: NONE'! Hardware gates slam shut!"
  Action:    "Hardware overlay fault raised (`SIGSEGV / SEGV_PKUERR`)! Secrets remain safe!"

[ Authorized Transaction: Instant Microsecond Unlock & Relock ]
  Crypto:    "1. Flip desk switch (`MSR POR_EL0`: Key 1 -> RW, 1 CPU cycle)"
             "2. Sign document with private key in vault"
             "3. Flip switch back (`MSR POR_EL0`: Key 1 -> NONE, 1 CPU cycle)"
  Security:  "The attack exposure window is crushed down to microsecond intervals!"
```

---

### 3. ARMv9 POE vs x86 MPK/PKU Comparison Matrix

| Feature | ARMv9 POE / S1POE (`CONFIG_ARM64_POE`) | x86 MPK / PKU (`CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS`) |
| :--- | :--- | :--- |
| **Control Register** | `POR_EL0` (Userspace), `POR_EL1` (Kernel) | `PKRU` (Userspace only) |
| **Permission Granularity** | 4-bit nibbles (None, Read, RW, Exec, RX overlays) | 2-bit flags (Access-Disable, Write-Disable) |
| **Execution Overlay** | Supported (`POE_PERM_X` overlays for code isolation) | Limited/unsupported in basic PKU |
| **Virtualization Stage 2** | Supported (S2POE hypervisor overlays) | Requires nested EPT extensions |
| **Register Write Instruction** | `MSR POR_EL0, Xn` (General-purpose register write) | `WRPKRU` (Dedicated instruction) |
| **Switching Latency** | **1 CPU Clock Cycle** (Zero Syscalls) | **Few Clock Cycles** (Zero Syscalls) |

---

## 3. Kernel Configurations & Hardening Flags

### 1. Hardening Kconfig (`configs/features/poe.config`)

```ini
# Linux Kernel Hardening Lab - ARMv9 POE Feature Config
CONFIG_ARM64_POE=y
CONFIG_ARCH_HAS_PKEYS=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
```

- `CONFIG_ARM64_POE=y`: Activates ARMv9.4-A Permission Overlay Extension and S1POE subsystem support.
- `CONFIG_ARCH_HAS_PKEYS=y`: Binds POE into Linux standard Memory Protection Keys (`pkey_alloc`, `pkey_mprotect`, `pkey_free`) syscall APIs.
- `CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y`: Allows storing key index tags in the upper bits of Virtual Memory Area (VMA) structures.

### 2. Userland Key Allocation & VMA Protection

```c
#define _GNU_SOURCE
#include <sys/mman.h>

/* 1. Allocate a hardware protection domain key */
int pkey = pkey_alloc(0, 0);

/* 2. Bind memory pages to the protection key */
pkey_mprotect(secret_vault, 4096, PROT_READ | PROT_WRITE, pkey);

/* 3. In-register lockdown (POR_EL0 mask set to NONE for Key) */
```

---

## 4. Hands-on Lab: `labs/42-armv9-poe`

### 1. Lab Components

1. **Target Driver (`labs/42-armv9-poe/vuln_poe.c`)**:
   - Implements simulated `POR_EL0` register holding 8 protection keys and a confidential AES key vault.
   - Registered at `/proc/vuln_poe` (0666):
     - `read_vault`: Attempts to read protected secret data in Key 1.
     - `write_vault <data>`: Attempts to overwrite protected data in Key 1.
     - `lock_vault`: Updates `POR_EL0` to `POE_PERM_NONE` (instantaneous lockdown).
     - `unlock_vault`: Updates `POR_EL0` to `POE_PERM_RW` (opens compartment).
     - `set_por <key> <perm>`: Dynamically sets permission nibble for any key.
2. **Exploit PoC Binary (`labs/42-armv9-poe/exploit.c`)**:
   - Stage 1: Demonstrates unprotected secret exposure in unlocked state.
   - Stage 2: Executes in-register zero-syscall lockdown via `POR_EL0`.
   - Stage 3: Verifies hardware trap (`-EACCES / SEGV_PKUERR`) upon unauthorized read attempt.
   - Stage 4: Verifies hardware trap upon unauthorized memory tampering write attempt.
   - Stage 5: Validates legitimate authorized fast access cycle (Unlock -> Operation -> Relock).
3. **Automated Test Runner (`labs/42-armv9-poe/test.sh`)**:
   - Evaluates CPU architecture, confirms driver presence, executes PoC, and verifies dmesg logs.

---

### 2. Execution Guide

```bash
# 1. Launch ARM64 virtual machine
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. Check for CPU POE hardware support
cat /proc/cpuinfo | grep -i poe

# 3. Run automated verification suite
/bin/test_armv9_poe
```

### 3. Expected Test Output

```text
================================================================
   Lab 42: ARMv9 Permission Overlay Extension (POE) Suite       
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking CPU Architecture and POE hardware support...
    Architecture: aarch64

[*] Step 2: Checking target driver at /proc/vuln_poe...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== ARMv9 POE (Permission Overlay Extension) Status ===
Kernel POE Support       : CONFIG_ARM64_POE=y
Simulated POR_EL0 Reg    : 0x00000033
Total Access Attempts    : 0
Read Allowed / Blocked   : 0 / 0
Write Allowed / Blocked  : 0 / 0
Protection Domain Key Table (POR_EL0):
  [Key 0] Perm: 0x3 - READ-WRITE (Full Access)
  [Key 1] Perm: 0x3 - READ-WRITE (Full Access) <- [PROTECTED SECRET VAULT]
  [Key 2] Perm: 0x0 - NONE (No Access - Fault on Read/Write)
  [Key 3] Perm: 0x0 - NONE (No Access - Fault on Read/Write)
====================================================

[*] Step 4: Running ARMv9 POE PoC...
===============================================================
   ARMv9 Permission Overlay Extension (POE) Evaluation PoC    
===============================================================

[*] Stage 1: Accessing Secret Vault in Unlocked State (POR_EL0: RW)...
[!] VULNERABLE: Secret vault data exposed! Any untrusted module can read it.

[*] Stage 2: Locking Vault Compartment via POR_EL0 register...
[+] Setting POR_EL0 Key 1 permission to POE_PERM_NONE (0x0)...

[*] Stage 3: Untrusted code attempts to read locked secret vault...
[+] DEFENSE SUCCESS: Hardware overlay trapped read access! (errno=13: Permission denied)
    Memory access halted by CPU POR_EL0 overlay (SEGV_PKUERR)!

[*] Stage 4: Untrusted code attempts to overwrite locked secret vault...
[+] DEFENSE SUCCESS: Hardware overlay trapped write access! (errno=13: Permission denied)
    Write tampering blocked in silicon before modifying memory!

[*] Stage 5: Authorized crypto routine: Fast unlock -> operation -> relock...
[+] Step 5a: Authorized routine unlocks POR_EL0 Key 1 to RW (1 CPU cycle)...
[+] Step 5b: Authorized routine reads secret key and signs transaction...
[+] Transaction signed successfully using private key in vault.
[+] Step 5c: Authorized routine immediately relocks POR_EL0 Key 1 to NONE (1 CPU cycle)...

[*] Final ARMv9 POE Driver Diagnostics Report:
=== ARMv9 POE (Permission Overlay Extension) Status ===
Kernel POE Support       : CONFIG_ARM64_POE=y
Simulated POR_EL0 Reg    : 0x00000003
Total Access Attempts    : 4
Read Allowed / Blocked   : 2 / 1
Write Allowed / Blocked  : 0 / 1
Protection Domain Key Table (POR_EL0):
  [Key 0] Perm: 0x3 - READ-WRITE (Full Access)
  [Key 1] Perm: 0x0 - NONE (No Access - Fault on Read/Write) <- [PROTECTED SECRET VAULT]
====================================================
[+] ARMv9 POE verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for POE events:
[   65.101200] vuln_poe: [ACCESS GRANTED] Read permitted on Key 1 (POR_EL0: R/RW)
[   65.101912] vuln_poe: [LOCKDOWN] Vault compartment (Key 1) locked in POR_EL0 (Perm: NONE)
[   65.102640] vuln_poe: [OVERLAY FAULT] Read denied on Key 1! POR_EL0 perm: 0x0 (-EACCES / SEGV_PKUERR)
[   65.103310] vuln_poe: [OVERLAY FAULT] Write denied on Key 1! POR_EL0 perm: 0x0 (-EACCES / SEGV_PKUERR)
[   65.104012] vuln_poe: [UNLOCKED] Vault compartment (Key 1) unlocked in POR_EL0 (Perm: RW)
[   65.104715] vuln_poe: [ACCESS GRANTED] Read permitted on Key 1 (POR_EL0: R/RW)
[   65.105410] vuln_poe: [LOCKDOWN] Vault compartment (Key 1) locked in POR_EL0 (Perm: NONE)

================================================================
   Lab 42 Test Complete: Verified ARMv9 Permission Overlay Ext  
================================================================
```

---

## 5. Security Checklist & Best Practices

| Control Measure | Recommended Value | Security Guarantee |
| :--- | :--- | :--- |
| **Enable Kernel POE** | `CONFIG_ARM64_POE=y` | Activates hardware permission overlay subsystem in ARMv9 silicon |
| **Bind Linux PKEYS** | `CONFIG_ARCH_HAS_PKEYS=y` | Ensures compatibility with standard userland `pkey_*` APIs |
| **Isolate Secrets by Domain** | PKEY segregation | Segregates private keys, tokens, and JIT buffers into distinct domains |
| **Default-Locked State** | `POR_EL0` set to `NONE` | Maintains compartments in inaccessible state outside active operations |
| **Minimize Exposure Time** | Instantaneous relocking | Re-locks `POR_EL0` immediately following cryptographic operations |
