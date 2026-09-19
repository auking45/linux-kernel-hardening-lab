# Hardened Usercopy (User-Space Memory Copy Boundary Enforcement)

## 1. Overview & Motivation

In the Linux kernel, data exchange between kernel space (Ring 0 / EL1) and user space (Ring 3 / EL0) primarily relies on primitive memory copy functions: `copy_to_user()` and `copy_from_user()`. System call parameters, filesystem I/O, device driver `read()` / `write()` / `ioctl()` operations, and network packets all pass through this critical boundary layer.

In traditional kernel implementations, memory copies perform straightforward byte transfers up to the requested length without validating the actual allocated size of the source or destination object (e.g., slab-allocated memory or kernel stack buffers):

1. **Heap Out-of-bounds Read & Information Disclosure (CWE-125)**:
   - When a device driver or network subsystem allocates a 64-byte SLUB object and mistakenly copies 128 bytes to user space (`copy_to_user`), adjacent heap data is exposed.
   - The extra 64 bytes leak adjacent slab objects, residual cryptographic keys, function pointers, and allocator metadata (`freelist` pointers) directly to user space. This gives attackers the exact memory leaks needed to bypass KASLR and construct further exploit chains.
2. **Heap Out-of-bounds Overwrite & Memory Corruption (CWE-787)**:
   - Conversely, unvalidated `copy_from_user()` calls writing 128 bytes into a 64-byte kernel buffer corrupt adjacent heap objects and allocator metadata, leading to privilege escalation and arbitrary code execution.
3. **Kernel Code (.text) Disclosure & KASLR Defeat**:
   - If kernel code addresses or function pointers are directly copied to user space, attackers can dump raw kernel executable instructions, calculate gadget offsets (ROP/JOP), and completely defeat KASLR.
4. **Stack Frame Escaping**:
   - Copying past the boundary of the current thread stack frame leaks local variables, stack canaries, or return addresses from previous stack frames.

Linux Kernel 6.12 LTS provides `CONFIG_HARDENED_USERCOPY=y` to eliminate these attack vectors. It inserts a rigorous runtime interceptor (`__check_object_size()`) into `copy_to_user()` and `copy_from_user()` that checks slab object sizes, stack frame validity, and kernel text boundaries. Any detected boundary breach instantly triggers `usercopy_abort()` and a kernel `BUG()`, terminating the offending process and safeguarding kernel memory.

---

## 2. Real-World Analogy: Bulletproof Bank Teller Window with Document Sizer

The mechanism of `CONFIG_HARDENED_USERCOPY` can be compared to a **high-security bank teller window**:

```
[ Bank Secure Area (Kernel Space) ]             [ Customer Lobby (User Space) ]
  ┌───────────────────────────────┐               ┌───────────────────────────┐
  │ 64B Deposit Slip (Chunk A)    │               │                           │
  │ 64B Vault Key Note (Chunk B)  │               │ Customer Receiving Tray   │
  └───────────────┬───────────────┘               └─────────────▲─────────────┘
                  │                                             │
                  ▼                                             │
      [ Security Sizer: __check_object_size ]                   │
      - Standard Size: Exactly 64B Deposit Slip                 │
      - Attempting 128B transfer? ────(⛔ SHUTTER SLAMS SHUT!)──┘
        (Vault Key Note detected attached -> Alarm triggered)
```

1. **Traditional Kernel (Unattended Open Counter)**:
   - A bank clerk attempts to hand a 64-byte deposit slip to a customer, but accidentally leaves a note with the vault key code (adjacent Chunk B) attached, sliding a 128-byte stack across the counter.
   - The customer receives confidential bank records without any authorization (heap out-of-bounds disclosure).
2. **Hardened Kernel (Electronic Document Sizer & Bulletproof Shutter)**:
   - The teller window features a precision electronic scanner (`__check_object_size`) measuring the dimensions and origin of every passed document.
   - If documents exceed the standard 64-byte slip size or if someone attempts to chip off tiles from the vault wall (kernel `.text` execution code), a steel shutter immediately slams down and alarms sound (`usercopy_abort` -> `BUG()`), isolating the breach entirely.

---

## 3. Architecture & Internal Mechanisms

### 3.1 `copy_to_user` Interception Pipeline

In `include/linux/uaccess.h`, memory copy invocations traverse compile-time and runtime validation gates:

```text
copy_to_user(to, from, n)
       │
       ▼
check_copy_size(from, n, is_source=true)
       │
       ▼
check_object_size(addr, bytes, is_source)
       │
       ▼ (When CONFIG_HARDENED_USERCOPY=y)
__check_object_size(ptr, n, to_user)
       │
       ├─► 1. check_bogus_address(): Checks for NULL or wrapped pointer addresses
       ├─► 2. check_kernel_text_object(): Blocks reads from kernel code ([_stext, _etext])
       ├─► 3. check_stack_object(): Validates process stack frame boundaries
       └─► 4. check_heap_object(): Enforces SLUB slab object limits (__check_heap_object)
```

### 3.2 SLUB Object Boundary Validation (`__check_heap_object`)

In `mm/slub.c`, slab object validation enforces the following bounds logic:

```c
void __check_heap_object(const void *ptr, unsigned long n,
                         const struct slab *slab, bool to_user)
{
    struct kmem_cache *s = slab->slab_cache;
    unsigned int offset = (ptr - slab_address(slab)) % s->size;

    /* Verify requested range falls completely within allowable usercopy bounds */
    if (offset >= s->useroffset &&
        offset - s->useroffset <= s->usersize &&
        n <= s->useroffset - offset + s->usersize)
        return; /* Bounds check passed */

    /* Abort if boundary exceeded */
    usercopy_abort("SLUB object", s->name, to_user, offset, n);
}
```

- For standard `kmalloc` caches, `s->useroffset = 0` and `s->usersize = s->object_size`.
- When copying 128 bytes from offset 0 of a 64-byte object (`kmalloc-64`), the condition `n (128) > s->usersize (64)` fails and invokes `usercopy_abort()`.

### 3.3 Kernel Text and Stack Protection

1. **Kernel Text Protection (`check_kernel_text_object`)**:
   ```c
   static inline void check_kernel_text_object(const unsigned long ptr,
                                               unsigned long n, bool to_user)
   {
       unsigned long textlow = (unsigned long)_stext;
       unsigned long texthigh = (unsigned long)_etext;

       if (overlaps(ptr, n, textlow, texthigh))
           usercopy_abort("kernel text", NULL, to_user, ptr - textlow, n);
   }
   ```
   - Prohibits copying memory between `_stext` and `_etext` to user space, eliminating arbitrary bytecode disclosure and ROP gadget location extraction.
2. **Abortion Handling (`usercopy_abort`)**:
   - Emits an emergency alert: `pr_emerg("Kernel memory %s attempt detected %s %s ... (offset %lu, size %lu)!\n", ...)`.
   - Calls `BUG()`, triggering kernel Oops handling and killing the rogue process.

---

## 4. Interactive Architecture Simulator

The interactive simulator below contrasts the vulnerable baseline with the hardened kernel behavior during user copy operations:

<iframe src="../../assets/diagrams/hardened-usercopy/architecture.html" width="100%" height="750px" style="border:none; border-radius:8px; overflow:hidden;"></iframe>

---

## 5. Lab Configuration & Build Guide

### 5.1 Kernel Configuration

```ini
# configs/features/hardened-usercopy.config
CONFIG_HARDENED_USERCOPY=y
CONFIG_LKDTM=y
```

### 5.2 Build & Execution Commands

#### ARM64 (aarch64)
```bash
# Boot hardened kernel with automated test
./scripts/run_lab.sh --arch arm64 --feature hardened-usercopy --test test_hardened_usercopy

# Boot baseline vulnerable kernel for comparison
./scripts/run_lab.sh --arch arm64 --feature hardened-usercopy-disabled --test test_hardened_usercopy
```

#### x86_64
```bash
# Boot hardened kernel with automated test
./scripts/run_lab.sh --arch x86_64 --feature hardened-usercopy --test test_hardened_usercopy

# Boot baseline vulnerable kernel for comparison
./scripts/run_lab.sh --arch x86_64 --feature hardened-usercopy-disabled --test test_hardened_usercopy
```

---

## 6. Exploit Verification & Analysis

### 6.1 Unprivileged PoC Exploit (`/bin/exploit_hardened_usercopy`)

Executed as non-root user `lab` (UID 1000) against `/proc/vuln_usercopy`.

#### Hardened Kernel (`CONFIG_HARDENED_USERCOPY=y`) Output
```text
=========================================================
  CONFIG_HARDENED_USERCOPY Proof of Concept Exploit
  UID: 1000 | GID: 1000 | PID: 106
=========================================================

[*] Test 1: Slab Heap Out-of-Bounds Memory Disclosure
[*] Attempting 128-byte copy_to_user from 64-byte SLUB allocation...
[+] [PASS] Child killed by signal 11 (Segmentation fault)!
[+] Protection ACTIVE: CONFIG_HARDENED_USERCOPY caught out-of-bounds copy.
[+] Kernel generated BUG() / usercopy_abort and aborted the exposure.

[*] Test 2: Kernel Code (.text) Disclosure
[*] Attempting copy_to_user directly from kernel function pointer...
[+] [PASS] Child killed by signal 11 (Segmentation fault)!
[+] Protection ACTIVE: Kernel text read blocked by check_kernel_text_object().

=========================================================
  PoC Summary:
  - Slab Heap Boundary Enforcement : PROTECTED
  - Kernel Text Read Enforcement   : PROTECTED
=========================================================
```

#### Kernel Log (`dmesg`)
```text
[   18.102145] vuln_usercopy: attempting copy_to_user(buf, chunk_a, 128) - exceeding 64-byte boundary!
[   18.102380] usercopy: Kernel memory exposure attempt detected from SLUB object 'kmalloc-64' (offset 0, size 128)!
[   18.102610] ------------[ cut here ]------------
[   18.102720] kernel BUG at mm/usercopy.c:102!
[   18.102850] Internal error: Oops - BUG: 00000000f2000800 [#1] PREEMPT SMP
```

#### Baseline Kernel (Disabled) Output
```text
[*] Test 1: Slab Heap Out-of-Bounds Memory Disclosure
    [Child] read() succeeded! Received 128 bytes:
    [Child] Chunk A Header (0-63)   : PUBLIC_CHUNK_A_HEADER: Welcome to Hardened Usercopy Lab!...
    [Child] Chunk B Adjacent (64-127): LEAKED SECRET -> CONFIDENTIAL_KEY_IN_CHUNK_B_9999
[-] [FAIL] Child successfully extracted adjacent heap memory (exit code 42).
[-] Vulnerability CONFIRMED: CONFIG_HARDENED_USERCOPY is NOT active.
```

### 6.2 LKDTM Test Points

Direct testing through the kernel crash driver:
```bash
echo USERCOPY_SLAB_SIZE_TO > /sys/kernel/debug/provoke-crash/DIRECT
echo USERCOPY_KERNEL > /sys/kernel/debug/provoke-crash/DIRECT
```

- **Hardened**: Kernel intercepts the attempt, logs `usercopy: Kernel memory exposure attempt detected`, and raises `BUG()`.
- **Baseline**: Logs `lkdtm: FAIL: bad usercopy not detected!`.

---

## 7. Performance & Production Trade-offs

1. **Performance Overhead**:
   - `__check_object_size()` introduces an overhead of **less than 1%** across standard CPU and I/O workloads.
2. **Whitelisting (`kmem_cache_create_usercopy`)**:
   - For structures where only a subfield needs to be copied to user space, `kmem_cache_create_usercopy()` restricts the accessible window to specific offsets and lengths.
3. **Production Adoption**:
   - Standard security requirement enabled across Android Common Kernel (ACK), Ubuntu, RHEL, and enterprise distributions.

---

## 8. FAQ & Troubleshooting

**Q1: Does the check function if the copy length is a compile-time constant?**
- When sizes are compile-time constants, `__builtin_constant_p()` evaluates sizes at compile-time where possible; variable lengths invoke full runtime object inspection via `check_object_size()`.

**Q2: Are custom slab caches protected automatically?**
- Yes. Slabs created via `kmem_cache_create()` default to `s->usersize = s->object_size`, clamping any copy exceeding the object allocation.

