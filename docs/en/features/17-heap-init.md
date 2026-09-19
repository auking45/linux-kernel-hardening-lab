# Heap Memory Zeroing on Alloc & Free (`CONFIG_INIT_ON_ALLOC` & `CONFIG_INIT_ON_FREE`)

## 1. Overview and Background

Dynamically allocated heap memory in the Linux kernel (SLUB allocator objects and buddy page allocator pages) has historically been returned to callers without initialization to optimize performance. When developers call `kmalloc()` without specifying `kzalloc()` or the `__GFP_ZERO` flag, the allocated memory contains stale residual data left behind by previous kernel subsystems or processes that occupied the same slab slot.

This uninitialized heap memory presents two major security threats:

1. **Uninitialized Kernel Memory Disclosure (CWE-457)**:
   - When structures are allocated and only partially initialized, or when compilers insert uninitialized structure padding bytes for alignment before invoking `copy_to_user()`, stale cryptographic keys, kernel pointers, or confidential tokens leak directly to unprivileged user space.
2. **Use-After-Free (UAF, CWE-416) Exploitation Surface**:
   - Stale sensitive data, such as function pointers or credential tokens, remains in memory after `kfree()`. An attacker possessing a dangling pointer can inspect the freed memory to defeat KASLR or prepare forged object layouts.
   - Furthermore, cold-boot attacks and live physical memory forensics can recover sensitive secrets from recently freed kernel pages.

Linux 6.12 LTS provides two standard Kconfig hardening options to mitigate these risks:
- **`CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`**: Automatically zeroes all slab objects and page allocations upon allocation (`slab_post_alloc_hook`).
- **`CONFIG_INIT_ON_FREE_DEFAULT_ON=y`**: Immediately zeroes slab objects and page allocations upon deallocation (`slab_free_hook`), reducing sensitive data lifetime to zero.

---

## 2. Real-World Analogy: Car Rental Sanitization vs Hotel Checkout Cleaning

The two zeroing mechanisms mirror standard hygiene protocols:

1. **Zero on Allocation (`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`) - Rental Car Sanitization**:
   - **Traditional Kernel**: Returns the rental vehicle to the next customer without cleaning. The vehicle still contains previous drivers' receipts, wallets, or documents (cryptographic keys, pointers).
   - **Hardened Kernel**: The rental agency thoroughly details and vacuums the interior right before handing the keys to the next driver. Regardless of what the previous driver left behind, the new driver receives a pristine vehicle (all `0x00`).
2. **Zero on Free (`CONFIG_INIT_ON_FREE_DEFAULT_ON`) - Immediate Hotel Checkout Cleaning**:
   - **Traditional Kernel**: Leaves the hotel room uncleaned until the next guest checks in. A burglar entering the vacant room (dangling pointer) can easily retrieve valuables left behind under the bed.
   - **Hardened Kernel**: The second a guest checks out (`kfree()`), the cleaning crew immediately strips the bed and clears all safes and drawers. A burglar breaking in later finds only empty rooms (all `0x00`).

---

## 3. Architecture and Implementation Mechanism

### 3.1 Allocation Zeroing (`slab_post_alloc_hook`)

```text
[ kmalloc(256) / kmem_cache_alloc() ]
                │
                ▼
      [ __slab_alloc_node() ]
     (Slot popped from freelist)
                │
                ▼
   [ slab_want_init_on_alloc() ]
   (Evaluates init_on_alloc key)
                │
         ┌──────┴──────┐
       true          false
         │             │
         ▼             ▼
[ memset(p, 0, size) ] [ Uninitialized memory returned ]
(Entire object zeroed)
                │
                ▼
   [ Safe buffer returned to caller ]
```

1. **Static Branch Evaluation**:
   - Evaluated via `want_init_on_alloc(flags)` in `include/linux/mm.h` and `slab_want_init_on_alloc(flags, c)` in `mm/slab.h`.
   - Enabled for all standard slab caches, except caches with explicit constructors (`c->ctor`) or RCU-delayed freeing (`SLAB_TYPESAFE_BY_RCU`).
2. **Slab Post-Alloc Hook**:
   - In `mm/slub.c`, `slab_post_alloc_hook()` calls `memset(p[i], 0, zero_size)` to wipe the newly allocated slot.
   - In `mm/page_alloc.c`, the page allocator calls `kernel_init_pages()` to zero allocated physical pages.

### 3.2 Free Zeroing (`slab_free_hook`)

```text
[ kfree(ptr) / kmem_cache_free() ]
                │
                ▼
      [ slab_free_hook() ]
                │
                ▼
   [ slab_want_init_on_free() ]
   (Evaluates init_on_free key)
                │
         ┌──────┴──────┐
       true          false
         │             │
         ▼             ▼
[ memset(x, 0, orig_size) ] [ Stale memory retained ]
(Excludes SLAB redzones & meta)
                │
                ▼
     [ set_freepointer() ]
    (Enters freelist chain)
```

1. **Immediate Sanitization**:
   - In `mm/slub.c`, `slab_free_hook()` invokes `memset(kasan_reset_tag(x), 0, orig_size)` as soon as `kfree()` is invoked.
   - SLAB redzones and external freelist pointers are preserved to maintain allocator integrity while erasing payload data.
2. **UAF and Forensics Defense**:
   - Dangling pointer reads immediately return zeroes rather than sensitive data.
   - Forensic physical memory dumps cannot recover freed keys or plaintext structures.

---

## 4. Performance and Security Trade-Off Matrix

| Metric | `init_on_alloc` | `init_on_free` | KASAN (Reference) |
| :--- | :--- | :--- | :--- |
| **Sanitization Point** | Allocation (`slab_post_alloc_hook`) | Deallocation (`slab_free_hook`) | Shadow memory tagging |
| **Cache Impact** | **Hot Cache**: Memory touched before write | **Cold Cache**: Memory touched before eviction | Consumes extra cache lines |
| **Runtime Overhead** | **< 1.0%** (most workloads) | **3% ~ 5%** (up to 8% in microbenchmarks) | **~200%** (debug only) |
| **Uninitialized Leakage** | **Complete Prevention (100% Zeroed)**| **Complete Prevention (100% Zeroed)**| Detection only (no wipe) |
| **UAF Dangling Reads** | Stale data visible until reallocated | **Zeroed immediately (Defended)** | Detects and crashes |
| **Production Suitability**| **Strongly Recommended** | Recommended for high-security environments | Development/QA only |

---

## 5. Interactive Architecture Simulator

The interactive simulator illustrates dynamic allocation zeroing waves and Use-After-Free memory sanitization:

- **Simulator Path**: `docs/assets/diagrams/heap-init/architecture.html`
- **Scenarios**:
  1. `Allocation Zeroing`: Step-by-step `kmalloc` pipeline and `0x00` wipe wave.
  2. `Free Zeroing`: Immediate `kfree` sanitization wave erasing object contents.
  3. `Baseline Leakage`: Stale secret data surviving across allocation cycles into user space.
  4. `Comparison Matrix`: Overhead and threat mitigation comparison.

---

## 6. Verification and Testing Guide

### 6.1 Target Driver and User-Space PoC

- **Target Driver**: `/proc/vuln_heap_init` (mode 0666)
- **User-Space PoC**: `/bin/exploit_heap_init` (executed as unprivileged user `lab`)
- **In-Guest Test Runner**: `/bin/test_heap_init`

```bash
# Execute unprivileged PoC
/bin/exploit_heap_init
```

### 6.2 LKDTM Kernel Test Triggers

```bash
mount -t debugfs none /sys/kernel/debug

# 1. Test slab allocation zeroing
echo SLAB_INIT_ON_ALLOC > /sys/kernel/debug/provoke-crash/DIRECT

# 2. Test buddy page allocation zeroing
echo BUDDY_INIT_ON_ALLOC > /sys/kernel/debug/provoke-crash/DIRECT

# 3. Test slab free zeroing
echo READ_AFTER_FREE > /sys/kernel/debug/provoke-crash/DIRECT

# 4. Test buddy page free zeroing
echo READ_BUDDY_AFTER_FREE > /sys/kernel/debug/provoke-crash/DIRECT

# Inspect dmesg output
dmesg | grep -E "lkdtm:.*(initialized|poisoned|FAIL)"
```

- **Hardened Kernel Output**:
  ```text
  lkdtm: Memory appears initialized (0, no earlier values)
  lkdtm: Memory correctly poisoned (0)
  ```
- **Baseline Kernel Output**:
  ```text
  lkdtm: FAIL: Slab was not initialized
  lkdtm: FAIL: Memory was not poisoned!
  ```

---

## 7. Kernel Configuration Guide

### 7.1 Kconfig Configuration (`configs/features/heap-init.config`)

```ini
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_LKDTM=y
```

### 7.2 Boot Parameters

Settings can be overridden dynamically at boot time:
- `init_on_alloc=1` or `init_on_alloc=0`
- `init_on_free=1` or `init_on_free=0`

---

## 8. Conclusion

`CONFIG_INIT_ON_ALLOC_DEFAULT_ON` and `CONFIG_INIT_ON_FREE_DEFAULT_ON` guard both ends of the kernel heap lifecycle, eliminating residual uninitialized data leaks (CWE-457) and shrinking Use-After-Free (CWE-416) attack surfaces with minimal runtime performance impact.

