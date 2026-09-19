# SLAB Freelist Hardening & Randomization

## 1. Overview & Background

The Linux kernel's SLUB (Slab Allocator with Queues) manages high-frequency allocations and deallocations of critical kernel objects (`struct task_struct`, `struct cred`, network socket buffers, `file` descriptors, etc.). Historically, the default design of slab allocators exposed severe security vulnerabilities to heap exploitation:

1. **Deterministic Linear Allocation**:
   - Freshly created slab pages initialized free object lists in contiguous address order (`[0] -> [1] -> [2] -> [3]...`).
   - Attackers relied on this determinism to perform **Heap Grooming / Heap Spraying**: allocating vulnerable buffer A followed immediately by target victim object B (holding sensitive function pointers or credentials), guaranteeing that an overflow in A corrupted B with 100% predictability.
2. **Plaintext Freelist Pointers**:
   - The first 8 bytes of an unallocated slab object stored the raw virtual address of the next free object in cleartext.
   - Attackers exploiting a heap buffer overflow or Use-After-Free (UAF) could overwrite this pointer with an arbitrary target address, causing the next `kmem_cache_alloc()` call to return that target address—achieving full **Freelist Hijacking / Arbitrary Kernel Write**.

Linux 6.12 LTS provides two silicon-independent kernel hardening defenses against these exploit techniques:
- **`CONFIG_SLAB_FREELIST_RANDOM=y`**: Shuffles freelist order upon slab page creation via Fisher-Yates randomization, eliminating predictable allocation order.
- **`CONFIG_SLAB_FREELIST_HARDENED=y`**: Obfuscates the free pointer via an XOR cipher using a per-cache secret cookie and byte-swapping (`ptr ^ s->random ^ swab(ptr_addr)`), trapping corruption and double frees (`BUG_ON`).

---

## 2. Real-World Analogy: Shuffled Lockers & Encrypted Tokens

The mechanisms of SLAB freelist hardening can be compared to bank safety deposit locker allocation:

1. **Freelist Randomization (`CONFIG_SLAB_FREELIST_RANDOM`)**:
   - **Vulnerable Baseline**: Lockers are assigned in strict numerical sequence (1, 2, 3, 4...). An adversary rents locker #1 knowing with certainty that the next victim will receive adjacent locker #2, allowing them to drill through the adjoining wall.
   - **Randomized Hardened**: Locker keys are drawn randomly from a thoroughly shuffled lottery box (e.g., 4, 1, 7, 0...). The attacker cannot predict who will be placed in neighboring lockers, collapsing adjacent overflow attacks.
2. **Freelist Pointer Obfuscation (`CONFIG_SLAB_FREELIST_HARDENED`)**:
   - **Vulnerable Baseline**: Inside each empty locker is an unsealed note reading "Next available locker: 0x1040". An adversary edits the note to "Next available: Vault Door 0xDEAD", tricking the clerk into handing over the master vault.
   - **Obfuscated Hardened**: The note is encrypted using a secret per-branch cipher key (`s->random`) combined with the locker's physical location (`swab(addr)`). If altered by even one bit, the decrypted result becomes unmapped garbage, instantly triggering the bank alarm (`kmem_cache: Free pointer corrupt`).

---

## 3. Core Architecture & Operating Mechanism

### 3.1 Freelist Order Randomization (`CONFIG_SLAB_FREELIST_RANDOM`)

```text
[ Slab Page Allocation ]
         │
         ▼
[ Determine Object Count N ] (e.g. N = 8)
         │
         ▼
[ Fisher-Yates Random Shuffle ]
  Pre-computed random_seq: [3, 0, 6, 1, 4, 7, 2, 5]
         │
         ▼
[ Construct Freelist Links ]
  Head -> Slot 3 -> Slot 0 -> Slot 6 -> Slot 1 -> Slot 4 -> Slot 7 -> Slot 2 -> Slot 5 -> NULL
```

1. **Pre-computed Random Permutations**:
   - When a slab cache is created, `cache_random_seq_create()` generates a pseudo-random permutation array (`s->random_seq`) using Fisher-Yates shuffle.
   - As new pages are assigned from the buddy allocator, `init_cache_random_seq()` and `next_freelist_entry()` link available chunks non-linearly.
2. **Mitigating Heap Grooming**:
   - Successive `kmem_cache_alloc()` calls jump non-contiguously across physical slab slots, preventing attackers from predictably arranging adjacent heap layouts.

### 3.2 Freelist Pointer Obfuscation (`CONFIG_SLAB_FREELIST_HARDENED`)

```text
Encoding (on object free):
  encoded_ptr = ptr ^ s->random ^ swab(ptr_addr)

Decoding (on object allocation):
  decoded_ptr = encoded_ptr ^ s->random ^ swab(ptr_addr)
```

1. **Cryptographic Elements**:
   - `ptr`: Canonical target virtual address of the next free slab object.
   - `s->random`: A 64-bit secret random cookie generated from the kernel CSPRNG per `kmem_cache`.
   - `swab(ptr_addr)`: Endian byte-swap of the pointer storage location, binding metadata to its physical address and preventing cross-location re-use.
2. **Corruption & Double-Free Trapping**:
   - Tampered free pointers decode into non-canonical or unmapped addresses, raising page faults or triggering `kmem_cache: Free pointer corrupt`.
   - `set_freepointer()` executes `BUG_ON(object == fp)`, instantly catching double-free loops before corruption spreads.

---

## 4. Interactive Architecture Diagram

The interactive diagram below illustrates randomized freelist permutations, pointer encoding/decoding transformations, and heap corruption detection:

<iframe src="../../assets/diagrams/slab-freelist/architecture.html" width="100%" height="700px" style="border: 1px solid #334155; border-radius: 8px; margin: 16px 0;"></iframe>

---

## 5. Kernel Configuration

### 5.1 Kconfig Configuration (`configs/features/slab-freelist.config`)

```ini
# Hardening Feature: SLAB Freelist Hardening & Randomization
# Obfuscate free pointers to mitigate freelist hijacking
CONFIG_SLAB_FREELIST_HARDENED=y

# Randomize freelist allocation order per slab page
CONFIG_SLAB_FREELIST_RANDOM=y

# SLUB debugging support
CONFIG_SLUB=y
CONFIG_SLUB_DEBUG=y

# LKDTM validation framework
CONFIG_LKDTM=y
```

---

## 6. Verification & Test Results

### 6.1 Dual-Architecture 4-Scenario Test Matrix

The feature was tested across both x86_64 and arm64 architectures:

| Scenario | Target Arch | Feature Config | Sequential Adjacency Rate | Pointer Obfuscation | LKDTM SLAB_FREE_DOUBLE Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | **ARM64** | `slab-freelist` (Hardened) | <span style="color:#22c55e">**0% (Non-linear)**</span> | <span style="color:#22c55e">**Active (XOR Encoded)**</span> | <span style="color:#22c55e">**BLOCKED (`BUG at mm/slub.c:547`)**</span> |
| **Scenario 2** | **ARM64** | `slab-freelist-disabled` | <span style="color:#ef4444">100% (Linear)</span> | <span style="color:#ef4444">Inactive (Plaintext)</span> | <span style="color:#ef4444">Undetected (Silent pass)</span> |
| **Scenario 3** | **x86_64** | `slab-freelist` (Hardened) | <span style="color:#22c55e">**0% (Non-linear)**</span> | <span style="color:#22c55e">**Active (XOR Encoded)**</span> | <span style="color:#22c55e">**BLOCKED (`BUG at mm/slub.c:547`)**</span> |
| **Scenario 4** | **x86_64** | `slab-freelist-disabled` | <span style="color:#ef4444">Linear (Deterministic)</span> | <span style="color:#ef4444">Inactive (Plaintext)</span> | <span style="color:#ef4444">Undetected (Silent pass)</span> |

### 6.2 Hardened Verification Log (Double Free Trapped)

```text
[Test 1/2] Real-World SLUB Freelist Hardening PoC
[*] CONFIG_SLAB_FREELIST_RANDOM: ENABLED
[*] Sequential Adjacency Rate:   0% (0/7 matches)
[*] Allocation Sample Offsets:
    [0] 0xffff000000d9a300
    [1] 0xffff000000d9a1c0
    [2] 0xffff000000d9afc0
    [3] 0xffff000000d9adc0
[+] DEFENSE ACTIVE: Freelist layout is randomized via Fisher-Yates shuffle.

[*] CONFIG_SLAB_FREELIST_HARDENED: ENABLED
[*] Pointer Obfuscated:            YES
[+] DEFENSE ACTIVE: Free pointer is obfuscated: ptr ^ cookie ^ swab(addr)

[Test 2/2] Triggering LKDTM SLAB_FREE_DOUBLE Test
[    4.520918] kernel BUG at mm/slub.c:547!
[    4.535371] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP
[    4.538302] pc : kmem_cache_free+0x280/0x2d8
[    4.552237] lr : lkdtm_SLAB_FREE_DOUBLE+0x5c/0x7c
[+] CONFIG_SLAB_FREELIST_HARDENED immediately trapped double-free via BUG_ON(object == fp)!
```

---

## 7. Security Benefits & Trade-offs

### 7.1 Security Benefits
1. **Neutralizes Heap Grooming**: Disrupts reliable placement of attacker-controlled buffers next to sensitive victim structures.
2. **Prevents Freelist Hijacking**: Overwritten free pointers fail to decode into attacker addresses, neutralizing arbitrary write primitives.
3. **Instant Double Free Trapping**: Catches recurring free calls immediately with zero latency.

### 7.2 Trade-offs
1. **Negligible Overhead**: Shuffling occurs once per slab page creation; pointer encoding/decoding is a lightweight XOR and swab (< 0.5% CPU overhead).
2. **Page-Local Randomization**: Randomization is bounded within individual slab pages; inter-page layout randomization relies on page allocator features.

---

## 8. Conclusion

`CONFIG_SLAB_FREELIST_RANDOM` and `CONFIG_SLAB_FREELIST_HARDENED` deliver essential baseline protection against modern heap exploitation with minimal runtime overhead and zero memory footprint increase.
