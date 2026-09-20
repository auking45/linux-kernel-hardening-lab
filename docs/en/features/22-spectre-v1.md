# Spectre v1: Bounds Check Bypass & array_index_nospec Defense

## 1. Overview & Technical Background

Modern high-performance microprocessors utilize **Branch Prediction** and **Out-of-Order Speculative Execution** to prevent execution pipeline stalls caused by memory latency. When confronting conditional branches (e.g., `if (index < size)`), the CPU predicts the branch outcome based on the branch history table before resolving the condition and speculatively executes subsequent instructions.

Publicly disclosed in 2018, **Spectre Variant 1 (Bounds Check Bypass - CVE-2017-5753)** is a microarchitectural side-channel vulnerability exploiting this speculative execution engine:
1. **Branch Predictor Mistraining**:
   - An unprivileged attacker repeatedly invokes a code path with valid, in-bounds inputs (`index < size`), training the Branch Target Buffer (BTB) and Pattern History Table (PHT) to predict the branch as "Taken".
2. **Transient Out-of-Bounds Load**:
   - The attacker supplies a malicious out-of-bounds offset (`index >= size`, pointing to arbitrary kernel secret memory) while causing a memory stall on the boundary variable.
   - The CPU mispredicts the branch as Taken, speculatively executing subsequent memory loads. It reads the secret byte (`secret = array1[index]`) and uses it as an offset into a secondary probe array (`probe_array[secret * 512]`), bringing that specific cache line into the CPU cache hierarchy.
3. **Cache State Persistence & Secret Recovery (Flush+Reload)**:
   - When the branch condition resolves as False, the CPU rolls back architectural register state, but the **microarchitectural state (CPU cache lines) remains warm**.
   - The attacker measures access latencies across the secondary probe array in user space using high-resolution timers (`rdtsc` / `cntvct_el0`). The cache line exhibiting low latency (Cache Hit) reveals the secret byte value.

The Linux kernel addresses this transient execution hazard by providing **`array_index_nospec()`** from **`<linux/nospec.h>`** as the standard software and hardware defense mechanism.

---

## 2. Real-World Analogy: Eager Library Clerk and Warm Bookshelves

The operation of `Spectre v1` and `array_index_nospec` can be compared to an **over-eager clerk in a classified library archive**:

```
[ Vulnerable Approach (Baseline: Standard Bounds Check) ]
  Attacker: "I'd like to check out document #500 (Classified Vault)!"
  Clerk: (Identity verification is slow, so based on past requests, rushes to the vault)
         ──► [Reads Top-Secret File] ──► [Leaves book on desk, warming the wood]
  Identity Verification Finishes: "Access Denied! Return book to shelf." (Checkout cancelled)
  Attacker: "Measuring desk surface temperature reveals Document #500 was touched! Secret leaked!"

[ Hardened Approach (Hardened: array_index_nospec) ]
  Attacker: "I'd like to check out document #500!"
  Clerk: (Applies hardware arithmetic mask before moving: 500 & 0 = 0)
         ──► [Only checks Public Notice #0] ──► [Vault area remains completely untouched]
  Identity Verification Finishes: "Access Denied! Request rejected."
  Attacker: "Measuring surface temperature reveals zero warmth from the vault (0 bytes leaked)!"
```

1. **Vulnerable Kernel (Eager Clerk Leaving Thermal Traces)**:
   - While the badge validation check is pending in memory, the clerk eagerly fetches the classified document and places it on the desk. Even though the request is later denied and the document returned, the thermal footprint on the desk (CPU cache line) reveals the secret.
2. **Hardened Kernel via array_index_nospec (Arithmetic Clamping)**:
   - Before taking any step toward memory, the index is clamped via a CPU arithmetic mask. Out-of-bounds inputs collapse to index 0. The speculative engine only touches public index 0, leaving the classified vault completely cold and untraceable.

---

## 3. Core Architecture & Defense Mechanism

### 3.1 Vulnerable Gadget Pattern

Spectre v1 vulnerabilities arise whenever an array access follows a conditional bounds check without speculative barriers:

```c
// Vulnerable kernel gadget pattern
if (user_index < array1_size) {
    // Step 1: Speculative out-of-bounds load while bounds check is stalled
    uint8_t secret = array1[user_index];
    // Step 2: Secret-dependent secondary cache line access
    uint8_t val = probe_array[secret * 512];
}
```

- When the attacker provides `user_index >= array1_size`, the mistrained branch predictor speculatively predicts the branch as taken.
- The 512-byte stride prevents hardware spatial prefetchers from warming adjacent cache lines, isolating the exact cache line corresponding to `secret`.

### 3.2 The array_index_nospec() Macro

Defined in `<linux/nospec.h>`, `array_index_nospec()` sanitizes array indices immediately following bounds checks:

```c
#define array_index_nospec(index, size)					\
({									\
	typeof(index) _i = (index);					\
	typeof(size) _s = (size);					\
	unsigned long _mask = array_index_mask_nospec(_i, _s);		\
									\
	(typeof(_i)) (_i & _mask);					\
})
```

- `array_index_mask_nospec()` computes a mask using **CPU arithmetic data dependency** instead of conditional branching:
  - When `index < size`: `mask = ~0UL` (`0xFFFFFFFFFFFFFFFF`), producing `index & mask == index`.
  - When `index >= size`: `mask = 0UL` (`0x0000000000000000`), producing `index & mask == 0`.

### 3.3 Architecture-Specific Hardware Instructions

| Architecture | Assembly Implementation (`asm volatile`) | Speculation Barrier | Performance Impact |
| :--- | :--- | :--- | :--- |
| **x86_64** | `cmp %1, %2; sbb %0, %0` | `barrier_nospec()` (`lfence`) | Uses `sbb` (Subtract with Borrow) to copy carry flag into mask register (< 1% overhead) |
| **ARM64 (aarch64)** | `cmp %1, %2; sbc %0, xzr, xzr` | **`csdb` (hint #20)** | Uses `sbc` for arithmetic mask, followed by Control Speculation Data Barrier (`csdb`) |

- **x86 `sbb` Technique**: On `cmp idx, sz`, if `idx < sz`, the carry flag (CF) is set to 1, causing `sbb dst, dst` to compute `0 - 0 - 1 = -1` (`~0UL`). If `idx >= sz`, CF is 0, yielding `0`. The out-of-order execution engine cannot determine the address of `array1[safe_idx]` until the subtraction completes, preventing out-of-bounds address generation.
- **ARM64 `csdb` Technique**: The **Control Speculation Data Barrier** instruction (`hint #20`) introduced in ARMv8-A ensures that data-dependent speculative loads cannot proceed until the preceding conditional evaluation completes.

---

## 4. Interactive Architecture Simulator

An interactive architecture simulator depicting the Spectre v1 bypass mechanism and `array_index_nospec` defense:

<iframe src="../../assets/diagrams/spectrev1/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. Hands-on Lab & Exploit Demonstration

### 5.1 Vulnerability Lab Driver (`vuln_spectrev1.c`)

The `/proc/vuln_spectrev1` interface provides:
- **Status & Mitigation Telemetry (`cat /proc/vuln_spectrev1`)**:
  - Displays CPU architecture and arithmetic masking instruction details (`sbb` vs `sbc+csdb`).
  - Active mode: `[0] Baseline (Vulnerable)` vs `[1] Hardened (array_index_nospec)`.
  - Public array size (16B), secret offset distance (+16B), and secondary probe physical address/stride.
  - Leak count and defense interception statistics.
- **Mode Switching**:
  - `echo 'mode baseline' > /proc/vuln_spectrev1`: Enables unmitigated branch gadget.
  - `echo 'mode hardened' > /proc/vuln_spectrev1`: Enables `array_index_nospec()` protection.
- **Direct Userland Flush+Reload via `mmap`**:
  - Maps the 128KB secondary probe array into user virtual memory for cycle-accurate Flush+Reload measurement.
- **In-Kernel Benchmark (`echo run_bench > /proc/vuln_spectrev1`)**:
  - Executes 30 rounds of branch mistraining and speculative OOB access within kernel space, verifying cache timing leakage.

### 5.2 Unprivileged Flush+Reload Exploit PoC (`exploit.c`)

Executed as non-privileged user `lab` (UID 1000):
1. **Dual-Architecture Cycle Timing**:
   - x86_64: `rdtscp` serialized cycle reading.
   - ARM64: `cntvct_el0` (Virtual Count Register) synchronized with `isb`.
2. **Branch Predictor Mistraining**:
   - Loops with in-bounds indices (0..15) 5 times, then injects target secret offset (+16).
3. **Verification**:
   - **Baseline Mode**: Recovers `FLAG` bytes ('F', 'L', 'A', 'G') via short cache hit latencies (52~70 cycles) (`[FAIL/VULNERABLE]`).
   - **Hardened Mode**: Indices are clamped to 0; all probe lines register cache misses (> 200 cycles) with 0 leaked bytes (`[PASS/PROTECTED]`).

---

## 6. Verification & Results

### 6.1 Automated Guest Test Execution

Execute the in-guest verification suite:

```bash
/bin/test_spectre_v1
```

### 6.2 Sysfs Vulnerability Interface

Verify system-level mitigation status:

```bash
cat /sys/devices/system/cpu/vulnerabilities/spectre_v1
# Output: Mitigation: __user pointer sanitization
```

### 6.3 Dual-Architecture QEMU 4-Scenario Matrix

| Scenario | Architecture | Mode | Secret Leaked | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | ARM64 | Mode 1 (Hardened) | 0 bytes (All cache misses) | **PASS (Protected)** |
| **Scenario 2** | ARM64 | Mode 0 (Baseline) | 'F', 'L', 'A', 'G' recovered | **VULNERABLE (Demonstrated)** |
| **Scenario 3** | x86_64 | Mode 1 (Hardened) | 0 bytes (`sbb` clamped) | **PASS (Protected)** |
| **Scenario 4** | x86_64 | Mode 0 (Baseline) | 'F', 'L', 'A', 'G' recovered | **VULNERABLE (Demonstrated)** |

