# STRUCTLEAK / INIT_STACK_ALL_ZERO: Uninitialized Stack Structure Disclosure Mitigation

## 1. Overview and Threat Model

In the C programming language used across the Linux kernel, local stack variables are uninitialized upon entering a function frame. Unless developers explicitly perform `memset()` or assign `{0}` initializers, the allocated stack frame retains whatever dirty residual data was left by previous function calls (kernel function pointers, stack canaries, encryption keys, and heap addresses).

Kernel data structures suffer from two critical security blind spots regarding stack memory:
1. **Alignment Padding Hole Exposures**:
   - On 64-bit architectures (x86_64, aarch64), natural memory alignment rules mandate that when a 4-byte integer precedes an 8-byte pointer or timestamp, the compiler inserts a 4-byte padding hole between them.
   - Even when a programmer explicitly initializes every visible struct member (`s.header = 1; s.timestamp = t;`), **the compiler-generated padding hole is never assigned and retains dirty kernel stack memory**.
   - When this structure is subsequently copied to user space via `copy_to_user()`, sensitive pointers or canaries residing in the padding hole leak into user space, defeating KASLR or enabling arbitrary control flow hijack attacks (e.g. CVE-2013-2141).
2. **Suppression of Uninitialized Warnings on By-Reference Calls**:
   - When a pointer to a stack-allocated structure is passed into a helper subroutine (`helper_init(&info)`), the compiler suppresses uninitialized variable warnings (`-Wmaybe-uninitialized`) under the assumption that the callee initializes the structure.
   - If the helper only populates a subset of members and returns, the remaining fields leak residual stack data to userspace (e.g. CVE-2017-1000410).

Historically, the Linux kernel mitigated this with the PaX/Grsecurity GCC plugin **`CONFIG_GCC_PLUGIN_STRUCTLEAK`**. In modern Linux kernels (v6.x LTS) and toolchains (GCC 12+, Clang 12+), this has been superseded and standardized into the native compiler flag **`CONFIG_INIT_STACK_ALL_ZERO=y` (`-ftrivial-auto-var-init=zero`)**.

---

## 2. Real-World Analogy: Reusing Scrap Paper Forms

The principle of `STRUCTLEAK` and automatic stack zeroing can be compared to office paperwork policies regarding scrap paper:

```
[ Vulnerable Approach (Baseline: CONFIG_INIT_STACK_NONE) ]
  Printing an official form on the back of confidential meeting minutes (dirty stack memory)
  ┌────────────────────────────────────────────────────────┐
  │ [Header: Filled OK] │ [Blank Margin (Padding): Secret!]│ [Body: Filled]│
  └────────────────────────────────────────────────────────┘
                           │ (Handed directly to an external visitor)
                           ▼
              Visitor holds form to light and steals secrets!

[ Hardened Approach (Hardened: CONFIG_INIT_STACK_ALL_ZERO) ]
  Always taking a brand new, clean sheet of white paper (0x00 zeroed)
  ┌────────────────────────────────────────────────────────┐
  │ [Header: Filled OK] │ [Blank Margin (Padding): Clean 0]│ [Body: Filled]│
  └────────────────────────────────────────────────────────┘
                           │ (Handed to external visitor)
                           ▼
                  Safe: Zero residue in margins!
```

1. **Baseline Kernel (Scrap Paper Policy)**:
   - When a function begins, the kernel reuses previous stack frames without erasing them.
   - Only explicitly assigned fields are overwritten. Margins (alignment padding holes) and untouched fields leak prior secrets (kernel addresses and canary values) directly to user space.
2. **STRUCTLEAK / INIT_STACK_ALL_ZERO (Clean Sheet Policy)**:
   - At the function prologue, the compiler emits instructions to zero out the entire local stack frame to `0x00` before any user code executes.
   - Any gaps, padding holes, or skipped fields are guaranteed to be clean zeroes, completely eliminating information disclosure channels.

---

## 3. Architecture and Implementation Details

### 3.1 The Alignment Padding Hole Mechanism

On 64-bit systems, structure layout adheres to strict alignment:

```c
struct demo_padding_leak {
    uint32_t header;       /* 4 bytes (offset 0..3) */
    /* [Padding Hole] 4 bytes (offset 4..7) inserted by compiler for 8-byte alignment */
    uint64_t timestamp;    /* 8 bytes (offset 8..15) */
    char msg[16];          /* 16 bytes (offset 16..31) */
};
```

Even if every named field is initialized:
```c
struct demo_padding_leak s;
s.header = 0x44454d4f;
s.timestamp = get_timestamp();
strncpy(s.msg, "STATUS_OK", 16);
copy_to_user(user_buf, &s, sizeof(s));
```
C standard rules do not require member assignment to initialize structure padding. Thus, bytes 4..7 contain residual stack contents, transmitted raw across the user boundary.

### 3.2 Compiler-Level Zeroing (`CONFIG_INIT_STACK_ALL_ZERO`)

With `-ftrivial-auto-var-init=zero`, the compiler emits prologue code clearing all stack frames:

#### ARM64 Assembly:
Using the 64-bit zero register `xzr` to zero 16-byte pairs:
```assembly
// Function Prologue (ARM64)
sub  sp, sp, #32             // Allocate 32-byte frame
stp  xzr, xzr, [sp]          // Zero bytes 0..15
stp  xzr, xzr, [sp, #16]     // Zero bytes 16..31
// Proceed with member assignment
```

#### x86_64 Assembly:
Using SSE/AVX 128-bit vector instructions or string operations:
```assembly
// Function Prologue (x86_64)
subq  $32, %rsp              // Allocate 32-byte frame
xorps %xmm0, %xmm0           // Clear xmm0 vector register
movaps %xmm0, (%rsp)         // Zero bytes 0..15
movaps %xmm0, 16(%rsp)       // Zero bytes 16..31
```

All bytes, including padding holes and skipped fields, start strictly at `0x00`.

### 3.3 Historical Evolution: GCC Plugin vs Native Flag

| Attribute | Legacy `CONFIG_GCC_PLUGIN_STRUCTLEAK` | Modern `CONFIG_INIT_STACK_ALL_ZERO` |
| :--- | :--- | :--- |
| **Technology** | Out-of-tree GCC plugin (PaX/Grsecurity) | Native compiler flag (`-ftrivial-auto-var-init=zero`) |
| **Scope** | `_USER`: `__user` annotated structs<br>`_BYREF`: By-ref passed structs<br>`_BYREF_ALL`: By-ref all vars | **All local variables, arrays, structures, and padding** |
| **Compiler Support** | GCC only (requires plugin development headers) | GCC 12+ and Clang 12+ native support |
| **Status** | Maintained for legacy kernels | Standard on modern enterprise, cloud, and mobile distributions |

---

## 4. Interactive Architecture Simulator

Below is the dynamic interactive diagram visualizing alignment padding leak mechanics and compiler stack zeroing:

<iframe src="../../assets/diagrams/structleak/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. Lab Hands-On and Exploit PoC

### 5.1 Vulnerability Driver (`vuln_structleak.c`)

Exposes `/proc/vuln_structleak` (mode 0666) with two distinct verification modes:
- **Mode 1 (`echo 1 > /proc/vuln_structleak`)**:
  - Pre-dirties caller stack with poison marker `0x53544b5f4c45414b` ("STK_LEAK").
  - Allocates `struct demo_padding_leak` (32 bytes).
  - Initializes header, timestamp, and message, but leaves the 4-byte padding hole untouched.
  - Copies structure to userspace via `copy_to_user()`.
- **Mode 2 (`echo 2 > /proc/vuln_structleak`)**:
  - Allocates `struct demo_byref_leak` (48 bytes) and passes pointer to a helper.
  - Helper only sets command and status, leaving secret and canary fields untouched.

### 5.2 Unprivileged Userland Exploit PoC (`exploit.c`)

Executed as non-privileged user `lab` (UID 1000):
```bash
/bin/exploit_structleak
```
- **Baseline (Vulnerable)**:
  - Detects `0x53544b5f` inside the padding hole (offset 4..7).
  - Detects leaked stack tokens inside by-reference fields.
  - Exits with return code `42`.
- **Hardened (Protected)**:
  - Confirms padding hole and untouched fields are strictly `0x00000000`.
  - Exits with return code `0`.

---

## 6. Dual-Architecture Verification Matrix

| Architecture | Kernel Configuration | Padding Hole (Offset 4..7) | By-Ref Untouched Fields | Result |
| :--- | :--- | :--- | :--- | :--- |
| **ARM64** | `CONFIG_INIT_STACK_ALL_ZERO=y` | 🛡️ **0x00000000 (Clean)** | 🛡️ **0x00000000 (Clean)** | ✅ **PASS (Protected)** |
| **ARM64** | `CONFIG_INIT_STACK_NONE=y` | ❌ **0x53544b5f (Leaked)** | ❌ **Dirty Stack Leaked** | ⚠️ **FAIL (Vulnerable)** |
| **x86_64** | `CONFIG_INIT_STACK_ALL_ZERO=y` | 🛡️ **0x00000000 (Clean)** | 🛡️ **0x00000000 (Clean)** | ✅ **PASS (Protected)** |
| **x86_64** | `CONFIG_INIT_STACK_NONE=y` | ❌ **0x53544b5f (Leaked)** | ❌ **Dirty Stack Leaked** | ⚠️ **FAIL (Vulnerable)** |

---

## 7. Production Guidelines and Trade-offs

1. **Performance Cost**:
   - Microbenchmarks show approximately **0.5% to 1.5% CPU overhead** due to prologue zeroing instructions.
   - Vector store instructions (`stp xzr` / `movaps`) and CPU store buffers mitigate real-world latency, making impact imperceptible on production services.
2. **Comparison with Pattern Initialization (`INIT_STACK_ALL_PATTERN`)**:
   - Pattern initialization (`0xAA`/`0xFF`) is valuable for debugging, but in production can trigger immediate dereference panics (denial-of-service).
   - Zero-initialization produces safe defaults (`NULL` pointers, string terminator `\0`, length 0), making it the optimal production mitigation.
3. **Recommendation**:
   - Strongly recommend enabling `CONFIG_INIT_STACK_ALL_ZERO=y` across all hardened kernel builds.

