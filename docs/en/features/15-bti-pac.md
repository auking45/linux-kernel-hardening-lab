# ARM64 BTI & PAC (Branch Target Identification & Pointer Authentication Code)

## 1. Overview & Background

In ARM64 (AArch64) mobile (Android/iOS), enterprise server (Neoverse), and embedded ecosystems, memory corruption vulnerabilities targeting control flow hijacking remain a critical security concern. Attackers systematically combine **JOP/COP (Jump/Call-Oriented Programming)**—hijacking function pointers via heap overflows or use-after-free (UAF)—with **ROP (Return-Oriented Programming)** targeting stack frame return addresses (LR).

While software-based CFI mechanisms (e.g., Clang KCFI) protect forward-edge indirect calls with type hashes, they incur linking constraints and cannot prevent stack return address overwrites. To solve this at the silicon level, Arm introduced architectural hardware extensions to the ISA:

1. **ARMv8.5-A BTI (Branch Target Identification)**:
   - Enforces forward-edge Control Flow Integrity (CFI) directly inside the processor pipeline.
   - On indirect branches (`BLR`, `BR`), validates that the target landing instruction is an authorized landing pad (`bti c`, `paciasp`, etc.).
2. **ARMv8.3-A PAC (Pointer Authentication Code)**:
   - Enforces backward-edge Control Flow Integrity (CFI) using cryptographic signatures.
   - On function prologue, signs the return address (LR/x30) using an internal secret key and stores the cryptographic tag in unused upper virtual address bits, verifying it on return to eliminate ROP attacks.

Linux 6.12 LTS provides full enterprise-grade enforcement via `CONFIG_ARM64_BTI_KERNEL=y` and `CONFIG_ARM64_PTR_AUTH_KERNEL=y`.

---

## 2. Real-World Analogy: Security Badge Gate & Cryptographic Notary Seal

The dual defense of ARM64 BTI and PAC can be illustrated through high-security facility access and classified document authorization:

1. **BTI (Forward-Edge Landing Gate)**:
   - **Vulnerable Baseline**: A visitor (indirect call `BLR`) is allowed through any door or window. If an attacker directs execution into the middle of a function or gadget, the CPU treats it as legitimate code.
   - **BTI Hardened**: Every legitimate entrance is marked with an authorized "BTI Landing Pad". When an indirect branch occurs, the CPU enters `PSTATE.BTYPE` guard mode. If the destination's first instruction is not an authorized landing pad (`bti c` or `paciasp`), the CPU immediately raises an `Oops - BTI` exception and terminates the process.
2. **PAC (Backward-Edge Cryptographic Notary)**:
   - **Vulnerable Baseline**: An employee's departure pass (return address LR) is stored in plain text on an open table (the stack). An attacker can easily rewrite the destination address to jump to an arbitrary gadget.
   - **PAC Hardened**: Before storing the pass on the stack, the CPU notarizes the upper bits with an unforgeable cryptographic signature (`paciasp`) using internal secret Key A and stack pointer SP. Upon return, `autiasp` validates the signature; if corrupted by even 1 bit, an immediate `Oops - FPAC` exception halts execution.

---

## 3. Core Architecture & Operating Principles

### 3.1 ARM64 BTI (Forward-Edge CFI) Architecture

```text
[ Indirect Branch: BLR Xn / BR Xn ]
                 │
                 ▼
     [ CPU Hardware PSTATE ]
     Set PSTATE.BTYPE = 0b10 (Call)
     Page Check: PTE_GP (Guarded Page)
                 │
         ┌───────┴───────┐
         ▼               ▼
   [ First Target Insn ]   [ First Target Insn ]
   == bti c (0xd503245f)   != BTI Landing Pad
   or paciasp (0xd503233f) (e.g. stp x29, x30...)
         │               │
         ▼               ▼
  [ BTYPE Cleared to 00 ] [ Branch Target Exception ]
  Execution Continues     ESR_EL1.EC = 0x0D
                          -> Kernel Oops - BTI
                          -> Process Terminated
```

1. **PSTATE.BTYPE State Machine**:
   - `0b00`: Normal execution (not awaiting an indirect branch target).
   - `0b01`: Following an indirect jump via general register (`BR Xn`, except X16/X17). Permits `bti j` or `bti jc`.
   - `0b10`: Following an indirect call (`BLR Xn` or `BR X16/X17`). Permits `bti c`, `bti jc`, `paciasp`, or `pacibsp`.
   - `0b11`: Reserved.
2. **Dual-Role Landing Pad (`paciasp`)**:
   - The `paciasp` instruction (`0xd503233f`) acts simultaneously as a PAC Key A signing instruction and an implicit `bti c` landing pad.
   - In functions where both BTI and PAC are enabled, Clang generates `paciasp` at entry, avoiding the overhead of separate `bti c` instructions.
3. **PTE Guarded Page (`PTE_GP`) Attribute**:
   - ARMv8.5 BTI operates on pages marked with bit 50 (`GP` - Guarded Page) in the page table descriptors (`PTE_MAYBE_GP`).

### 3.2 ARM64 PAC (Backward-Edge CFI) Architecture

```text
64-bit Virtual Address with PAC Layout (TBI enabled):
┌───────────┬─────────────┬───────────────────────────────────────────┐
│ Bits 63   │ Bits 62..48 │ Bits 47..0                                │
│ Sign Ext  │ PAC Tag     │ Canonical Virtual Memory Address          │
└───────────┴─────────────┴───────────────────────────────────────────┘
     ▲             ▲                            ▲
     │             │                            │
     └────── PACIASP computes tag ──────────────┘
            using Key A (128-bit secret) + SP (Modifier)
```

1. **Pointer Signing (`paciasp`)**:
   - In 64-bit virtual address architectures, upper bits (e.g., bits 54:48) are unused by page translation.
   - `paciasp` uses an on-chip cryptographic engine (QARMA or PAC-GA) with 128-bit secret `Key A` and `SP` as a context modifier to calculate and insert a cryptographic tag into these bits.
2. **Pointer Authentication (`autiasp`)**:
   - Upon function epilogue, `autiasp` recalculates the expected signature.
   - **Valid**: The signature is stripped, restoring the canonical return address for `ret`.
   - **Invalid**: An error code is injected into the upper address bits (or on ARMv8.6 FPAC hardware, raises `ESR_EL1.EC=0x1C` / `Oops - FPAC`), causing an immediate fault upon dereference or return.

---

## 4. Interactive Architecture Diagram

The interactive diagram below visualizes ARM64 BTI forward-edge verification, PAC backward-edge cryptographic signing, baseline vulnerability comparison, and the architectural comparison with x86 Intel CET:

<iframe src="../../assets/diagrams/bti-pac/architecture.html" width="100%" height="700px" style="border: 1px solid #334155; border-radius: 8px; margin: 16px 0;"></iframe>

---

## 5. Kernel Configuration & Toolchain Requirements

### 5.1 Kconfig Configuration (`configs/features/bti-pac.config`)

```ini
# Hardening Feature: ARM64 BTI & PAC
# Enable userspace and kernel Pointer Authentication
CONFIG_ARM64_PTR_AUTH=y
CONFIG_ARM64_PTR_AUTH_KERNEL=y

# Enable userspace and kernel Branch Target Identification
CONFIG_ARM64_BTI=y
CONFIG_ARM64_BTI_KERNEL=y

# LKDTM validation framework
CONFIG_LKDTM=y
```

### 5.2 Toolchain Requirements & LLVM Build Flag

- **GCC Bug 106671 Workaround**: Upstream Linux 6.12 `arch/arm64/Kconfig` specifies `depends on !CC_IS_GCC` for `CONFIG_ARM64_BTI_KERNEL` due to GCC Bug 106671. Therefore, `scripts/build_kernel.sh` automatically compiles ARM64 BTI/PAC kernels using Clang 18 (`LLVM=1`).
- **Compiler Flags**: Clang applies `-mbranch-protection=pac-ret+leaf+bti`, automatically emitting `paciasp` (`0xd503233f`) or `bti c` (`0xd503245f`) in prologues and `autiasp` (`0xd50323bf`) in epilogues.

---

## 6. Verification & Test Results

### 6.1 Dual-Architecture 4-Scenario Test Matrix

All 4 scenarios were compiled and verified live inside QEMU 8.2:

| Scenario | Target Arch | Build Feature | Forward BTI (JOP Defense) | Backward PAC (ROP Defense) | LKDTM CFI_BACKWARD Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | **ARM64** | `bti-pac` (Hardened) | <span style="color:#22c55e">**BLOCKED** (`Oops - BTI`)</span> | <span style="color:#22c55e">**BLOCKED** (`Oops - FPAC`)</span> | <span style="color:#22c55e">**PASS: Trapped by FPAC**</span> |
| **Scenario 2** | **ARM64** | `bti-pac-disabled` | <span style="color:#ef4444">VULNERABLE (`NOBTI_EXECUTED`)</span> | <span style="color:#ef4444">VULNERABLE (Unsigned)</span> | <span style="color:#ef4444">VULNERABLE: `FAIL: redirected!`</span> |
| **Scenario 3** | **x86_64** | `bti-pac` (Hardened) | Architecture contrast notice | Architecture contrast notice | Points to x86 CET (Lab 14) |
| **Scenario 4** | **x86_64** | `bti-pac-disabled` | Architecture contrast notice | Architecture contrast notice | Baseline unhardened |

### 6.2 Scenario 1: ARM64 Hardened Live Log (`Image` 5.9MB)

```text
[Step 2A] Triggering legitimate indirect call (with BTI/PAC landing pad)...
[+] Result: LEGIT_SUCCESS (Total calls: 1)

[Step 2B] Triggering indirect call to target lacking BTI landing pad...
[    4.321017] Internal error: Oops - BTI: 0000000036000002 [#1] SMP
[    4.327997] CPU: 0 UID: 1000 PID: 48 Comm: exploit_bti_pac Not tainted 6.12.109 #1
[    4.331037] pstate: 61400805 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=-c)
[    4.341288] pc : bti_nobti_target+0x0/0x54
[    4.346606] lr : bti_dispatch_call+0x34/0x44
[    4.388245] Code: 9401b342 a8c17bfd d50323bf d65f03c0 (a9be7bfd)
[+] ARM64 BTI trapped invalid branch target before first instruction executed!

[Test 2/2] Triggering LKDTM CFI_BACKWARD Test
[    4.689924] lkdtm: Attempting unchecked stack return address redirection ...
[    4.690729] lkdtm: ok: redirected stack return address.
[    4.691675] lkdtm: Attempting checked stack return address redirection ...
[    4.692970] Internal error: Oops - FPAC: 0000000072000000 [#2] SMP
[    4.700042] pc : set_return_addr+0x28/0x44
[    4.761848] Code: eb00011f 540000a1 f90007a2 a8c17bfd (d50323bf)
[+] autiasp (0xd50323bf) detected corrupted return address and generated Oops - FPAC!
```

### 6.3 Scenario 2: ARM64 Baseline Live Log (`Image` 5.8MB)

```text
[Step 2B] Triggering indirect call to target lacking BTI landing pad...
[*] Result: NOBTI_EXECUTED (Total calls: 2)
[    1.855738] [vuln_bti_pac] [!] VULNERABLE: Function without BTI landing pad executed!
[    1.855765] [vuln_bti_pac] [!] Control flow redirected to non-BTI target: val=0xdeadbeef

[Test 2/2] Triggering LKDTM CFI_BACKWARD Test
[    2.004013] lkdtm: Attempting checked stack return address redirection ...
[    2.004097] lkdtm: FAIL: stack return address was redirected!
[    2.005578] lkdtm: This is probably expected, since this kernel was built *without* CONFIG_ARM64_PTR_AUTH_KERNEL=y
```

---

## 7. Architectural Comparison: ARM64 vs x86_64 Intel CET

| Feature | ARM64 (BTI + PAC) | x86_64 (Intel CET IBT + SHSTK) |
| :--- | :--- | :--- |
| **Forward Defense** | Branch Target Identification (BTI) | Indirect Branch Tracking (IBT) |
| **Landing Pad Instruction** | `bti c` (`0xd503245f`) or `paciasp` (`0xd503233f`) | `endbr64` (`0xfa1e0ff3`) |
| **Backward Defense** | Pointer Authentication Code (PAC) | Shadow Stack (SHSTK) |
| **Implementation** | In-band cryptographic tag in upper address bits | Hardware-isolated physical shadow stack page |
| **Memory Overhead** | **0% (Zero additional memory)** | 100% duplicate stack allocation |
| **Bus Traffic Overhead** | None (internal CPU register arithmetic) | Extra memory read/write per CALL/RET |
| **Scope of Protection** | Return addresses, function pointers, data pointers | Return address (RIP) only |
| **Hardware Exception** | `Oops - BTI (0x0D)` / `Oops - FPAC (0x1C)` | `#CP (Interrupt 21, Error Code 3)` |

---

## 8. Security Benefits & Trade-offs

### 8.1 Benefits
1. **Disrupts ROP/JOP Exploit Chains**: Eliminates code-reuse gadget chaining by enforcing silicon-level branch target validation.
2. **Zero Memory Footprint**: No secondary memory allocation required, making it ideal for mobile and memory-constrained devices.
3. **Broad Pointer Protection**: PAC can protect arbitrary function pointers and data structures (`pacia`, `pacda`) beyond return addresses.

### 8.2 Trade-offs
1. **Hardware & Compiler Prerequisites**: Requires ARMv8.3/v8.5 silicon and modern Clang 18+ toolchains.
2. **Cycle Overhead**: Cryptographic signing/authentication introduces an estimated 1-2% performance overhead.

---

## 9. Conclusion & Future Roadmap (MTE / AVF / CCA)

ARM64 BTI and PAC provide robust hardware-enforced control flow integrity across mobile, server, and hypervisor environments.

### Future Roadmap Extensions
1. **ARM64 MTE (Memory Tagging Extension - Proposed Phase 7)**:
   - Synchronous and asynchronous 4-bit memory color tagging (per 16-byte granules) to instantly detect heap buffer overflows and UAF exploits.
2. **AVF (Android Virtualization Framework)**:
   - Protected KVM (pKVM) isolated Android micro-guest VM (pVM) demo environment.
3. **Arm CCA (Confidential Compute Architecture)**:
   - Realm Management Monitor (RMM) and confidential compute enclave protection demonstrations.
