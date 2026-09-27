# Spectre v2: Branch Target Injection & Retpoline/IBPB Defense

## 1. Overview & Technical Background

Modern microprocessors employ a **Branch Target Buffer (BTB)** to eliminate pipeline bubbles associated with **indirect branches** (e.g., `call *%rax` in x86, `blr xN` in ARM64) where destination addresses are resolved dynamically at runtime (function pointers, virtual method tables, interface dispatch). The BTB records the target addresses of past indirect branches, predicting the destination and speculatively branching ahead before registers or memory loads complete.

Publicly disclosed in 2018, **Spectre Variant 2 (Branch Target Injection - CVE-2017-5715)** exploits hardware sharing and partial-tag indexing in the BTB:
1. **BTB Poisoning**:
   - Because processors index BTB entries using only the lower virtual address bits (without ASID or privilege-level isolation on affected microarchitectures), an unprivileged attacker in user space (EL0 / Ring 3) repeatedly executes indirect branches at virtual addresses that alias with target kernel indirect branch sites.
   - The attacker sets the branch target to a malicious in-kernel **victim gadget**.
2. **Branch Target Injection (BTI)**:
   - When the kernel (EL1 / Ring 0) subsequently invokes an indirect call (e.g., VFS operations, LSM hooks), the CPU references the poisoned BTB entry and speculatively jumps to the attacker's chosen victim gadget.
3. **Transient Execution & Secret Exfiltration**:
   - The victim gadget reads kernel secret memory and accesses a secondary probe array line (`probe_array[secret * 512]`), warming the CPU cache line.
   - When architectural execution verifies the real pointer and rolls back register state, the cache footprint persists, allowing the attacker to extract kernel secrets via **Flush+Reload**.

The Linux kernel mitigates Spectre v2 through compiler-level **Retpoline (Return Trampoline)** software thunks, hardware microcode **IBPB / STIBP / eIBRS**, and ARM64 **CSV2 / BHB** mitigations.

---

## 2. Real-World Analogy: Counterfeit Highway Signs and Roundabout Traps

The mechanics of `Spectre v2` and `Retpoline` can be compared to an **attacker altering highway fork signs, intercepted by a designated roundabout trap**:

```
[ Vulnerable Approach (Baseline: Poisoned Indirect Branch) ]
  Attacker: "Alters highway fork sign to point to Classified Military Base (Victim Gadget)!"
  Kernel Driver: (GPS navigation delayed; driver trusts counterfeit sign and turns immediately)
                 ──► [Speculatively enters military base] ──► [Leaves hot tire marks (cache line)]
  GPS Resolves: "Wrong turn! Reverse immediately and resume planned route."
  Attacker: "Measures tarmac heat on military base access road to infer secret operations!"

[ Hardened Approach (Hardened: Retpoline Trampoline) ]
  Attacker: "Alters highway fork sign!"
  Kernel Driver: (Completely ignores the sign; enters safe roundabout loop)
                 ──► [Speculative Trap: Spins in roundabout loop (pause; lfence; jmp)]
  GPS Resolves: "Authentic sealed envelope opened: non-speculatively exits to legitimate route!"
  Attacker: "Military base road remains completely untouched (0 bytes leaked)!"
```

1. **Vulnerable Kernel (Blind Trust in Poisoned Signs)**:
   - While memory retrieval is pending, the CPU eagerly trusts the attacker-manipulated BTB sign and speculatively jumps into the victim gadget, leaving persistent cache warm-up traces.
2. **Retpoline Kernel (RSB Roundabout Trap)**:
   - Ignores the BTB fork entirely and enters an infinite speculative loop (`pause; lfence; jmp`) predicted via the Return Stack Buffer (RSB). The speculative engine harmlessly spins while architectural execution retrieves the verified target from memory stack, achieving complete immunity from BTB poisoning.

---

## 3. Core Architecture & Defense Mechanism

### 3.1 The Retpoline Assembly Trampoline

Devised by Paul Turner (Google), Retpoline exploits the fact that the CPU predicts `ret` instructions using the **Return Stack Buffer (RSB)** rather than the BTB:

```x86asm
/* x86_64 Retpoline Trampoline (__x86_indirect_thunk_rax) */
.global __x86_indirect_thunk_rax
__x86_indirect_thunk_rax:
    call 2f                 /* Step 1: Pushes address of label 1 to RSB and stack */
1:
    pause                   /* Step 2: Speculative execution trapped in infinite loop */
    lfence
    jmp 1b
2:
    pushq %rax              /* Step 3: Overwrite stack slot with target address (%rax) */
    ret                     /* Step 4: Non-speculatively pops and jumps to %rax */
```

- **Step 1 (`call 2f`)**: Emits a `call` to `2f`. The CPU pushes the return address (`1: pause; lfence; jmp 1b`) to both the architectural memory stack and the internal hardware RSB.
- **Steps 2 & 3**: Overwrites the architectural stack slot with the real target address (`%rax`).
- **Step 4 (`ret`)**:
  - **Speculative Path**: The branch predictor predicts `ret` using the RSB, branching to `1:`. The CPU speculative pipeline enters the infinite `pause; lfence` loop, preventing any speculative jump.
  - **Architectural Path**: When memory resolves, the CPU pops `%rax` from the stack and jumps to the legitimate target.
  - **Outcome**: The attacker's poisoned BTB entry is **never consulted**.

### 3.2 Hardware-Assisted Mitigations (IBPB, STIBP, eIBRS)

1. **IBPB (Indirect Branch Prediction Barrier)**:
   - Setting bit 0 of MSR `IA32_PRED_CMD` flushes all BTB state. The Linux kernel issues IBPB on context switches between unprivileged processes to eliminate cross-process poisoning.
2. **STIBP (Single Thread Indirect Branch Predictors)**:
   - MSR `IA32_SPEC_CTRL` bit 1 prevents sibling SMT/Hyper-Threading threads from poisoning each other's BTB entries.
3. **eIBRS (Enhanced IBRS)**:
   - On Intel Ice Lake+ and AMD Zen 3+, automatically isolates kernel BTB from user space without the performance overhead of traditional IBRS.

### 3.3 ARM64 Mitigations

- **CSV2 (ID_AA64PFR0_EL1.CSV2)**: Hardware context tagging preventing EL0 branch history from affecting EL1.
- **SMCCC_ARCH_WORKAROUND_1**: Firmware PSCI hypercall invalidating branch predictor state upon EL1 entry.
- **Spectre-BHB**: Loop-based Branch History Buffer clearing routines.

---

## 4. Interactive Architecture Simulator

An interactive simulator illustrating Spectre v2 BTI attacks and Retpoline RSB loop trapping:

<iframe src="../../assets/diagrams/spectrev2/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. Hands-on Lab & Exploit Demonstration

### 5.1 Vulnerability Lab Driver (`vuln_spectrev2.c`)

Exposes `/proc/vuln_spectrev2` (mode 0666):
- **Mitigation Status (`cat /proc/vuln_spectrev2`)**:
  - Displays CPU architecture, Retpoline thunk configuration, active mode, and dispatch statistics.
- **Mode Switching**:
  - `echo 'mode baseline' > /proc/vuln_spectrev2`: Raw indirect branches vulnerable to BTI.
  - `echo 'mode hardened' > /proc/vuln_spectrev2`: Retpoline trampoline enabled.
- **Indirect Dispatch Trigger**:
  - `echo 'dispatch <arg>' > /proc/vuln_spectrev2`: Performs indirect function pointer dispatch.
- **Userland Cache Probe Mapping via `mmap`**:
  - Maps 128KB probe array into user space for cycle measurement.

### 5.2 Unprivileged BTI Exploit PoC (`exploit.c`)

Executed as non-privileged user `lab` (UID 1000):
- **Baseline Mode**: Poisoned indirect branches hijack execution to `victim_spectre_gadget`, leaking `FLAG` secret bytes (`[FAIL/VULNERABLE]`).
- **Hardened Mode**: Retpoline traps speculation in the RSB pause loop; only `safe_target_function` executes non-speculatively, resulting in 0 leaked bytes (`[PASS/PROTECTED]`).

---

## 6. Verification & Results

### 6.1 Automated Guest Test Execution

```bash
/bin/test_spectre_v2
```

### 6.2 Sysfs Vulnerability Interface

```bash
cat /sys/devices/system/cpu/vulnerabilities/spectre_v2
# x86_64: Mitigation: Retpolines, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling
# arm64 : Mitigation: CSV2, BHB
```

### 6.3 Dual-Architecture QEMU Verification Matrix

| Scenario | Architecture | Mode | Gadget Execution | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | ARM64 | Mode 1 (Hardened) | 0 hijacks (CSV2 / BHB / CSDB) | **PASS (Protected)** |
| **Scenario 2** | ARM64 | Mode 0 (Baseline) | Gadget executed & secret leaked | **VULNERABLE (Demonstrated)** |
| **Scenario 3** | x86_64 | Mode 1 (Hardened) | 0 hijacks (Retpoline RSB Trap) | **PASS (Protected)** |
| **Scenario 4** | x86_64 | Mode 0 (Baseline) | Gadget executed & secret leaked | **VULNERABLE (Demonstrated)** |

