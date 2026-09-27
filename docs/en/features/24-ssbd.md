# Spectre v4: Speculative Store Bypass Disable (SSBD)

## 1. Overview and Background

Modern out-of-order execution processors use sophisticated **memory disambiguation** predictors to hide memory latency. When a load instruction follows an unresolved store instruction, the processor tries to predict whether the two memory accesses conflict (alias each other).

Published in 2018, **Spectre Variant 4 (Speculative Store Bypass - CVE-2018-3639)** exploits the memory disambiguator to prematurely execute loads before preceding stores with unknown target addresses commit:
1. **Store Buffer Delay**:
   - A preceding store instruction (`*ptr_x = safe_val`) is issued, but calculating its destination physical address is delayed due to complex address calculations, TLB misses, or memory dependencies.
   - The store data sits in the internal hardware Store Buffer pending address resolution.
2. **Speculative Store Bypass (SSB)**:
   - A subsequent load instruction (`val = *ptr_y`) arrives in the execution pipeline.
   - The CPU's **Memory Disambiguation Predictor** guesses that `ptr_x` and `ptr_y` do not alias (`ptr_x != ptr_y`), predicting that the load does not depend on the pending store.
   - The load speculatively executes and bypasses the uncompleted store.
3. **Transient Leak of Stale Secret Data**:
   - If the two pointers actually point to the same memory location (`ptr_x == ptr_y`), the load speculatively retrieves the **stale (prior) data** present in memory instead of the new `safe_val`.
   - The transient load forwards the stale secret (`val`) to an address computation for a secondary array (`probe_array[val * 512]`), warming up a specific L1D cache line.
   - When the store address eventually resolves, the processor recognizes the hazard, squashes the speculative register state, and re-executes the load with `safe_val`.
   - However, the microarchitectural state—specifically the warmed cache line—remains cached, allowing an unprivileged attacker to extract the stale secret byte using **Flush+Reload** cache timing.

The Linux kernel defends against Spectre v4 through hardware control registers (x86 MSR `IA32_SPEC_CTRL`, ARM64 `PSTATE.SSBS`), task-level controls via `prctl(2)`, and memory serialization barriers (`lfence`, `dsb sy; isb`).

---

## 2. Real-World Analogy: The Eager Mail Clerk and the Stale Letter

The mechanism of `Spectre v4` and `SSBD` can be visualized as an **eager mail clerk reading stale letters from an un-updated post office box**:

```
[ Vulnerable Mode (Baseline: Speculative Store Bypass Allowed) ]
  Supervisor: "We are calculating which PO Box to overwrite with a public announcement (safe_val)! (Store Delayed)"
  Eager Clerk: "I don't want to wait for the box number calculation. Box A and Box B probably don't conflict! (No Alias)"
               ──► [Opens Box A before the new announcement arrives and reads the stale secret letter!]
               ──► [Leaves a fluorescent highlighter mark on the wall based on the letter's first letter]
  Supervisor: "Calculation done! Box A was the one being overwritten! Erase clerk's memory and insert announcement!"
  Attacker:    "The clerk forgot, but the fluorescent mark on the wall reveals the secret letter!"

[ Hardened Mode (Hardened: SSBD Active via MSR / PSTATE.SSBS) ]
  Supervisor: "SSBD Rule Active: No clerk may open any box until all pending updates have resolved destination addresses!"
  Cautious Clerk: (Waits patiently until the supervisor calculates the box number and writes the safe announcement)
               ──► [Only opens the box after safe_val is securely deposited inside]
               ──► [The only mark on the wall is for safe_val (0 secret bytes accessed)]
  Attacker:    "Wall only shows safe announcement marks. Zero secret bytes leaked!"
```

1. **Legacy Kernel (Speculative Bypass Permitted)**:
   - Prioritizes instruction-level parallelism by letting loads speculatively leapfrog unresolved stores.
   - When an aliasing hazard occurs, architectural state is restored, but side-channel cache lines leave residual traces that expose kernel secrets.
2. **SSBD-Hardened Kernel (Enforced Serialization)**:
   - Hardware controls instruct the memory disambiguator to force loads to stall until all unresolved store addresses in the Store Buffer are known.
   - Loads strictly observe the latest committed data, completely closing the transient window for stale secret exfiltration.

---

## 3. Core Architecture and Defense Mechanisms

### 3.1 Hardware Store Buffer and Memory Disambiguation

```
+--------------------------------------------------------------------------------+
|                         CPU Execution Pipeline                                 |
|                                                                                |
|  [ Store: *ptr_x = safe_val ]               [ Load: val = *ptr_y ]             |
|                |                                       |                       |
|                v                                       v                       |
|     +---------------------+               +-------------------------+          |
|     |    Store Buffer     |               |  Memory Disambiguator   |          |
|     |  Address: PENDING.. |               |  Prediction: NO ALIAS   |          |
|     |  Data:    0x55      |               +-------------------------+          |
|     +---------------------+                            |                       |
|                | (Delayed)                             v (Speculative Bypass)  |
|                |                           +------------------------+          |
|                |                           | Speculative Load Exec  |          |
|                |                           | Reads STALE Secret!    |          |
|                |                           +------------------------+          |
|                |                                       |                       |
|                v                                       v                       |
|     +---------------------------------------------------------------+          |
|     |              L1 Data Cache / Main Memory Slot                 |          |
|     |  [Physical Slot]: 0x46 ('F') =====> 0x55 (Safe)               |          |
|     +---------------------------------------------------------------+          |
+--------------------------------------------------------------------------------+
```

1. **Store Buffer**:
   - Temporarily holds written data and addresses until the memory bus can commit them, avoiding pipeline stalls on store operations.
2. **Store-to-Load Forwarding**:
   - If a load address matches an entry in the Store Buffer, data is forwarded directly from the Store Buffer to the load without accessing cache.
3. **Memory Disambiguation Predictor**:
   - When store addresses are pending, this unit predicts whether an upcoming load will conflict with any entry in the Store Buffer.
   - A prediction of "No Conflict" allows speculative bypass, creating the vulnerability window for Spectre v4.

---

### 3.2 x86_64 Hardware SSBD Mitigation

Intel and AMD introduced microcode updates providing Model-Specific Registers (MSRs):

1. **MSR `IA32_SPEC_CTRL` (0x48)**:
   - **Bit 2 (`SPEC_CTRL_SSBD`)**:
     - `0`: Speculative Store Bypass allowed (default performance mode).
     - `1`: Speculative Store Bypass disabled (SSBD active).
     - Setting bit 2 disables the memory disambiguator, forcing loads to wait until preceding store addresses are known.
2. **MSR `IA32_ARCH_CAPABILITIES` (0x10A)**:
   - **Bit 4 (`SSB_NO`)**: Indicates that the hardware processor is not susceptible to Speculative Store Bypass.
3. **Kernel Command Line Parameters**:
   - `spec_store_bypass_disable=on`: Enables SSBD permanently across kernel and user space.
   - `spec_store_bypass_disable=prctl`: Disables by default, but allows processes to enable it per-task via `prctl` (Linux default).
   - `spec_store_bypass_disable=seccomp`: Enables SSBD automatically for sandboxed seccomp threads.
   - `spec_store_bypass_disable=off`: Disables all SSBD mitigations.

---

### 3.3 ARM64 SSBD and PSTATE.SSBS

On ARM64 (ARMv8.5-A and ARMv8.0 mitigations), SSBD is governed by architectural state:

1. **`PSTATE.SSBS` (Speculative Store Bypass Safe) Bit**:
   - `PSTATE.SSBS == 0`: Speculative Store Bypass disabled.
   - `PSTATE.SSBS == 1`: Speculative Store Bypass allowed.
   - Manipulated directly via `msr ssbs, #0` or `msr ssbs, #1`.
2. **SMCCC Firmware Workaround (`ARM_SMCCC_ARCH_WORKAROUND_2`)**:
   - Invokes EL3 Secure Monitor or EL2 hypervisor firmware to toggle dynamic memory disambiguation for processors without hardware SSBS register access.
3. **ARM64 Kernel Command Line**:
   - `ssbd=force-on`: Forces SSBD on for all execution levels.
   - `ssbd=kernel`: Enforces SSBD on kernel entries (EL1).
   - `ssbd=force-off`: Disables SSBD mitigation.

---

### 3.4 Software Serialization Barriers (LFENCE / DSB)

When hardware SSBD control is unavailable or for targeted code sequences, software memory serialization barriers serialize execution:

```c
// x86_64: LFENCE forces previous store to commit before load executes
*slot = safe_value;
asm volatile("lfence" ::: "memory");
val = *slot;

// ARM64: DSB SY and ISB serialize memory access
*slot = safe_value;
asm volatile("dsb sy\n\tisb" ::: "memory");
val = *slot;
```

---

### 3.5 Linux Task Control Interface (`prctl`)

The Linux kernel enables unprivileged user-space processes to inspect and configure speculative store bypass defenses using `prctl(2)`:

```c
#include <sys/prctl.h>

// 1. Query current SSBD speculation status
int status = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

// 2. Disable speculative store bypass for this thread
prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);

// 3. Permanently lock speculation control (immutable, recommended for seccomp)
prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE, 0, 0);
```

---

## 4. Interactive Architecture Simulator

The following interactive SVG simulator visualizes the mechanics of Speculative Store Bypass and its mitigation via hardware SSBD and serialization barriers:

<iframe src="../../assets/diagrams/ssbd/architecture.html" width="100%" height="700px" style="border: 1px solid var(--card-border); border-radius: 8px; margin: 16px 0; background: #0b132b;"></iframe>

---

## 5. Lab Environment and Verification

Lab 24 (`labs/24-ssbd`) provides hands-on verification of Spectre v4 and SSBD defenses across both ARM64 and x86_64.

### 5.1 Target Driver (`/proc/vuln_ssbd`)

- **Location**: `labs/24-ssbd/vuln_ssbd.c`
- **Commands**:
  - `echo 'mode baseline' > /proc/vuln_ssbd`: Switches to Mode 0 (SSB allowed / vulnerable).
  - `echo 'mode hardened' > /proc/vuln_ssbd`: Switches to Mode 1 (SSBD active / protected).
  - `echo 'trigger <offset>' > /proc/vuln_ssbd`: Triggers store bypass cycle for target offset.
  - `echo 'run_bench' > /proc/vuln_ssbd`: Executes in-kernel verification benchmark.
  - `mmap()`: Provides unprivileged access to the 128KB probe array for Flush+Reload measurement.

### 5.2 Unprivileged PoC Exploit (`labs/24-ssbd/exploit.c`)

Runs as user `lab` (UID 1000) and evaluates both operational modes:

```bash
# Automated in-guest test runner
/bin/test_ssbd
```

1. **Phase 1: Baseline Mode (Mode 0 - SSB Allowed)**:
   - Stores safe data into memory slot with delayed commitment.
   - Load speculatively bypasses store and reads stale secret bytes (`FLAG{...}`).
   - Recovers secret bytes from probe array and logs `[FAIL/VULNERABLE] In Baseline mode, Speculative Store Bypass leaked stale data!`.
2. **Phase 2: Hardened Mode (Mode 1 - SSBD Active)**:
   - Enforces hardware SSBD control and memory serialization barriers.
   - Load is forced to wait until store commits safe data (`0x55`).
   - Probe array observes 0 secret bytes, confirming `[PASS/PROTECTED] SSBD successfully prevented speculative store bypass!`.

---

## 6. Architecture Comparison Matrix

| Metric | Baseline (Vulnerable) | x86_64 SSBD (MSR) | ARM64 SSBD (PSTATE.SSBS) | Software Barrier (LFENCE) |
| :--- | :--- | :--- | :--- | :--- |
| **Mitigation Principle** | Speculative bypass allowed | MSR 0x48 bit 2 disables disambiguation | PSTATE.SSBS=0 or SMCCC workaround | Memory serialization between store and load |
| **Hardware Requirement** | Standard CPU | Microcode update / modern CPU | ARMv8.5-A or SMCCC firmware | Supported on all architectures |
| **User-Space Control** | `PR_SPEC_ENABLE` | `prctl(PR_SPEC_STORE_BYPASS)` | `prctl(PR_SPEC_STORE_BYPASS)` | Requires source recompilation |
| **Performance Overhead** | 0% | ~2% - 8% on memory workloads | ~1% - 5% on memory workloads | High localized stall penalty |
| **Sysfs Status** | `Vulnerable` | `Mitigation: Speculative Store Bypass...` | `Mitigation: Speculative Store Bypass...` | Marked vulnerable if hardware unmitigated |

---

## 7. References

- [Kernel Documentation: Speculative Store Bypass](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/speculative-store-bypass.html)
- [Intel Analysis of Speculative Store Bypass (CVE-2018-3639)](https://software.intel.com/security-software-guidance/insights/deep-dive-speculative-store-bypass)
- [Arm Speculative Processor Vulnerability: Speculative Store Bypass](https://developer.arm.com/Arm%20Security%20Center/Speculative%20Processor%20Vulnerability)
- [Linux prctl(2) Speculation Control Interface](https://man7.org/linux/man-pages/man2/prctl.2.html)

