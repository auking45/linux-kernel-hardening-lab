# MDS & TAA Mitigation: Microarchitectural Buffer Clearing (VERW / MD_CLEAR)

## 1. Overview and Background

Modern microprocessors use various internal hardware buffers to minimize memory hierarchy latency and maximize data throughput. Key internal structures include the **Line Fill Buffer (LFB)**, which manages L1D cache fill and eviction lines, the **Store Buffer (SB)**, which queues pending memory writes, and the **Load Ports (LP)**, which serve as interfaces between registers and the memory subsystem.

Disclosed in 2019, **MDS (Microarchitectural Data Sampling)** and **TAA (TSX Asynchronous Abort)** represent a critical class of microarchitectural side-channel vulnerabilities where out-of-order CPUs forward transient, uncommitted data from internal buffers during faults or aborts:
1. **Faulting Loads and Speculative Buffer Forwarding**:
   - When an unprivileged program attempts to read privileged kernel memory or unmapped virtual addresses, the operation inevitably triggers a page fault (`#PF`) or TSX transaction abort.
   - To avoid stalling the execution pipeline while the memory management unit (MMU) walks the page tables to determine fault legitimacy, the processor speculatively forwards whatever stale residual data happens to reside in internal buffers (**LFB, Store Buffer, or Load Ports**) to dependent instructions.
2. **Side-Channel Cache Encoding and Data Recovery**:
   - The attacker's speculative code uses the transiently sampled byte as an index into a user-controlled probe array (`probe_array[sampled_byte * 512]`), warming up the corresponding L1D cache line.
   - When the architectural fault is finally committed and handled via `SIGSEGV` or TSX rollback, the **microarchitectural cache tags remain modified**.
   - The attacker measures memory access latency using **Flush+Reload**, reconstructing kernel memory, encryption keys, and credentials at bandwidths reaching hundreds of kilobytes per second.

The Linux kernel, in coordination with Intel microcode updates, mitigates this class of vulnerabilities by repurposing the **`VERW` (Verify a Segment for Writing) instruction (`MD_CLEAR`)** to overwrite all internal CPU buffers with zeroes on kernel exit (`sysret`, `iret`), VM transitions, and context switches.

---

## 2. Real-World Analogy: Unattended Teller Slips and the Permanent Shredder (VERW)

The mechanics of `MDS` and `VERW` buffer clearing can be visualized as **unattended bank teller transaction slips and the introduction of a permanent shredder**:

```
[ Vulnerable Mode (Baseline: Microarchitectural Buffer Clearing Disabled) ]
  VIP Client (Kernel):   "Deposits secret funds (system call) at the teller window and departs!"
  Bank Teller (CPU):     "Transaction done, but leaves the customer's draft slip (0x46) in the open tray (LFB)!"
  Malicious Visitor:     "Approaches the window with an invalid account number (Faulting Load)!"
  Bank Teller (CPU):     "While checking the account, idly shows the visitor the draft slip (0x46) in the tray (Speculative Sampling)!"
  Malicious Visitor:     "Before getting rejected (SIGSEGV), notes down the slip details (0x46) and reconstructs VIP secrets!"

[ Hardened Mode (Hardened: MD_CLEAR via VERW Instruction) ]
  VIP Client (Kernel):   "Deposits secret funds and prepares to depart!"
  Security Policy(VERW): "Before any customer leaves the counter, the teller must run the shredder (VERW)!"
  Bank Teller (CPU):     (Executes VERW microcode ──► LFB, Store Buffer, and Load Ports instantly overwritten with 0x00)
  Malicious Visitor:     "Approaches with invalid account number!"
  Bank Teller (CPU):     "The tray contains only shredded blank paper (0x00). Zero secret details visible!"
  Malicious Visitor:     "Samples only neutral zeroes. 0 secret bytes exfiltrated!"
```

1. **Legacy Kernel (Residual Buffer Stash)**:
   - Leaves internal CPU queues populated after servicing privileged kernel requests.
   - Unprivileged attackers trigger intentional faults to speculatively sample residual buffer contents.
2. **VERW-Hardened Kernel (Sanitization on Exit)**:
   - Issues the `VERW` instruction at all privilege boundary transitions.
   - Hardware microcode flushes LFB, Store Buffer, and Load Ports with zeroes, preventing speculative data sampling.

---

## 3. Core Architecture and Defense Mechanisms

### 3.1 MDS Variants and Targeted Hardware Buffers

| Vulnerability Variant | CVE Identifier | Targeted Microarchitectural Buffer | Attack Characteristics |
| :--- | :--- | :--- | :--- |
| **MFBDS (ZombieLoad v1)** | CVE-2018-12130 | **Line Fill Buffer (LFB)**<br>(12 non-coherent buffers managing L1D cache fill/evict requests) | Faulting load samples in-flight cache line data across cores and SMT siblings |
| **MSBDS (Fallout)** | CVE-2018-12126 | **Store Buffer (SB)**<br>(56-entry queue holding pending store data prior to cache commit) | Delayed store address calculation exposes store buffer data to subsequent speculative loads |
| **MLPDS (RIDL)** | CVE-2018-12127 | **Load Ports (LP)**<br>(Execution ports 2 & 3 handling memory load operations) | Speculative loads sample data passing through execution load ports |
| **MDSUM (RIDL Variant)** | CVE-2019-11091 | **Uncacheable Memory (UC)** Buffers | Samples uncacheable data buffers (e.g. MMIO, device memory) |
| **TAA (ZombieLoad v2)** | CVE-2019-11135 | **TSX Transactional Abort** LFB Buffers | Asynchronous abort inside Intel TSX transactions forwards stale LFB data |

---

### 3.2 x86_64 VERW Buffer Clearing (`MD_CLEAR`)

Intel implemented buffer clearing by extending the architectural behavior of the x86 `VERW` instruction:

```x86asm
/* Linux Kernel x86_64 CPU Buffer Clearing Entry */
.macro CLEAR_CPU_BUFFERS
    /* Invoked if X86_FEATURE_MD_CLEAR is detected */
    ALTERNATIVE "", "verw x86_verw_sel(%rip)", X86_FEATURE_MD_CLEAR
.endm
```

```c
/* <asm/nospec-branch.h> In-Kernel Implementation */
static __always_inline void x86_clear_cpu_buffers(void)
{
    static const u16 ds = __KERNEL_DS;
    /*
     * Must use the memory-operand variant (verw %[ds]) because only
     * that variant is guaranteed by microcode to trigger the buffer clear.
     * VERW modifies the ZF condition code flag, requiring the "cc" clobber.
     */
    asm volatile("verw %[ds]" : : [ds] "m" (ds) : "cc");
}
```

- **Execution Gateways**:
  - Return to user space via `sysret` and `iret`.
  - Virtual machine entry (`VM-Entry`) and exit (`VM-Exit`) in KVM.
  - Process context switches and CPU idle transitions.

---

### 3.3 SMT (Simultaneous Multi-Threading) Considerations

Because sibling logical cores (Hyper-Threads) on the same physical core share Line Fill Buffers and Store Buffers in real time:

- **Cross-Thread Attack Surface**: While Thread A executes privileged kernel code, Thread B running concurrently on the sibling hyper-thread can continuously sample LFB data.
- **Full Defense Strategy**:
  - `VERW` protects transitions, but complete cross-thread isolation requires disabling SMT (`nosmt` or `mds=full,nosmt` / `taa=full,nosmt`).

---

### 3.4 ARM64 Architecture Status

ARM microarchitectures (Cortex-A, Neoverse):
- Do not implement speculative forwarding of uncommitted Line Fill Buffer data on faulting loads across privilege levels.
- All ARM64 processors are **Not affected** by MDS, TAA, and related CPU buffer sampling vulnerabilities.

---

### 3.5 Linux Kernel Configuration and Sysfs Interfaces

- **Sysfs Paths**:
  - `/sys/devices/system/cpu/vulnerabilities/mds`
  - `/sys/devices/system/cpu/vulnerabilities/tsx_async_abort`
  - `/sys/devices/system/cpu/vulnerabilities/mmio_stale_data`
- **Typical Status Values**:
  - `Mitigation: Clear CPU buffers; SMT disabled`: Fully protected with buffer clear and SMT disabled.
  - `Mitigation: Clear CPU buffers; SMT vulnerable`: Buffer clear active, but SMT enabled.
  - `Not affected`: Hardware immune processor (ARM64 or modern Intel cores).
- **Boot Parameters**:
  - `mds=full`: Enables VERW buffer clearing on all transitions.
  - `mds=full,nosmt`: Enables VERW and disables SMT siblings.
  - `mds=off`: Disables MDS mitigations.
  - `tsx_async_abort=full`: Enables TAA mitigations.

---

## 4. Interactive Architecture Simulator

The following interactive SVG simulator models the mechanics of MDS/TAA data sampling and its mitigation via VERW microcode buffer clearing:

<iframe src="../../assets/diagrams/mds/architecture.html" width="100%" height="700px" style="border: 1px solid var(--card-border); border-radius: 8px; margin: 16px 0; background: #0b132b;"></iframe>

---

## 5. Lab Environment and Verification

Lab 25 (`labs/25-mds`) verifies MDS buffer sampling and VERW mitigations across x86_64 and ARM64.

### 5.1 Target Driver (`/proc/vuln_mds`)

- **Location**: `labs/25-mds/vuln_mds.c`
- **Commands**:
  - `echo 'mode baseline' > /proc/vuln_mds`: Switches to Mode 0 (buffer clear disabled / vulnerable).
  - `echo 'mode hardened' > /proc/vuln_mds`: Switches to Mode 1 (VERW buffer clear enabled / protected).
  - `echo 'sample <offset>' > /proc/vuln_mds`: Executes sampling cycle for target offset.
  - `echo 'verw' > /proc/vuln_mds`: Manually issues `VERW` instruction to clear buffers.
  - `echo 'run_bench' > /proc/vuln_mds`: Runs in-kernel verification benchmark.
  - `mmap()`: Provides user-space access to the 128KB probe array for Flush+Reload measurement.

### 5.2 Unprivileged PoC Exploit (`labs/25-mds/exploit.c`)

Runs as user `lab` (UID 1000) and tests both operational modes:

```bash
# Automated in-guest test runner
/bin/test_mds
```

1. **Phase 1: Baseline Mode (Mode 0 - Buffer Clearing Disabled)**:
   - Secret residue (`FLAG{...}`) left in LFB slot.
   - Speculative faulting load samples residual byte, warming probe array line.
   - Detects secret byte and logs `[FAIL/VULNERABLE] In Baseline mode, MDS sampled stale microarchitectural buffer data!`.
2. **Phase 2: Hardened Mode (Mode 1 - VERW Buffer Clearing Active)**:
   - Kernel executes `VERW` instruction before returning to user space, wiping internal buffers to 0x00.
   - Speculative load only samples neutral 0s; 0 secret bytes leaked.
   - Logs `[PASS/PROTECTED] Microarchitectural buffer clearing (VERW) prevented data sampling!`.

---

## 6. Vulnerability Variants and Defense Comparison Matrix

| Variant Name | Targeted Buffer | Affected Hardware | Linux Mitigation | SMT Impact |
| :--- | :--- | :--- | :--- | :--- |
| **MFBDS (ZombieLoad)** | Line Fill Buffer | Intel Sandy Bridge to Coffee Lake | VERW on kernel exit | Cross-thread sampling (nosmt recommended) |
| **MSBDS (Fallout)** | Store Buffer | Intel Haswell to Cascade Lake | VERW buffer clear (`mds=full`) | Shared physical core store buffer |
| **MLPDS (RIDL)** | Load Ports | Intel Nehalem to Whiskey Lake | VERW buffer clear (`mds=full`) | Load port sharing across siblings |
| **TAA (ZombieLoad v2)** | TSX LFB Abort | Intel Skylake, Cascade Lake | `tsx_async_abort=full` + VERW | SMT TSX abort snooping |
| **ARM64 Architecture** | N/A (Immune) | ARMv8 / ARMv9 cores | Hardware immune (`Not affected`) | No impact |

---

## 7. References

- [Kernel Documentation: Microarchitectural Data Sampling (MDS)](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html)
- [Kernel Documentation: TSX Asynchronous Abort (TAA)](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/tsx_async_abort.html)
- [Intel Security Advisory: Microarchitectural Data Sampling (INTEL-SA-00233)](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html)
- [ZombieLoad Attack Whitepaper (Schwarz et al., 2019)](https://zombieloadattack.com/)
- [RIDL: Rogue In-Flight Data Load (van Schaik et al., S&P 2019)](https://mdsattacks.com/)
