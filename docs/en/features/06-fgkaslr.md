# FG-KASLR: Function Granular Randomization & Overcoming Monolithic KASLR Limits

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/fgkaslr/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="FG-KASLR Architecture Diagram"></iframe>
</div>

---

## 1. Overview & Threat Model

### 1.1 Addressed Threat: Monolithic KASLR's Single-Pointer Infoleak Flaw

- **Structural Vulnerability of Monolithic Slide**:
  - Standard KASLR (`CONFIG_RANDOMIZE_BASE=y`) shifts the entire kernel `.text` section as a single monolithic block using one uniform random `Slide`.
  - While the base address (`_text`) is randomized, the relative distances ($\Delta$) between all kernel functions remain identical to the offline ELF binary structure:
    $$\Delta = \text{Addr}(\text{Target\_Func}) - \text{Addr}(\text{Leaked\_Func}) = \text{Constant}$$
  - If an attacker obtains a single kernel function pointer via an uninitialized stack or heap leak, the global slide and all ROP gadget addresses can be trivially computed.
- **Security Goals of FG-KASLR (Function Granular KASLR)**:
  - Compiles functions into individual sections (`-ffunction-sections`) and shuffles their layout permutation during boot or loading.
  - Disrupts the fixed relative distance ($\Delta$), ensuring that leaking one pointer does not expose adjacent functions or facilitate ROP chains.

### 1.2 Real-World Metaphor: The Shuffled LEGO Blocks

- **Explanation**:
  - Kernel functions can be visualized as individual rooms built out of LEGO bricks.
  - **Monolithic KASLR**: Moving an entire assembled LEGO castle to a random coordinate on the map. The absolute location changes, but the hallway distance from Room 1 (leaked function) to Room 5 (target function) remains identical. An intruder finding Room 1 can walk straight to Room 5.
  - **FG-KASLR**: Detaching every single room into individual LEGO bricks, shuffling them in a box, and reassembling them in random order. Even if an intruder finds Room 1, they have zero knowledge of Room 5's whereabouts; following the old blueprint ($\Delta$) causes them to step into empty space.

---

## 2. Kernel Internal Architecture & Upstream Trade-offs

### 2.1 FG-KASLR Mechanics (Kristen Carlson Accardi LKML RFC)

- **Compiler-Level Function Partitioning**:
  - Uses GCC's `-ffunction-sections` flag to emit every kernel function into an independent ELF section (`.text.<function_name>`).
- **Boot Decompressor Permutation**:
  - Early during x86 decompression (`arch/x86/boot/compressed/`), parses the relocation table and reorders function sections in a pseudo-random permutation.
  - Dynamically recalculates and patches symbol tables, exception tables (`extable`), and bug tables (`bug_table`).

### 2.2 Mainline Rejection Reasons & Trade-off Analysis

- **Microarchitectural Performance Impact**:
  - **iTLB (Instruction TLB) Pressure**: Scattered functions break 2MB huge page mappings, forcing 4KB page granularity and degrading TLB hit rates.
  - **BTB & L1i Cache Locality Loss**: Closely cooperating hot functions are separated, leading to instruction cache thrashing and branch mispredictions (1~3%+ benchmark regressions observed).
- **Kernel Tracing & Tooling Breakage**:
  - `ftrace` and `livepatch`: Collides with 5-byte nop/fentry prologue patching and relative call expectations.
  - `perf`, `BPF`, `objtool`: Toolchains optimized for linear, monotonic address spaces face severe complexity.
- **Modern Alternatives**:
  - Mainline Linux chose compiler/hardware Control Flow Integrity (**Clang kCFI**, **Intel FineIBT**, **ARM64 PAC/BTI**) rather than physical boot-time function shuffling.

---

## 3. Hands-on Lab Implementation

### 3.1 Vulnerable Target Driver (`vuln_fgkaslr.c`)

- Implements `/proc/vuln_fgkaslr` (mode `0666`):
  - **Relative Distance Telemetry**:
    - `LEAK_FUNC_ADDR`: Base reference function (`fgkaslr_leak_source`).
    - `DEFAULT_TARGET_ADDR`: Default sequentially linked target function (`fgkaslr_target_slot0`).
    - `ACTIVE_TARGET_ADDR`: Current active target function.
    - `STATIC_DELTA`: Precomputed compile-time relative offset.
    - `ACTUAL_DELTA`: Runtime relative offset.
  - **Mode Control & Attack Validation**:
    - Boot parameter parsing (`fgkaslr=1` for enabled, `fgkaslr=0` for monolithic).
    - Checks user-provided target addresses against active function addresses.

### 3.2 Relative-Offset Exploit PoC (`exploit.c`)

- Executed by unprivileged user `lab` (UID 1000):
  - Step 1: Reads `LEAK_FUNC_ADDR` from `/proc/vuln_fgkaslr`.
  - Step 2: Adds `STATIC_DELTA` ($Target = Leaked + \Delta_{static}$).
  - Step 3: Writes calculated address to trigger execution.
  - Outcomes:
    - **Monolithic Mode**: Static delta matches actual delta $\rightarrow$ 100% exploit success (`[!] VULNERABILITY CONFIRMED`).
    - **FG-KASLR Mode**: Randomization causes delta mismatch $\rightarrow$ write fails (`[+] DEFENSE ACTIVE`).

---

## 4. Dual-Architecture Live Verification

### 4.1 x86_64 Live Verification Logs

#### Base / Monolithic KASLR (`fgkaslr-disabled`, `fgkaslr=0`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & FG-KASLR State Check
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=0
Boot Mode: FG-KASLR DISABLED via boot param (fgkaslr=0)

=========================================================
  [Test 2/3] Kernel Telemetry Analysis (/proc/vuln_fgkaslr)
=========================================================
FGKASLR_STATUS:        DISABLED
LEAK_FUNC_ADDR:        0xffffffff8f5ab440
DEFAULT_TARGET_ADDR:   0xffffffff8f5ab470
ACTIVE_TARGET_ADDR:    0xffffffff8f5ab470
STATIC_DELTA:          48
ACTUAL_DELTA:          48
DELTA_MISMATCH:        0
ACTIVE_SLOT:           0

=========================================================
  [Test 3/3] Real-World Relative Offset Exploit Demonstration
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Function Layout Telemetry:
    FG-KASLR Status:     DISABLED
    Leaked Function:     0xffffffff8f5ab440
    Default Target:      0xffffffff8f5ab470
    Active Target:       0xffffffff8f5ab470 (Slot 0)
    Static Delta:        +48 bytes
    Actual Delta:        +48 bytes
    Delta Mismatch:      +0 bytes

[*] Exploit Execution (Relative Offset Attack):
    Leaked Pointer:      0xffffffff8f5ab440
    Static Delta:        +48
    Calculated Target:   0xffffffff8f5ab470
[!] Target call returned success!
[!] VULNERABILITY CONFIRMED: Monolithic KASLR defeated via relative offset!
[!] Because function layout was NOT granularly randomized, static delta was valid.
[!] Attacker hijacked control flow with 100% accuracy from 1 infoleak.
```

#### Hardened / FG-KASLR (`fgkaslr`, `fgkaslr=1`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & FG-KASLR State Check
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=1
Boot Mode: FG-KASLR ENABLED via boot param (fgkaslr=1)

=========================================================
  [Test 2/3] Kernel Telemetry Analysis (/proc/vuln_fgkaslr)
=========================================================
FGKASLR_STATUS:        ENABLED
LEAK_FUNC_ADDR:        0xffffffffbb9ab440
DEFAULT_TARGET_ADDR:   0xffffffffbb9ab470
ACTIVE_TARGET_ADDR:    0xffffffffbb9ab4d0
STATIC_DELTA:          48
ACTUAL_DELTA:          144
DELTA_MISMATCH:        96
ACTIVE_SLOT:           3

=========================================================
  [Test 3/3] Real-World Relative Offset Exploit Demonstration
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Function Layout Telemetry:
    FG-KASLR Status:     ENABLED
    Leaked Function:     0xffffffffbb9ab440
    Default Target:      0xffffffffbb9ab470
    Active Target:       0xffffffffbb9ab4d0 (Slot 3)
    Static Delta:        +48 bytes
    Actual Delta:        +144 bytes
    Delta Mismatch:      +96 bytes

[*] Exploit Execution (Relative Offset Attack):
    Leaked Pointer:      0xffffffffbb9ab440
    Static Delta:        +48
    Calculated Target:   0xffffffffbb9ab470
[-] Write returned error: Invalid argument (errno = 22)
[+] Attack blocked or jumped to invalid location!
[+] DEFENSE ACTIVE: FG-KASLR prevented offset calculation!
[+] Function-level layout randomization broke compile-time relative offsets.
[+] Single-pointer infoleak failed to reveal adjacent function addresses.
```

---

### 4.2 ARM64 Live Verification Logs

#### Base / Monolithic KASLR (`fgkaslr-disabled`)
```text
Kernel cmdline: console=ttyAMA0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=0
Boot Mode: FG-KASLR DISABLED via boot param (fgkaslr=0)
FGKASLR_STATUS:        DISABLED
LEAK_FUNC_ADDR:        0xffffa3be17b12b24
DEFAULT_TARGET_ADDR:   0xffffa3be17b12b50
ACTIVE_TARGET_ADDR:    0xffffa3be17b12b50
STATIC_DELTA:          44
ACTUAL_DELTA:          44
DELTA_MISMATCH:        0
[!] VULNERABILITY CONFIRMED: Monolithic KASLR defeated via relative offset!
```

#### Hardened / FG-KASLR (`fgkaslr`)
```text
Kernel cmdline: console=ttyAMA0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=1
Boot Mode: FG-KASLR ENABLED via boot param (fgkaslr=1)
FGKASLR_STATUS:        ENABLED
LEAK_FUNC_ADDR:        0xffffd2fb3ed12b24
DEFAULT_TARGET_ADDR:   0xffffd2fb3ed12b50
ACTIVE_TARGET_ADDR:    0xffffd2fb3ed12b74
STATIC_DELTA:          44
ACTUAL_DELTA:          80
DELTA_MISMATCH:        36
ACTIVE_SLOT:           1
[-] Write returned error: Invalid argument (errno = 22)
[+] DEFENSE ACTIVE: FG-KASLR prevented offset calculation!
```

---

### 4.3 Feature Comparison Matrix

| Metric | Monolithic KASLR | FG-KASLR |
| :--- | :--- | :--- |
| **Granularity** | Single monolithic `.text` block | Per-function (ELF section) |
| **Randomization Scope** | Global uniform slide ($Slide$) | Independent function permutation |
| **Relative Distance ($\Delta$)** | **Fixed constant (Deterministic)** | **Randomized per boot** |
| **Single Infoleak Defense** | **Completely defeated** | **Resilient (Uncorrelated functions)** |
| **ROP Chaining Defense** | Gadgets preserve relative spacing | Inter-function gadget chains broken |
| **Performance Overhead** | Virtually 0% | **~1-3% regression** (iTLB/BTB misses) |
| **Toolchain Compatibility** | Full native support | Conflicts with `ftrace`, `livepatch` |
| **Mainline Status** | Upstream (`CONFIG_RANDOMIZE_BASE`) | RFC stage $\rightarrow$ Succeeded by FineIBT/kCFI |

---

## 5. Performance Trade-offs & Strategic Takeaways

### 5.1 Performance & Engineering Cost
- **iTLB & BTB Miss Overhead**: Breaking spatial locality introduces memory stalls and degrades instruction cache efficiency.
- **Section Multiplication**: `-ffunction-sections` inflates relocation and symbol tables, increasing binary size.

### 5.2 Lessons for Modern Hardening
- Proves the necessity of **Defense in Depth**: Relying solely on layout randomization is fragile. Pairing memory cleansing (`STACKLEAK`) with CFI (`kCFI`/`FineIBT`) ensures layered survivability.

---

## 6. Appendix

### 6.1 Technical Presentation Script

> "Ladies and gentlemen, today we analyze FG-KASLR—Function Granular KASLR—and explore why modern security architectures evolved beyond monolithic randomization.
>
> Traditional KASLR shifts the entire kernel text using a single random slide. While this stops blind attacks using static addresses, it has a fatal flaw: the relative distance $\Delta$ between any two functions remains constant. If an attacker discovers a single memory leak, they can calculate the address of all ROP gadgets and critical functions with 100% precision.
>
> FG-KASLR was engineered to solve this by compiling functions into individual ELF sections and shuffling their order at boot time. As demonstrated in our lab, when an attacker attempts a relative offset jump after an infoleak, FG-KASLR breaks the expected delta, turning what would have been a successful exploit into an invalid branch or crash.
>
> While FG-KASLR was ultimately not merged into mainline Linux due to instruction TLB performance degradation and conflicts with ftrace and livepatching, its architectural principles laid the foundation for modern compiler-enforced Control Flow Integrity—such as Clang kCFI and hardware-assisted FineIBT."

### 6.2 Security Glossary

- **FG-KASLR (Function Granular KASLR)**: A fine-grained layout randomization technique that partitions functions into separate ELF sections and reorders them at boot time.
- **Monolithic KASLR**: Traditional KASLR that shifts the entire `.text` segment by a single uniform offset.
- **Relative Offset ($\Delta$)**: The fixed distance between two symbols in memory ($Addr_B - Addr_A$).
- **iTLB (Instruction Translation Lookaside Buffer)**: Specialized CPU cache that speeds up virtual-to-physical translation for executable code pages.
- **BTB (Branch Target Buffer)**: Hardware predictor caching jump and branch target addresses to minimize pipeline stalls.
- **kCFI (Kernel Control Flow Integrity)**: A Clang-based mitigation validating function signatures at indirect call sites during runtime.
