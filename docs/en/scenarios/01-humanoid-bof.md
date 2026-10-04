# [Scenario 01] Humanoid Wireless Daemon Buffer Overflow and Stack Canary Defense

!!! abstract "🎯 Executive Summary"
    - **Real-World Incident**: Unitree G1 EDU Humanoid Robot BLE Daemon Buffer Overflow (**CVE-2026-76640**)
    - **Threat Vector**: Unpaired BLE GATT write injecting 1,050 bytes into a 500-byte buffer
    - **Cyber-Physical Hazard**: Locomotion PC root RCE and collision detection safety overrides
    - **Primary Defense**: Compiler-based **Stack Protector (`CONFIG_STACKPROTECTOR_STRONG`)**
    - **Secondary Defenses**: **Fortify Source (`_FORTIFY_SOURCE=3`)** and **Seccomp / Least Privilege Sandboxing**


---

## 1. Real-World Humanoid Incident: Unitree G1 EDU (CVE-2026-76640)

Disclosed in August 2026 by security researcher Olivier Laflamme, the **Unitree G1 EDU Remote Code Execution (RCE) flaw** demonstrates how memory corruption in embedded robotics creates critical cyber-physical hazards ([see Section 6.1 Deep Dive](#deep-dive-bss-stack)).

```
[Proximity Attacker (< 10m BLE)]
               │ (Unpaired GATT Write: 0xFFE2)
               ▼
[Robot Daemon: btgatt-server] ──(1,050B Overwrite)──> [500B wifi_ssid Buffer Overflow]
                                                                     │ (Event Loop Callback Corruption)
                                                                     ▼
                                                   [Locomotion PC Root RCE (system())]
                                                                     │
                                                                     ▼
                                                   [💥 Collision Detection Disabled & Physical Takeover]
```

### 1.1 Root Cause Breakdown
- **Vulnerable Component**: `btgatt-server`, the background daemon handling wireless provisioning.
- **Flaw Mechanism**: During Wi-Fi setup via BLE, the daemon copies incoming strings into a **500-byte `wifi_ssid` buffer without bounds checking, enabling a 1,050-byte write**.
- **Impact**: The overflow corrupted adjacent memory structures in the event loop, causing it to invoke `system()` as `root` on the robot's Locomotion PC.

### 1.2 Cyber-Physical Hazards
- 🔴 **Collision Detection & Safety Interlocks Bypassed**: Software limits preventing high-speed impacts can be disabled.
- 🔴 **Gait Disruption**: Unsafe actuator torque commands cause severe gait instability and mechanical damage.
- 🔴 **Physical Botnet Propagation**: Compromised robots can transmit malicious payloads over BLE to adjacent units.

---

## 2. Buffer Overflow Mechanism & Stack Corruption

Buffer overflows occur when memory writes exceed designated boundaries without length verification ([see Section 6.2 Assembly Verification](#deep-dive-assembly)).

```
[ Low Memory ]
▲  [ Local Buffer: char cmd_buf[64] ] ── (Write Direction: ────────────────▶ )
│  -------------------------------------------------- [Boundary]
│  [ Stack Canary (Random Guard) ]     <--- First corrupted during overflow!
│  [ Saved Frame Pointer (RBP / X29) ]
│  [ Return Address (RIP / X30 / LR) ] <--- Attacker's hijacking target
[ High Memory ]
```

---

## 3. Interactive Architecture Diagram: 4-Phase Sequential Flow

Each phase can be examined sequentially with natural page scrolling, free from iframe scroll hijacking.

### 3.1 [Phase 1] Normal Telemetry & Safe Stack Frame
- Control console sends valid 32B BLE packet; stack canary integrity remains VALID.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase1-normal.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 1 Normal State Diagram"></iframe>
</div>

### 3.2 [Phase 2] Buffer Overflow Injection (CVE-2026-76640)
- Attacker writes 1,050B into 500B buffer via unpaired BLE GATT, corrupting canary slot.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase2-attack.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 2 Attack Diagram"></iframe>
</div>

### 3.3 [Phase 3] Canary Trap & Intercept Detonation
- Function epilogue detects canary mismatch and invokes `__stack_chk_fail()`, aborting hijacked return.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase3-trap.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 3 Trap Diagram"></iframe>
</div>

### 3.4 [Phase 4] Fail-Safe E-Stop & Joint Lock
- Hardware safety relay cuts motor power (0V), securing the humanoid in an upright locked posture.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase4-failsafe.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 4 Fail-Safe Diagram"></iframe>
</div>

<script>
window.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'diagram-resize') {
    document.querySelectorAll('iframe').forEach(function(iframe) {
      if (iframe.contentWindow === e.source) {
        iframe.style.height = e.data.height + 'px';
      }
    });
  }
});
</script>


---

## 4. Layered Hardening Defenses (Defense-in-Depth)

Memory corruption attacks like the Unitree G1 exploit are thwarted not by a single fix, but through **compiler, library, and kernel defense-in-depth**:

| Defense Layer | Security Mechanism | Applied Layer | Protected Target | Key Mitigation Effect |
| :--- | :--- | :--- | :--- | :--- |
| **1st Line** | **Stack Protector** (`CONFIG_STACKPROTECTOR_STRONG`) ([Sec 6.3](#deep-dive-compiler-flags)) | Compiler / Stack Frame | Return Address (RIP/LR) | Epilogue XOR mismatch immediately triggers `__stack_chk_fail()` (0% hijack) |
| **2nd Line** | **Fortify Source** (`_FORTIFY_SOURCE=3`) ([Sec 6.4](#deep-dive-fortify)) | Compiler / C Library | Unsafe memory functions | Pre-copy detection of buffer overflows (1,050B > 500B) invokes `SIGABRT` |
| **3rd Line** | **Least Privilege & Seccomp** | OS / Kernel LSM | Process privileges & syscalls | Unprivileged UID & blocked `execve` prevent root shell compromise |

### 4.1 Primary: Stack Protector (`CONFIG_STACKPROTECTOR_STRONG`)

<div class="grid cards vertical" markdown>

-   __⚙️ Working Mechanism__

    ---

    1.  **Prologue Random Canary Insertion**

        Compiler (GCC/Clang) injects a thread-randomized 64-bit value immediately before the return address during function prologues ([see Section 6.3 Compiler Flags](#deep-dive-compiler-flags)).

    2.  **Epilogue XOR Integrity Check**

        Before function return (`ret`), CPU compares the stack canary against the master register reference (`%gs:40` on x86, `__stack_chk_guard` on ARM64) via XOR.

-   __🛡️ Defense Impact__

    ---

    1.  **Mandatory Pre-Corruption**

        Any buffer overflow attempting to hijack the return address must overwrite the intervening canary slot first.

    2.  **Hijack Detonation & Abort**

        Mismatches abort execution immediately via `__stack_chk_fail()`, reducing arbitrary code execution success rate to **0%**.

</div>

### 4.2 Secondary: Fortify Source (`_FORTIFY_SOURCE=3`)

<div class="grid cards vertical" markdown>

-   __⚙️ Working Mechanism__

    ---

    1.  **Bounds-Checked Wrappers**

        Replaces unsafe copy functions (`memcpy`, `strcpy`, `snprintf`) with bounds-checked variants (`__memcpy_chk`) whenever buffer sizes are detectable at compile time ([see Section 6.4 Dynamic Sizing](#deep-dive-fortify)).

    2.  **Dynamic Object Sizing**

        Employs `__builtin_dynamic_object_size` to dynamically evaluate destination bounds before memory copies execute.

-   __🛡️ Defense Impact__

    ---

    1.  **Pre-Copy Detonation**

        Aborts runtime execution (`SIGABRT`) prior to buffer corruption when input length (1,050B) exceeds destination capacity (500B).

    2.  **Broad Scope Coverage**

        Protects heap allocations and BSS data segments in addition to stack buffers.

</div>

### 4.3 Isolation: Least Privilege & Seccomp System Call Filtering

<div class="grid cards vertical" markdown>

-   __⚙️ Working Mechanism__

    ---

    1.  **Unprivileged Daemon Isolation**

        Runs network daemons under isolated service accounts (`bluetooth` / `daemon`) rather than full `root`.

    2.  **Seccomp-BPF Syscall Whitelist**

        Applies BPF filters to restrict execution to essential I/O syscalls, prohibiting dangerous primitives.

-   __🛡️ Defense Impact__

    ---

    1.  **Minimized Blast Radius**

        Even if control flow is hijacked, compromised daemons lack root privileges to access locomotion hardware.

    2.  **Shell Spawn Prevention**

        Attempts to spawn shells via `execve` or `fork` are trapped instantly by the kernel with `SIGSYS` or `EPERM`.

</div>

---

## 5. Hands-on Lab & Exploit PoC Simulation

This laboratory reproduces the real-world Unitree G1 humanoid robot wireless provisioning daemon vulnerability ([CVE-2026-76640](https://nvd.nist.gov/vuln/detail/CVE-2026-76640)) using a standalone C simulator (`humanoid_bof_demo.c`), empirically demonstrating runtime behavior across vulnerable and stack canary-protected environments.

### 5.1 Vulnerable Daemon Simulator Implementation (`humanoid_bof_demo.c`)

- Lab Source Code: [`labs/scenarios/01-humanoid-bof/humanoid_bof_demo.c`](file:///home/auking45/repos/linux-kernel-hardening-lab/labs/scenarios/01-humanoid-bof/humanoid_bof_demo.c)
- **Memory Layout**: A 500-byte stack buffer (`ssid`) is placed contiguously before the simulated stack canary slot and the event callback function pointer.
- **Vulnerability Trigger**: Copies a 1,050-byte malicious BLE packet without bounds checking, corrupting adjacent stack slots.

```c
/* Key Structure in labs/scenarios/01-humanoid-bof/humanoid_bof_demo.c */
typedef struct {
    char ssid[500];               // 500-byte local stack buffer
    uint64_t simulated_canary;    // Stack canary random slot (%gs:40 / __stack_chk_guard)
    void (*event_callback)(void); // Function return address and event callback
} daemon_context_t;
```

---

### 5.2 Attack Execution & Cyber-Physical Disaster Logs

When the 1,050-byte exploit payload is injected into the vulnerable daemon compiled without stack protection (`-fno-stack-protector`), the real runtime execution telemetry displays as follows:

```bash
# Run Vulnerable Mode (No Defense Boundary)
cd labs/scenarios/01-humanoid-bof && make run-attack
```

**Runtime Warning Telemetry Output Log**:
```text
======================================================================
 🤖 Humanoid Robot BLE Daemon BOF & Hardening Laboratory (CVE-2026-76640) 
======================================================================

[MODE 2: ATTACK INJECTION WITHOUT STACK CANARY (EXPLOIT SUCCEEDS)]
[*] Processing incoming BLE GATT packet (Length: 1050 bytes, Buffer capacity: 500 bytes)...
    [!] BUFFER OVERFLOW TRIGGERED: copying 1050 bytes into 500-byte stack buffer!

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Locomotion PC Hijacked! 
======================================================================
  [*] Attacker control flow reached: __builtin_return_address(0) hijacked!
  [*] Current Context: UID = 0, EUID = 0 (root / Locomotion Daemon)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & SAFETY OVERRIDE] ---
  [🔴 PHYSICAL HAZARD] Collision Avoidance Safety Interlock (Radar Loop): DEACTIVATED
  [🔴 PHYSICAL HAZARD] Actuator Torque Limit modified: 120.0 Nm -> 350.0 Nm (OVERLOAD)
  [🔴 PHYSICAL HAZARD] Gait Trajectory: High-speed instability injected -> Risk of Violent Tip-over
  [🔴 BOTNET BEACON] BLE Transmitter reconfigured: Broadcasting worm beacon on GATT 0xFFE2
```

> **Cyber-Physical Hazard Analysis:** The moment control flow is hijacked via buffer overflow, consequences transcend traditional IT data breaches, immediately triggering irreversible physical disasters including **safety interlock deactivation and motor actuator thermal over-torque destruction**.

---

### 5.3 Post-Exploitation Phase: Sensitive Asset Exfiltration & Locomotion Socket Hijack

Immediately after obtaining a `root` shell (UID 0) through the compromised daemon, the attacker initiates secondary asset looting against the robot's local subsystem:

```text
--- [PHASE 2: LOCAL SENSITIVE ASSET EXFILTRATION] ---
  [🔓 ASSET DUMP] /etc/unitree/wpa_supplicant.conf -> PSK: "Corp_Secret_Robotics_2026!"
  [🔓 ASSET DUMP] /opt/unitree/calibration.json    -> Joint Zero-Offsets & Kinematic Matrix exfiltrated
  [🔓 ASSET DUMP] /var/run/unitree/locomotion.sock  -> Direct IPC socket connection established
```

1. **Enterprise Wi-Fi PSK Exfiltration**: Extracts corporate wireless credentials stored on the robot to pivot laterally into internal enterprise networks.
2. **Kinematic Calibration Dump**: Steals joint motor zero-point offsets and PID gain matrices to disrupt precise joint alignment and control.
3. **Locomotion IPC Socket Ingress**: Connects directly to `/var/run/unitree/locomotion.sock` Unix domain socket to inject malicious joint trajectory packets, inducing violent physical falls.

---

### 5.4 Architectural Deep Dive: Critical Distinction Between Rooting (UID 0 / Ring 3) vs Kernel Space (Ring 0)

Many system administrators and developers mistakenly assume that *"once root (UID 0) is compromised, the attacker commands absolute and omnipotent control over the entire OS and hardware"*. From the Linux kernel architecture perspective, however, **rooting and kernel control represent entirely distinct security boundaries**:

!!! tip "🛡️ Global Security Architecture Deep Dive (Overview)"
    For a comprehensive analysis of the dual isolation model between OS Identity (UID 0) and CPU Rings (Ring 0), the 4 kernel hardening interception mechanisms, and the multi-stage attack pivot lifecycle across all scenarios, refer to the **[Scenarios Roadmap & Architecture Overview: Rooting vs Kernel Space](index.md#security-boundary-root-vs-kernel)**.

```text
+-------------------------------------------------------------------------------+
| [USER SPACE (Ring 3 / EL0)]                                                   |
|   - Unprivileged User (UID 1000)                                              |
|   - Root Administrator (UID 0) <--- Position reached upon daemon compromise!  |
|     * Controls filesystem (/etc/shadow, configs) and standard networking       |
|     * [Hardware Isolation] CANNOT directly execute CPU privileged instructions|
+-------------------------------------------------------------------------------+
       │
       │ === [System Call & Hardware Privilege Boundary] ===
       │ (Kernel Hardening Defenses: Lockdown LSM, Module Signing, Strict Devmem)
       ▼
+-------------------------------------------------------------------------------+
| [KERNEL SPACE (Ring 0 / EL1)]                                                 |
|   - MMU page table manipulation, direct physical memory access, IDT tables    |
|   - Full hardware sovereignty (Kernel hardening defeat, persistent rootkits)  |
+-------------------------------------------------------------------------------+
```

#### (1) Operations Blocked by Kernel Hardening Even Under Root (UID 0)

Even when a daemon executes with full UID 0 privileges, modern Linux kernel hardening defenses strictly confine Ring 3 user space, intercepting and blocking dangerous actions:

1. **Direct Physical Memory & Kernel Code Modification Blocked (`CONFIG_STRICT_DEVMEM` / Lockdown LSM)**:
   - Even when root attempts to open `/dev/mem` or `/dev/kmem` to patch live kernel code, the kernel rejects file access with `EPERM`.
2. **Unsigned Malicious Kernel Module Loading Blocked (`CONFIG_MODULE_SIG_FORCE`)**:
   - Even if root compiles an arbitrary rootkit (`.ko`) and invokes `init_module()`, the kernel refuses to load it without a valid cryptographic signature.
3. **CPU Privileged Control Register Modification Blocked (Hardware Ring 3 Trap)**:
   - User space execution cannot invoke CPU hardware opcodes such as `mov %rax, %cr4` or write to MSRs; doing so triggers an immediate Illegal Instruction (`SIGILL`) hardware trap.
4. **Core System Binary Tampering Blocked (IMA / EVM)**:
   - Any modifications made to system binaries under root are detected and blocked at execution time if cryptographic integrity attestations fail.

#### (2) The Attacker's Next Pivot & Bridge to Scenario 02

- Consequently, after gaining user space root (UID 0), if an attacker wishes to establish persistence or manipulate the hardware MMU directly, **they must exploit a secondary privilege escalation vulnerability to break from user space (Ring 3) into kernel space (Ring 0)**.
- A classic technique for jumping from user mode into kernel mode to execute attacker payloads is **ret2usr (Return-to-User)**. The hardware MMU-level defense against this pivot forms the core of the upcoming **[Scenario 02. ret2usr & SMEP/PXN Hardware Execution Defense]**.

---

### 5.5 Active Defense Verification: Stack Canary Detection & Fail-Safe Lock

When the identical 1,050-byte exploit payload is injected into the hardened binary compiled with stack protection (`CONFIG_STACKPROTECTOR_STRONG`), the real runtime execution telemetry displays as follows:

```bash
# Run Hardened Mode (Stack Canary Active)
cd labs/scenarios/01-humanoid-bof && make run-canary
```

**Hardened Defense Telemetry Output Log**:
```text
======================================================================
 🤖 Humanoid Robot BLE Daemon BOF & Hardening Laboratory (CVE-2026-76640) 
======================================================================

[MODE 3: ATTACK INJECTION WITH STACK CANARY ACTIVE (ATTACK INTERCEPTED)]
[*] Processing incoming BLE GATT packet (Length: 1050 bytes, Buffer capacity: 500 bytes)...
    [!] BUFFER OVERFLOW TRIGGERED: copying 1050 bytes into 500-byte stack buffer!
[*] Function Epilogue: Validating Stack Canary (XOR with master guard)...

======================================================================
 [🛡️ STACK PROTECTOR TRAP DETONATED] __stack_chk_fail() invoked! 
======================================================================
  [!] Canary Mismatch Detected: Expected 0xDEADC0DEBEEFCAFE, Found 0x4141414141414141
  [!] Execution aborted: ret instruction withheld. Arbitrary code execution: 0%
  [FAIL-SAFE ACTIVE] Motor driver power cut (0V) -> Robotic joints locked safely!
```

> **Defense Conclusion:** Despite the buffer overflow occurrence, the function epilogue detected canary corruption with 100% certainty. The CPU withheld execution of the `ret` instruction and aborted the process immediately. This **preemptively and conclusively prevented** root shell acquisition and subsequent physical catastrophe.

---

## 6. Engineering Deep Dive & Technical Implementation

This section provides register- and assembly-level implementation details for systems engineers and security researchers.

### 6.1 BSS vs Stack Buffer Overflow Exploit Mechanics {: #deep-dive-bss-stack }

- The `btgatt-server` flaw originated in a static global buffer (`wifi_ssid`) allocated in the BSS segment, overwriting adjacent event-loop callback pointers.
- Had the buffer resided on a local function stack, it would constitute a classic Stack Buffer Overflow overwriting the return address (RIP/LR), where **Stack Protector** serves as the primary line of defense.
- For BSS or heap segment corruption, **Clang kCFI (Control Flow Integrity)** and **Fortify Source** act as the primary defense boundaries.
- 🔗 [Control Flow Integrity Specification: 13. Clang kCFI](../../features/13-kcfi.md)

### 6.2 x86_64 vs ARM64 Stack Frame & Epilogue Verification Assembly {: #deep-dive-assembly }

Architecture-specific assembly generated by the compiler during prologue injection and epilogue validation:

=== "x86_64"

    ```nasm
    ; [Prologue] Canary injection
    movq    %gs:40, %rax          ; Load canary from per-CPU storage
    movq    %rax, -8(%rbp)        ; Store canary directly before saved RIP

    ; [Epilogue] Canary verification
    movq    -8(%rbp), %rax
    xorq    %gs:40, %rax          ; XOR compare with reference
    jne     __stack_chk_fail      ; Detonate panic handler on mismatch
    leave
    ret
    ```

=== "ARM64 (AArch64)"

    ```asm
    ; [Prologue] Canary injection
    adrp    x8, __stack_chk_guard ; Load global guard address
    ldr     x9, [x8, :lo12:__stack_chk_guard]
    str     x9, [sp, #8]          ; Store canary on stack frame

    ; [Epilogue] Canary verification
    ldr     x10, [sp, #8]
    cmp     x9, x10               ; Register comparison
    b.ne    __stack_chk_fail      ; Branch to abort trap on mismatch
    ret
    ```

### 6.3 Compiler Flag Coverage & Kernel Recommendations {: #deep-dive-compiler-flags }

- `-fstack-protector`: Protects functions declaring `char` arrays of 8 bytes or greater.
- `-fstack-protector-strong`: Substantially expands coverage to local arrays of any type, Variable Length Arrays (VLAs), and references to stack addresses (`&local_var`).
- The Linux kernel strictly mandates `CONFIG_STACKPROTECTOR_STRONG` for production deployments.
- 🔗 [Feature Specification: 01. Stack Protector](../../features/01-stack-protector.md)

### 6.4 Fortify Source Mechanics & Dynamic Object Sizing (`_FORTIFY_SOURCE=3`) {: #deep-dive-fortify }

- `_FORTIFY_SOURCE=3` (introduced in GCC 12+ and Clang 12+) provides the highest tier of buffer verification by evaluating both compile-time and dynamic buffer sizes (`__builtin_dynamic_object_size`), aborting execution prior to memory writes.
- 🔗 [Feature Specification: 02. Fortify Source](../../features/02-fortify-source.md)

---

## 7. External Advisories & References

<div class="grid cards vertical" markdown>

-   __📌 Official CVE Database__

    ---

    1.  **CVE-2026-76640**

        Unitree G1 EDU Humanoid Robot BLE `btgatt-server` Buffer Overflow leading to Root RCE

    2.  **CVE-2026-76639**

        Unitree G1 EDU `chat_go` / `bashrunner` Path Traversal RCE

-   __🔬 Research Papers & Disclosures__

    ---

    1.  **Olivier Laflamme (The Hacker News, Aug 2026)**

        *"Two Unitree G1 EDU Humanoid Robot Flaws Enable Root RCE, One Starts Over Bluetooth"*

    2.  **Boschko Research (Aug 2026)**

        *"Deep Dive: G1 BLE RCE Chain Technical Disclosure & Physical Safety Risks"*

    3.  **Trend Micro & PoliMi (CPS Security Analysis)**

        *"Rogue Robots: Testing the Limits of an Industrial Robot’s Security"*

-   __🛡️ Kernel Hardening & Embedded Standards__

    ---

    1.  **Linux Kernel Hardening Project**

        [Compiler-based Stack Protection Mechanics](https://kernsec.org/)

    2.  **NIST SP 800-82 Rev. 3**

        Guide to Operational Technology (OT) Security

    3.  **CIS Linux Benchmark**

        Section 1.5 - Memory Protection & Compiler Flags

</div>
