# [Scenario 03] User Data Access (ret2dir / SMAP) & ARM64 PAN Hardware Data Isolation Defense

!!! abstract "🎯 Executive Summary"
    - **Real-World Exploit**: Linux kernel packet socket Use-After-Free race condition corrupting object pointers (**CVE-2016-8655**)
    - **Threat Vector**: With SMEP/PXN blocking user-space code execution, the attacker places a fake motion safety policy (`struct robot_safety_policy`) in user memory and causes a kernel pointer to directly dereference user virtual address `0x00405000`
    - **Cyber-Physical Hazard**: Kernel supervisor privilege (Ring 0) blindly ingests the hostile fake object as valid data, driving actuator torque limits from 120Nm to 650Nm and purging collision radar margins and emergency stop interlocks
    - **Primary Defense**: Hardware MMU-enforced **x86 CR4.SMAP (Supervisor Mode Access Prevention)** and **ARM64 PSTATE.PAN (Privileged Access Never)**
    - **Complementary Defenses**: Memory copy bounds verification **Hardened Usercopy (`CONFIG_HARDENED_USERCOPY`)** and page table separation **KPTI**

---

## 1. Real-World Kernel Incident: CVE-2016-8655 & Locomotion Object Tampering

As demonstrated in [Scenario 02](02-ret2usr.md), hardware MMU enforcement via **SMEP (`CR4.SMEP=1`) and PXN (`PTE_PXN=1`)** completely neutralizes instruction fetching from user memory while running in supervisor mode (Ring 0).

To overcome this defense, attackers adapted by keeping execution within legitimate kernel code (`.text`) while **diverting kernel data pointers to dereference data structures crafted in user memory**—an attack known as **Confused Deputy** or **ret2dir** ([see Section 6.4 Deep Dive](#deep-dive-ret2dir)).

```
[Robot User Space (Locomotion PC: Ring 3 / EL0)]
               │ (mmap: Fake safety policy allocated at 0x00405000)
               ▼
[Fake Safety Policy: struct robot_safety_policy] ──(Torque: 650Nm, Radar: 0m, E-Stop: Purged)
               ▲
               │ (CVE-2016-8655: packet_sock UAF race corrupts kernel policy pointer)
[Kernel Locomotion Loop (Ring 0 / EL1)] ──(g_active_policy direct dereference)
               │
               ▼
[💥 Without SMAP: Hostile data ingested -> Joint torque overload & violent tip-over collision]
```

### 1.1 Root Cause Breakdown

- **Vulnerable Component**: `packet_set_ring()` function in `net/packet/af_packet.c` within the Linux kernel networking subsystem.
- **Flaw Mechanism**: Lock contention during packet ring buffer creation and teardown creates a **Use-After-Free (UAF) race condition, allowing an attacker to corrupt the freed `packet_sock` memory slot** with an arbitrary user-space address.
- **Fake Kernel Object Injection**: Instead of attempting to execute shellcode, the attacker allocates a fake safety profile in user space (`0x00405000`) matching the exact layout of the kernel's kinematic control structures.
- **Direct Dereference Flaw**: In legacy kernels without SMAP, the CPU in supervisor mode (Ring 0) was permitted to read and write user-space addresses (`< TASK_SIZE`). When kernel code dereferenced `active_policy->max_joint_torque`, the hostile 650Nm value was ingested without validation.

### 1.2 Cyber-Physical Hazards

Corrupting kernel control structures compromises the robot's real-time kinematic feedback loop:

- 🔴 **Actuator Torque Overload (650Nm vs 120Nm)**: Exceeding design limits by over 500% strips harmonic reduction gears and burns out motor stator windings.
- 🔴 **Collision Detection Radar Nullified**: Clearing the safety margin from 0.50m to 0.00m causes high-speed physical impacts with obstacles and personnel.
- 🔴 **Safety Interlocks Disabled**: The emergency stop flag is cleared, preventing automated fail-safe halts upon kinematic instability.

---

## 2. Technical Mechanism & Data Boundary Breach (ret2dir vs SMAP)

The vulnerability stems from the **historic absence of data access separation between Kernel Mode (Ring 0) and User Mode (Ring 3)** ([see Section 6.3 Hardware Exception Decoding](#deep-dive-smap-pf)).

### 2.1 Virtual Address Space Split & Historic Architecture Gap

In 64-bit Linux architectures, virtual addresses are divided into two regions:

```
[ 0x0000000000000000 ~ 0x00007FFFFFFFFFFF ] : User Space Memory (U/S bit = 1)
   - Attacker crafts fake struct robot_safety_policy (0x00405000)
   - [Historic Flaw] Ring 0 CPU was allowed to read/write this memory directly via MOV/LDR!

─────────────────────── [TASK_SIZE Boundary] ───────────────────────

[ 0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF ] : Kernel Space Memory (U/S bit = 0)
   - Kernel .text, internal state, driver MMIO mappings
```

1. **The Limitation of SMEP without SMAP**:
   - SMEP (`CR4` Bit 20) restricts only **instruction fetching (RIP branching)** from user memory.
   - It does not prevent the CPU in Ring 0 from executing `MOV (%rax), %rbx` to **read or write data in user memory**.
2. **Confused Deputy Attack Paradigm**:
   - The attacker tricks the kernel into reading its critical control parameters from `0x00405000`.
   - The kernel, acting with supervisor authority, reads the hostile data and applies it across the system.

---

## 3. Interactive Architecture Diagram: 4-Phase Sequential Flow

Each phase can be examined sequentially with natural page scrolling, free from iframe scroll hijacking.

### 3.1 [Phase 1] Normal Usercopy via STAC/CLAC Hardware Window
- The kernel temporarily opens a hardware access window (`EFLAGS.AC=1`) via `stac` during `copy_from_user()`, closing it immediately via `clac` upon completion.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase1-normal.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 1 Normal Usercopy Diagram"></iframe>
</div>

### 3.2 [Phase 2] Fake Object Dereference without SMAP
- In an unhardened kernel, a UAF flaw causes Ring 0 to directly dereference user memory (0x00405000), ingesting the 650Nm overload and disabling safety radar.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase2-attack.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 2 Attack Diagram"></iframe>
</div>

### 3.3 [Phase 3] Hardware MMU SMAP/PAN Trap Execution (#PF 0x0015)
- With `CR4.SMAP=1` and `EFLAGS.AC=0` active, direct read attempts from user memory are intercepted by the MMU with 0 clock latency, detonating `#PF (0x0015)`.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase3-trap.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 3 Trap Diagram"></iframe>
</div>

### 3.4 [Phase 4] Fail-Safe E-Stop & Joint Lockdown
- Immediate exception handling trips the hardware safety relay to cut motor power to 0.0V and engages spring-loaded brakes to hold the robot securely upright.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase4-failsafe.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 4 Fail-Safe Diagram"></iframe>
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
  if (e.data && e.data.type === 'diagram-theme-change') {
    document.querySelectorAll('iframe').forEach(function(iframe) {
      try {
        iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: e.data.theme }, '*');
      } catch(err){}
    });
  }
});

function syncMkDocsThemeToIframes() {
  const scheme = document.body.getAttribute('data-md-color-scheme');
  const target = scheme === 'default' ? 'light' : 'dark';
  document.querySelectorAll('iframe').forEach(function(iframe) {
    try {
      iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: target }, '*');
    } catch(err){}
  });
}
const themeObserver = new MutationObserver(function(mutations) {
  mutations.forEach(function(mutation) {
    if (mutation.attributeName === 'data-md-color-scheme') {
      syncMkDocsThemeToIframes();
    }
  });
});
themeObserver.observe(document.body, { attributes: true, attributeFilter: ['data-md-color-scheme'] });
</script>

---

## 4. Layered Defenses Against Data Tampering (Defense-in-Depth)

Neutralizing fake object dereferencing and ret2dir requires a three-tiered defense:

| Defense Layer | Security Mechanism | Applied Layer | Protected Target | Primary Intercept Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **1st Line** | **SMAP (x86) / PAN (ARM64)** ([Section 6.1](#deep-dive-smap-asm)) | CPU MMU Hardware | User Memory Data | `#PF` (0x0015) trap when `EFLAGS.AC=0` during supervisor loads/stores |
| **2nd Line** | **Hardened Usercopy** (`CONFIG_HARDENED_USERCOPY`) | Kernel C Library | `copy_from_user` | Aborts operations exceeding slab object boundaries or current stack frames |
| **3rd Line** | **KPTI (Kernel Page Table Isolation)** | Kernel Virtual Memory | Page Table Structure | Completely unmaps user-space pages while running in kernel mode |

### 4.1 [1st Line of Defense] SMAP (x86) & PAN (ARM64) Hardware Data Isolation

<div class="grid cards vertical" markdown>

-   __⚙️ Operating Mechanism__

    ---

    1.  **Register Activation & Flag Monitoring**

        During boot, Bit 21 (`X86_CR4_SMAP`) of `CR4` is enabled ([Section 6.1](#deep-dive-smap-asm)). On ARM64, the `PSTATE.PAN` bit is asserted.

    2.  **Explicit STAC / CLAC Access Windows**

        Access to user memory is prohibited except during brief intervals where `EFLAGS.AC=1` is set via `stac`, immediately cleared with `clac` upon completion.

-   __🛡️ Defense Impact__

    ---

    1.  **Direct Dereference Prevention**

        Attempts to dereference user pointers outside authorized windows trigger an immediate hardware exception.

    2.  **Elimination of Fake Object Attack Surfaces**

        The kernel cannot read attacker-controlled structures or forged credentials (`struct cred`) residing in user space.

</div>

### 4.2 [2nd Line of Defense] Hardened Usercopy (`CONFIG_HARDENED_USERCOPY`)

<div class="grid cards vertical" markdown>

-   __⚙️ Operating Mechanism__

    ---

    1.  **Slab Allocation Bounds Verification**

        Validates that target kernel buffers reside within valid, allocated slab object boundaries during `copy_from_user()`.

    2.  **Stack Frame Boundary Enforcement**

        Prevents copies into kernel stack memory that extend past the active function frame.

-   __🛡️ Defense Impact__

    ---

    1.  **Protection Against Exploited Copy Primitives**

        Blocks attackers from misdirecting legitimate copy APIs toward critical adjacent kernel objects.

    2.  **Prevention of Secondary Heap Corruptions**

        Restricts copy lengths to safe boundaries, stopping heap and stack overflow escalation.

</div>

### 4.3 [3rd Line of Defense] KPTI (Kernel Page Table Isolation)

<div class="grid cards vertical" markdown>

-   __⚙️ Operating Mechanism__

    ---

    1.  **Physical Page Table Separation**

        Maintains separate page tables for user-space and kernel-space execution (`CR3` switching).

    2.  **Unmapped User Pages in Kernel Context**

        User-space page translations are absent from the MMU while executing kernel code.

-   __🛡️ Defense Impact__

    ---

    1.  **Mitigation of Direct-Mapped (ret2dir) Exploits**

        Eliminates indirect user memory mappings in kernel space.

    2.  **Side-Channel & Meltdown Mitigation**

        Prevents speculative memory leakage between user and kernel domains.

</div>

---

## 5. Hands-on Lab & Exploit Simulation Demo (Hands-on Lab & Exploit PoC)

This lab models a robot locomotion safety policy corruption scenario ([CVE-2016-8655](https://nvd.nist.gov/vuln/detail/CVE-2016-8655)) in C (`smap_demo.c`) to verify behavior under unhardened versus SMAP/PAN-hardened configurations.

### 5.1 Architecture & Implementation (`smap_demo.c`)

- Code Location: [`labs/scenarios/03-smap/smap_demo.c`](file:///home/auking45/repos/linux-kernel-hardening-lab/labs/scenarios/03-smap/smap_demo.c)
- **Memory Structure**: The active safety policy pointer (`g_active_policy`) is redirected to a hostile fake policy (`g_user_fake_policy`) in user space.
- **MMU Simulation**: Models x86 `CR4.SMAP`, `EFLAGS.AC`, and ARM64 `PSTATE.PAN` to determine whether direct data accesses to user virtual addresses (`< TASK_SIZE`) are permitted in Ring 0.

```c
/* labs/scenarios/03-smap/smap_demo.c Core Structure */
typedef struct {
    uint32_t magic;              // "SAFE" magic header
    float    max_joint_torque;   // Rated 120Nm -> Hostile forged 650Nm
    float    collision_margin;   // Normal 0.50m -> Hostile forged 0.00m
    uint32_t emergency_stop_en;  // Normal 1 -> Hostile forged 0 (Disabled)
} robot_safety_policy_t;

// Attacker-controlled fake policy allocated in User Space (Ring 3)
static robot_safety_policy_t g_user_fake_policy = {
    .max_joint_torque  = 650.0f,
    .collision_margin  = 0.0f,
    .emergency_stop_en = 0
};
```

---

### 5.2 Attack Execution & Cyber-Physical Disaster Logs

Running the vulnerable daemon without SMAP (`CR4.SMAP=0`):

```bash
# Run vulnerable mode (without SMAP/PAN defense)
cd labs/scenarios/03-smap && make run-attack
```

**Runtime Warning Telemetry Output**:
```text
======================================================================
 🤖 Humanoid Robot ret2dir / Fake Object & SMAP/PAN Lab (CVE-2016-8655) 
======================================================================

[MODE 2: RET2DIR / FAKE OBJECT ATTACK WITHOUT SMAP (CR4.SMAP=0, PAN=0)]
[*] Simulating CVE-2016-8655: AF_PACKET packet_sock Use-After-Free race condition...
    [!] Attacker crafts Fake Safety Object in User Space (Ring 3): Address = 0x580044b7a038
    [!] UAF flaw corrupts kernel safety pointer: g_active_policy = 0x580044b7a038
[*] Kernel Locomotion Loop executes in Ring 0: Dereferencing g_active_policy directly...

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Confused Deputy / Fake Object Dereferenced! 
======================================================================
  [*] Kernel blindly accepted user-space fake object: 'Attacker_Hostile_Override'
  [*] Current Context: Ring 0 (CPL=0), Direct User Data Access: ALLOWED

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & KINEMATIC INTEGRITY BREACH] ---
  [🔴 PHYSICAL HAZARD] Joint Torque Limit Overwritten: 120.0 Nm -> 650.0 Nm (FATAL OVERLOAD)
  [🔴 PHYSICAL HAZARD] Collision Margin Nullified: 0.50 m -> 0.00 m (RADAR BLINDED)
  [🔴 PHYSICAL HAZARD] Emergency Stop Interlock: DISABLED (PHYSICAL SAFETY PURGED)
  [🔴 ACTUATOR RUNAWAY] High-velocity leg swing commanded -> Violent collision inevitable!
```

> **Cyber-Physical Hazard Analysis:** Without SMAP, the kernel dereferences user memory directly. Actuator torque surges to 650Nm and the emergency stop is purged, causing severe joint burnout and high-speed collision hazards.

---

### 5.3 Post-Exploitation Phase: What Happens After Fake Object Dereference? {: #53-post-exploitation-phase }

Following successful fake object dereferencing, attackers execute secondary system compromise:

1. **Privilege Escalation via Forged Credentials (`struct cred`)**:
   - The attacker allocates a fake credential structure with all IDs set to 0 and redirects `current->cred`, granting root privileges across the OS.
2. **Control Flow Hijacking via Fake File Operations (`struct file_operations`)**:
   - Forged function tables in user memory redirect indirect kernel calls to attacker-chosen gadgets.
3. **Stack Pivoting to User Memory**:
   - The kernel stack pointer (RSP) is redirected to an attacker-controlled ROP chain in user space.
4. **Permanent Actuator Calibration Corruption**:
   - Motor PID gains are corrupted to trigger mechanical resonance and gearhead destruction.

---

### 5.4 Hardened Defense Output: Hardware MMU Trap & Fail-Safe State

Executing the same attack against an active SMAP/PAN system:

```bash
# Run hardened mode (SMAP/PAN active)
cd labs/scenarios/03-smap && make run-hardened
```

**Defense Telemetry Output**:
```text
======================================================================
 🤖 Humanoid Robot ret2dir / Fake Object & SMAP/PAN Lab (CVE-2016-8655) 
======================================================================

[MODE 3: RET2DIR ATTACK INTERCEPTED BY HARDENED MMU (CR4.SMAP=1, PAN=1)]
[*] Simulating CVE-2016-8655: AF_PACKET packet_sock Use-After-Free race condition...
    [!] Attacker crafts Fake Safety Object in User Space (Ring 3): Address = 0x580044b7a038
    [!] UAF flaw corrupts kernel safety pointer: g_active_policy = 0x580044b7a038
[*] Kernel Locomotion Loop executes in Ring 0: Attempting direct dereference...
    [*] Hardware MMU Intercept: Validating Data Access (CPL=0 vs U/S bit)...

    [!] MMU ACCESS VIOLATION: Supervisor (Ring 0) attempted direct READ to User Page (0x580044b7a038)!
======================================================================
 [🛡️ HARDWARE MMU TRAP DETONATED] SMAP / PAN Page Fault (#PF)! 
======================================================================
  [!] VIOLATION DETECTED: Supervisor Mode (Ring 0) attempted unauthorized User Data Read!
  [!] Hardware Registers:
      CR4.SMAP = 1 (Active) | EFLAGS.AC = 0 (Locked) | PSTATE.PAN = 1
      Dereference Target = 0x580044b7a038 (User Virtual Address < TASK_SIZE)
      Page Fault Error Code = 0x0015 (P=1, W/R=0, U/S=0, I/D=0, SMAP Violation)
  [!] Direct read aborted: Fake parameters rejected. Memory tampering: 0%

  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Spring-loaded parking brakes LOCKED. Robotic joints secured safely!
```

> **Defense Conclusion:** The CPU MMU intercepts direct user memory access on the initial read, raising `#PF (0x0015)`. Zero bytes of hostile data enter the kernel, and the safety relay locks the robot into an upright halt.

---

## 6. Engineering Deep Dive

Detailed register specifications and hardware exception decoding for system engineers.

### 6.1 x86_64 CR4.SMAP Control Register & STAC/CLAC Assembly {: #deep-dive-smap-asm }

On Intel Haswell and AMD processors, SMAP resides at Bit 21 of `CR4`:

```nasm
; [x86_64] Boot Initialization (arch/x86/kernel/cpu/common.c)
movq    %cr4, %rax            ; Read current CR4
btsq    $21, %rax             ; Set Bit 21 (X86_CR4_SMAP: 1 << 21 = 0x00200000)
movq    %rax, %cr4            ; Write back -> SMAP active in hardware
```

- **EFLAGS.AC (Alignment Check, Bit 18) Control**:
  - `stac`: Sets `EFLAGS.AC = 1`, temporarily enabling supervisor access to user space.
  - `clac`: Clears `EFLAGS.AC = 0`, immediately re-engaging user memory isolation.
  - The kernel strictly restricts `stac`/`clac` invocations to paired wrappers inside `copy_from_user()`.
- 🔗 [Feature Specification: 10. SMAP & PAN Hardware Data Isolation Analysis](../../features/10-smap-pan.md)

### 6.2 ARM64 PSTATE.PAN (Privileged Access Never) Control {: #deep-dive-pan-arm }

On ARMv8.1-A and later architectures, the `PSTATE.PAN` bit enforces access control:

```asm
; [ARM64] Usercopy Access Window
msr     pan, #0               ; Clear PAN -> Allow EL1 access to EL0 memory (stac equivalent)
ldr     x1, [x0]              ; Safely copy data from user virtual address (x0)
msr     pan, #1               ; Set PAN -> Re-arm isolation (clac equivalent)
```

- If `PSTATE.PAN = 1` and EL1 code attempts a load (`LDR`) or store (`STR`) to an EL0 address, the MMU fires a **Data Abort Exception** (`DFSR` / `ESR_EL1` EC `0x25`).

### 6.3 Hardware `#PF` Error Code 0x0015 Bit-field Dissection {: #deep-dive-smap-pf }

When `#PF` occurs on x86 due to an SMAP violation, the CPU pushes a 32-bit error code onto the stack:

| Bit Position | Flag Name | Value | Meaning |
| :--- | :--- | :--- | :--- |
| **Bit 0** | **P (Present)** | `1` | Page is present in physical memory (protection violation) |
| **Bit 1** | **W/R (Write/Read)** | `0` | Access was a **Data Read** (1 if write) |
| **Bit 2** | **U/S (User/Supervisor)** | `0` | Access occurred in **Supervisor Mode (Ring 0)** |
| **Bit 4** | **I/D (Instruction Fetch)** | `0` | Access was **Data Access** (distinguishes SMAP from SMEP) |
| **Bit 5** | **PK (Protection Key / SMAP)**| `0` | Standard protection fault |

- **Combined Value**: `0x0001` (Bit 0) | `0x0004` (Bit 2 SMAP violation signature) = **`0x0015`**.
- The page fault handler (`arch/x86/mm/fault.c`) recognizes this as an unauthorized supervisor access (`spurious_kernel_fault`) and triggers a kernel panic.

### 6.4 The Physmap Direct-Mapping Exploit (ret2dir) & Mitigations {: #deep-dive-ret2dir }

- **ret2dir Mechanics**: Instead of referencing user virtual addresses (`< TASK_SIZE`), ret2dir leverages the kernel's **direct physical memory map (physmap)** to access user-allocated physical frames via kernel addresses.
- **Defenses**:
  - **XPFO (eXclusive Page Frame Ownership)**: Unmaps user pages from the kernel physmap to eliminate ret2dir attack vectors.
  - **KPTI**: Maintains isolated page tables to prevent cross-domain translation leaks.
- 🔗 [Feature Specification: 12. KPTI (Kernel Page Table Isolation)](../../features/12-kpti.md)

---

## 7. External Advisories & References

<div class="grid cards vertical" markdown>

-   __📌 Official CVE Database__

    ---

    1.  **CVE-2016-8655**

        Linux Kernel `packet_set_ring` AF_PACKET Race Condition Use-After-Free Privilege Escalation

    2.  **CVE-2017-6074**

        Linux Kernel DCCP Protocol `dccp_rcv_state_process` Use-After-Free leading to Local Privilege Escalation

-   __🔬 Research & Technical Reports__

    ---

    1.  **Philip Pettersson (2016)**

        *"Vulnerability Disclosure: CVE-2016-8655 Linux packet_socket UAF Exploit Analysis"*

    2.  **Vasileios P. Kemerlis et al. (USENIX Security, 2014)**

        *"ret2dir: Rethinking Kernel Isolation & Physical Address Space Exploitation"*

    3.  **Intel 64 and IA-32 Architectures Software Developer's Manual**

        Volume 3A: System Programming Guide - Section 4.6 (Supervisor-Mode Access Prevention & EFLAGS.AC)

-   __🛡️ Kernel Hardening & Standards__

    ---

    1.  **Linux Kernel Hardening Project**

        [Hardware-assisted Data Access Protection (SMAP & PAN)](https://kernsec.org/)

    2.  **ARM Architecture Reference Manual (ARMv8/v9-A)**

        Section D5: Memory System Architecture - Privileged Access Never (PAN) Mechanism

    3.  **Kernel Documentation (x86)**

        `Documentation/arch/x86/smap.rst` - Supervisor Mode Access Prevention Mechanics

</div>
