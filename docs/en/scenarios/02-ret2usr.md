# [Scenario 02] Kernel Pointer Hijack via ret2usr and SMEP/PXN Hardware Execution Defense

!!! abstract "🎯 Executive Summary"
    - **Real-World Exploit**: Linux kernel packet socket heap out-of-bounds function pointer hijack (**CVE-2017-7308**)
    - **Threat Vector**: User-space Root (UID 0) process triggers socket option (`packet_set_ring`) integer overflow to overwrite kernel function pointer with user virtual address (`0x00401337`)
    - **Cyber-Physical Hazard**: Kernel supervisor privilege (Ring 0) executing user shellcode, killing hardware watchdog thread and driving motor current overload (15A -> 85A)
    - **Primary Defense**: Hardware MMU-enforced **x86 CR4.SMEP (Supervisor Mode Execution Prevention)** and **ARM64 PTE_PXN (Privileged Execute-Never)**
    - **Complementary Defenses**: User data access prevention **SMAP/PAN** and page table separation **KPTI (Kernel Page Table Isolation)**

---

## 1. Real-World Kernel Incident: CVE-2017-7308 & Locomotion PC Ring 0 Takeover

In [Scenario 01](01-humanoid-bof.md), the attacker attained user-space Root (UID 0) on the Locomotion PC via a wireless daemon buffer overflow (CVE-2026-76640). However, modern kernel hardening (`Strict Devmem`, `Lockdown LSM`, `Module Signing`) strictly blocked direct access to physical memory registers and MMU control ([see Section 5.3 Architecture Analysis](#53-post-exploitation-phase-what-happens-after-ring-0-breach)).

To escalate privileges from User Space (Ring 3) to Kernel Space (Ring 0), the attacker pivots to **CVE-2017-7308**, a notorious heap out-of-bounds vulnerability in the Linux socket subsystem ([see Section 6.1 Deep Dive](#deep-dive-smep-reg)).

```
[Robot User Space (Locomotion PC: UID 0 / Ring 3)]
               │ (setsockopt: PACKET_RX_RING integer overflow)
               ▼
[Kernel AF_PACKET Handler: packet_set_ring] ──(SLUB Heap Overwrite)──> [struct packet_sock]
                                                                              │ (Function Pointer Hijack)
                                                                              ▼
                                                            [Ring 0 Kernel Worker branches to User Memory]
                                                                              │ (0x00401337 jump)
                                                                              ▼
                                                            [💥 Watchdog Killed & Motor Overload 85A]
```

### 1.1 Root Cause Breakdown

- **Vulnerable Component**: `packet_set_ring()` function in `net/packet/af_packet.c` within the Linux kernel networking subsystem.
- **Flaw Mechanism**: When configuring the packet ring buffer size via the `setsockopt()` system call, an **integer overflow during block size calculation allows an out-of-bounds write into the SLUB heap allocator**.
- **Control Flow Hijack**: The attacker overwrites adjacent function pointers within `struct packet_sock` (such as `prb_close_block` or `packet_rcv`) with the address of shellcode pre-allocated in user space (`0x00401337`).
- **ret2usr Execution**: When the kernel receives a packet or closes the socket ring, the CPU in supervisor mode (Ring 0) jumps directly into user-space memory (`0x00401337`) and executes arbitrary code with highest supervisor authority.

### 1.2 Cyber-Physical Hazards

Kernel-level (Ring 0) takeover leads to catastrophic hardware destruction far exceeding user-space root privileges:

- 🔴 **Hardware Safety Watchdog Terminated**: Kernel timer interrupt handlers and watchdog kick routines are purged from memory, preventing fail-safe interlocks upon system hang.
- 🔴 **Actuator Gate Driver Current Overload**: Direct memory-mapped I/O (MMIO) register writes bypass CAN/EtherCAT buses to drive motor current from rated 15A to destructive 85A.
- 🔴 **Mechanical Destruction & Fire Risk**: Continuous overload burns out BLDC motor windings, strips reduction gearheads, and risks battery BMS thermal runaway.

---

## 2. Technical Mechanism & ret2usr Memory Boundary Breach

Return-to-User (ret2usr) exploitation exploits the **historic lack of hardware execution separation between Kernel Mode (Ring 0) and User Mode (Ring 3)** ([see Section 6.3 Hardware Exception Decoding](#deep-dive-pf-decode)).

### 2.1 Virtual Address Space Split & Historic Architecture Gap

In 64-bit Linux architectures, the canonical virtual address space is split into two halves:

```
[ 0x0000000000000000 ~ 0x00007FFFFFFFFFFF ] : User Space (Ring 3 / EL0)
   - Attacker maps shellcode at arbitrary address (e.g., 0x00401337)
   - Page Table Entry (PTE) User/Supervisor bit = 1 (User Accessible)

─────────────────────── [TASK_SIZE Boundary] ───────────────────────

[ 0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF ] : Kernel Space (Ring 0 / EL1)
   - Kernel code (.text), internal structures, MMIO mappings
   - Page Table Entry (PTE) User/Supervisor bit = 0 (Supervisor Only)
```

1. **Historic x86/ARM Architectural Flaw**:
   - In supervisor mode (Ring 0), the CPU gained full access across the entire address space.
   - However, legacy CPU hardware did not restrict Ring 0 from fetching instructions located in user-space addresses (`< TASK_SIZE`).
2. **ret2usr Attack Steps**:
   - Step 1: The attacker maps executable user memory (`0x00401337`) containing privilege escalation code (e.g., calling `commit_creds(prepare_kernel_cred(0))`).
   - Step 2: The attacker triggers a kernel vulnerability to overwrite a kernel function pointer with `0x00401337`.
   - Step 3: A kernel worker invokes the corrupted pointer (`call *%rax`).
   - Step 4: The CPU **executes instructions from user-space memory while retaining supervisor (Ring 0) privilege**.

---

## 3. Interactive Architecture Diagram: 4-Phase Sequential Flow

Each phase can be examined sequentially with natural page scrolling, free from iframe scroll hijacking.

### 3.1 [Phase 1] Normal Syscall Dispatch
- User-space process issues a `syscall`, handled safely by Ring 0 kernel workers in kernel memory (`0xffffffff81...`) before returning via `SYSRET`.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase1-normal.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 1 Normal Syscall Dispatch Diagram"></iframe>
</div>

### 3.2 [Phase 2] ret2usr Attack Injection
- In an unhardened kernel (`CR4.SMEP=0`), a corrupted function pointer diverts Ring 0 execution to user memory (`0x00401337`), killing the watchdog and driving motor current to 85A.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase2-attack.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 2 Attack Injection Diagram"></iframe>
</div>

### 3.3 [Phase 3] Hardware MMU Trap Execution (SMEP / PXN)
- With hardware defenses active (`CR4.SMEP=1` / `PTE_PXN=1`), the MMU intercepts instruction fetching from user memory during Ring 0 execution with 0 clock latency, firing a Page Fault (`#PF` Error Code `0x0011`).

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase3-trap.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 3 Hardware Trap Diagram"></iframe>
</div>

### 3.4 [Phase 4] Fail-Safe E-Stop & Joint Lockdown
- Immediate exception handling triggers the hardware safety relay to de-energize the motor bus to 0V and engages spring-loaded brakes to hold the robot securely upright.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/ret2usr/phase4-failsafe.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 4 Fail-Safe Lockdown Diagram"></iframe>
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

// MkDocs theme change detection and synchronization to iframe diagrams
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

## 4. Layered Defenses Against ret2usr (Defense-in-Depth)

Neutralizing ret2usr requires a multi-layered defensive strategy combining **hardware CPU register enforcement, page table isolation, and access prevention**:

| Defense Layer | Security Mechanism | Applied Layer | Protected Target | Primary Intercept Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **1st Line** | **SMEP (x86) / PXN (ARM64)** ([Section 6.1](#deep-dive-smep-reg)) | CPU MMU Hardware | Kernel Code Flow | `#PF` (0x0011) trap on instruction fetch from user pages during Ring 0 |
| **2nd Line** | **SMAP (x86) / PAN (ARM64)** | CPU MMU Hardware | Kernel Data Flow | Blocks unauthorized read/write access to user memory in Ring 0 (prevents stack pivoting) |
| **3rd Line** | **KPTI (Kernel Page Table Isolation)** | Kernel Virtual Memory | Page Table Structure | Completely unmaps user-space pages while executing in kernel mode |

### 4.1 [1st Line of Defense] SMEP (x86) & PXN (ARM64) Hardware Execution Prevention

<div class="grid cards vertical" markdown>

-   __⚙️ Operating Mechanism__

    ---

    1.  **Hardware Control Register Activation**

        During x86_64 boot (`arch/x86/kernel/cpu/common.c`), the kernel sets Bit 20 (`X86_CR4_SMEP`) of control register `CR4` ([Section 6.1](#deep-dive-smep-reg)). On ARM64, Bit 53 (`PTE_PXN`) is asserted in Stage 1 translation tables ([Section 6.2](#deep-dive-pxn-arm)).

    2.  **MMU Instruction Fetch Monitoring**

        While the CPU operates in supervisor mode (CPL=0 / EL1), the MMU validates the $User/Supervisor$ flag in the TLB and page table descriptors on every instruction fetch.

-   __🛡️ Defense Impact__

    ---

    1.  **Zero-Latency Hardware Trap**

        The instant an instruction fetch targeting a user page (`U/S=1`) occurs in supervisor mode, the CPU triggers a Page Fault (`#PF` 0x0011), aborting execution before any instructions run.

    2.  **Complete Neutralization of Classic ret2usr**

        Even if an attacker crafts complex shellcode in user memory, jumping to that address from Ring 0 causes an immediate kernel panic.

</div>

### 4.2 [2nd Line of Defense] SMAP (Supervisor Mode Access Prevention) & ARM64 PAN

<div class="grid cards vertical" markdown>

-   __⚙️ Operating Mechanism__

    ---

    1.  **User Data Read/Write Restriction**

        While SMEP prevents instruction execution, SMAP (`CR4` Bit 21) and PAN (`PSTATE.PAN`) forbid Ring 0 read or write access to user-space addresses.

    2.  **Explicit Whitelisting via Safe APIs**

        When the kernel legitimately needs user data, access is temporarily unmasked using `stac` / `clac` instructions (ARM64: `msr pan, #0`) exclusively wrapped inside `copy_from_user()`.

-   __🛡️ Defense Impact__

    ---

    1.  **Stack Pivoting Prevention**

        Prevents attackers from switching the kernel stack pointer (RSP) into user-space memory to execute ROP chains.

    2.  **Indirect Data Dereference Mitigation**

        Blocks secondary exploitation vectors where kernel code dereferences user pointers to resolve jump targets.

</div>

### 4.3 [3rd Line of Defense] KPTI (Kernel Page Table Isolation)

<div class="grid cards vertical" markdown>

-   __⚙️ Operating Mechanism__

    ---

    1.  **Dual Page Table Architecture**

        Maintains two distinct sets of page tables (`CR3` switching): one for user-space execution and one for kernel-space execution.

    2.  **Masked User Mappings in Kernel Mode**

        While running in kernel mode, user-space virtual addresses are completely unmapped in the MMU and TLB.

-   __🛡️ Defense Impact__

    ---

    1.  **Side-Channel & Meltdown Mitigation**

        Prevents speculative execution side channels from leaking kernel memory to user mode.

    2.  **SMEP Defense Redundancy**

        Provides defense-in-depth against hardware bugs or register manipulation by eliminating user mappings entirely.

</div>

---

## 5. Hands-on Lab & Exploit Simulation Demo (Hands-on Lab & Exploit PoC)

This lab provides a C simulation (`ret2usr_demo.c`) replicating the socket vulnerability ([CVE-2017-7308](https://nvd.nist.gov/vuln/detail/CVE-2017-7308)) to empirically verify behavior under unhardened versus SMEP/PXN-hardened configurations.

### 5.1 Architecture & Implementation (`ret2usr_demo.c`)

- **Lab Source Code**: [`ret2usr_demo.c`](../../assets/labs/scenarios/02-ret2usr/ret2usr_demo.c) (Local Raw) | [GitHub Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/scenarios/02-ret2usr/ret2usr_demo.c)
- **Memory Structure**: The function pointer (`rx_handler`) in `struct mock_packet_sock` is overwritten by the attacker to point to `user_malicious_shellcode`.
- **MMU Simulation**: Models x86 `CR4.SMEP` and ARM64 `PTE_PXN` bit enforcement to verify whether instruction fetch targets fall within user space (`< TASK_SIZE`).

```c
/* labs/scenarios/02-ret2usr/ret2usr_demo.c Core Structure */
typedef struct {
    uint32_t ring_buffer_size;
    uint32_t block_nr;
    void (*rx_handler)(void); // Kernel function pointer corrupted by attacker
} mock_packet_sock_t;

// Malicious payload placed in user space (Ring 3)
void user_malicious_shellcode(void) {
    // Dangerous telemetry executed in Ring 0: Watchdog kill & motor overload 85A
}
```

---

### 5.2 Attack Execution & Cyber-Physical Disaster Logs

Running the vulnerable daemon without SMEP (`CR4.SMEP=0`):

```bash
# Run vulnerable mode (without SMEP/PXN defense)
cd labs/scenarios/02-ret2usr && make run-attack
```

**Runtime Warning Telemetry Output**:
```text
======================================================================
 ⚡ Linux Kernel ret2usr & Hardware MMU Defense Lab (CVE-2017-7308) 
======================================================================

[MODE 2: RET2USR ATTACK WITHOUT SMEP (CR4.SMEP=0, PTE_PXN=0)]
[*] Simulating CVE-2017-7308: Heap out-of-bounds corrupting packet_sock...
    [!] Vulnerable pointer hijacked: sock->rx_handler = 0x5608f51ec290 (User Space)
[*] Dispatching socket RX packet in Kernel Context (CPL=0 / Ring 0)...
    [!] MMU Warning: CR4.SMEP=0. Instruction fetch from user space ALLOWED!

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Ring 0 CPU Running User Shellcode! 
======================================================================
  [*] Attacker payload executed with SUPERVISOR PRIVILEGE (Ring 0)!
  [*] Current CPU Execution Context: Ring 0 (CPL=0)
  [*] Code Location: User Space Virtual Address (0x5608f51ec290)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & KERNEL TAKEOVER] ---
  [🔴 PHYSICAL HAZARD] Hardware Safety Watchdog Thread: TERMINATED
  [🔴 PHYSICAL HAZARD] Joint Actuator Current Overload: 15.0 A -> 85.0 A (OVERHEAT)
  [🔴 PHYSICAL HAZARD] PCIe MMIO Motor Driver Registers: DIRECT WRITE ACCESS GRANTED
  [🔴 KERNEL PERSISTENCE] MMU Page Tables: Supervisor flags cleared across all user pages
```

> **Cyber-Physical Hazard Analysis:** Without SMEP, the CPU executes user shellcode while retaining supervisor privilege. The **watchdog is terminated, and motor current surges to 85A**, risking actuator destruction and fire.

---

### 5.3 Post-Exploitation Phase: What Happens After Ring 0 Breach? {: #53-post-exploitation-phase-what-happens-after-ring-0-breach }

Once Ring 0 is breached, the attacker can execute catastrophic follow-on actions:

1. **Credential Escalation**: Calling `commit_creds(prepare_kernel_cred(0))` to permanently elevate all process credentials to root.
2. **Disabling Kernel Defenses**: Overwriting `selinux_enforcing` to 0 and modifying `CR4` bits to deactivate security controls.
3. **Stealth Kernel Rootkit Injection**: Unlinking malicious module nodes from `modules` list to evade detection by `lsmod`.
4. **Direct Hardware Manipulation**: Bypassing OS device drivers to manipulate motor inverters, BMS, and LiDAR physical MMIO registers directly.

---

### 5.4 Hardened Defense Output: Hardware MMU Trap & Fail-Safe State

Executing the same attack against a hardened system (`CR4.SMEP=1` / `PTE_PXN=1`):

```bash
# Run hardened mode (SMEP/PXN active)
cd labs/scenarios/02-ret2usr && make run-hardened
```

**Defense Telemetry Output**:
```text
======================================================================
 ⚡ Linux Kernel ret2usr & Hardware MMU Defense Lab (CVE-2017-7308) 
======================================================================

[MODE 3: RET2USR ATTACK WITH HARDENED MMU (CR4.SMEP=1, PTE_PXN=1)]
[*] Simulating CVE-2017-7308: Heap out-of-bounds corrupting packet_sock...
    [!] Vulnerable pointer hijacked: sock->rx_handler = 0x5608f51ec290 (User Space)
[*] Dispatching socket RX packet in Kernel Context (CPL=0 / Ring 0)...
    [*] Hardware MMU Intercept: Validating instruction fetch address against User/Supervisor bit...

======================================================================
 [🛡️ HARDWARE MMU TRAP DETONATED] Page Fault (#PF) Exception! 
======================================================================
  [!] VIOLATION DETECTED: Supervisor CPU (Ring 0) attempted instruction fetch from User Page!
  [!] Hardware Registers:
      CR4.SMEP = 1 (Enabled) | PTE_PXN = 1 (Active)
      Target Address = 0x5608f51ec290 (< TASK_SIZE)
      Page Fault Error Code = 0x0011 (Supervisor Instruction Fetch Protection Violation)
  [!] Execution blocked: 0 instructions executed in user space. Arbitrary code execution: 0%
  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Spring-loaded parking brakes LOCKED. Robotic joints secured!
```

> **Defense Conclusion:** The CPU MMU immediately detects the violation on the first instruction fetch, raising `#PF` with Error Code `0x0011`. Zero instructions are executed in user space, and the robot enters a fail-safe mechanical lock.

---

## 6. Engineering Deep Dive

Detailed register specifications and hardware exception decoding for system engineers.

### 6.1 x86_64 CR4.SMEP Control Register & Boot Initialization {: #deep-dive-smep-reg }

On Intel and AMD x86_64 architectures, SMEP resides at Bit 20 of control register `CR4`:

```nasm
; [x86_64] Kernel Boot Setup (arch/x86/kernel/cpu/common.c)
movq    %cr4, %rax            ; Read current CR4
btsq    $20, %rax             ; Set Bit 20 (X86_CR4_SMEP: 1 << 20 = 0x00100000)
movq    %rax, %cr4            ; Write back -> SMEP active in hardware
```

- When the CPU is at CPL=0 (Ring 0) and attempts an instruction fetch from a page with $U/S = 1$, the MMU triggers a Vector 14 **Page Fault (`#PF`)**.
- 🔗 [Feature Specification: 09. SMEP & PXN Hardware Defense Analysis](../../features/09-smep-pxn.md)

### 6.2 ARM64 Stage 1 Translation & PTE_PXN (Bit 53) {: #deep-dive-pxn-arm }

On ARMv8-A/ARMv9-A architectures, Bit 53 (`PTE_PXN`: Privileged Execute-Never) in Stage 1 translation tables enforces execution restrictions:

```text
[ARM64 64-bit Stage 1 Translation Block/Page Descriptor]
63      59 58 54 53  52 51                                          12 11   2 1 0
+---------+-----+---+---+--------------------------------------------+-----+---+-+
| Ignored | ... |PXN|UXN| Output Physical Address (Bits 47:12)       | AP  |...|1|
+---------+-----+---+---+--------------------------------------------+-----+---+-+
                 │
                 └──> Bit 53 = 1 : EL1 execution strictly prohibited from this page!
```

- Any attempt by EL1 to execute code from this page triggers an **Instruction Abort Exception** (`ESR_EL1` EC `0x21`).

### 6.3 Hardware `#PF` Error Code 0x0011 Bit-field Dissection {: #deep-dive-pf-decode }

When `#PF` occurs on x86, the CPU pushes a 32-bit error code onto the stack:

| Bit Position | Flag Name | Value | Meaning |
| :--- | :--- | :--- | :--- |
| **Bit 0** | **P (Present)** | `1` | Page is present in physical memory (protection violation) |
| **Bit 1** | **W/R (Write/Read)** | `0` | Access was read or instruction fetch |
| **Bit 2** | **U/S (User/Supervisor)** | `0` | Access occurred in **Supervisor Mode (Ring 0)** |
| **Bit 3** | **RSVD (Reserved)** | `0` | No reserved bit violation |
| **Bit 4** | **I/D (Instruction Fetch)** | `1` | Access was an **Instruction Fetch** (SMEP signature!) |

- **Combined Value**: `0x0001` (Bit 0) | `0x0010` (Bit 4) = **`0x0011`**.
- The Linux kernel page fault handler (`arch/x86/mm/fault.c`) recognizes `0x0011` as a fatal ret2usr attempt and triggers `Oops: 0011 [#1] PREEMPT SMP`.

### 6.4 Attacker's Evolution: Transition from ret2usr to kROP {: #deep-dive-krop-pivot }

- With SMEP/PXN universally deployed, classic ret2usr using user shellcode is neutralized.
- Attackers evolved to **kROP (Kernel Return-Oriented Programming)**, chaining existing instructions within kernel space (`.text`).
- To construct kROP chains, attackers must locate kernel gadgets, making **KASLR (`CONFIG_RANDOMIZE_BASE`)**, **FG-KASLR**, and **kCFI** critical defenses.
- 🔗 [Address Space Randomization: 05. KASLR Specification](../../features/05-kaslr.md)
- 🔗 [Control Flow Integrity: 13. Clang kCFI Specification](../../features/13-kcfi.md)

---

## 7. External Advisories & References

<div class="grid cards vertical" markdown>

-   __📌 Official CVE Database__

    ---

    1.  **CVE-2017-7308**

        Linux Kernel `packet_set_ring` AF_PACKET Heap Out-of-Bounds Privilege Escalation

    2.  **CVE-2022-25636**

        Linux Kernel `netfilter` (nf_tables) Heap Out-of-Bounds Write leading to Local Privilege Escalation

-   __🔬 Research & Technical Reports__

    ---

    1.  **Andrey Konovalov (Google Project Zero, 2017)**

        *"Exploiting CVE-2017-7308: A Linux Kernel Socket Vulnerability Deep Dive"*

    2.  **Vitaly Nikolenko (2018)**

        *"Modern Linux Kernel Exploitation: Bypassing SMEP/SMAP using kROP and Page Table Manipulation"*

    3.  **Intel 64 and IA-32 Architectures Software Developer's Manual**

        Volume 3A: System Programming Guide - Section 4.6 (Supervisor-Mode Execution Prevention)

-   __🛡️ Kernel Hardening & Standards__

    ---

    1.  **Linux Kernel Hardening Project**

        [Hardware-assisted Memory Protection (SMEP & SMAP)](https://kernsec.org/)

    2.  **ARM Architecture Reference Manual (ARMv8/v9-A)**

        Section D5: Memory System Architecture - Privileged Execute-Never (PXN)

    3.  **Kernel Documentation (x86)**

        `Documentation/arch/x86/smep.rst` - Supervisor Mode Execution Prevention Mechanics

</div>
