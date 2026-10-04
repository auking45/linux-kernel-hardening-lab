# [Scenario 04] Heap UAF & SLAB Freelist Corruption (SLAB Freelist Hardening & KFENCE)

!!! abstract "🎯 Executive Summary"
    - **Real-World Incident**: Linux kernel filesystem context heap buffer overflow (**CVE-2022-0185**) and Netfilter heap corruption exploit (**CVE-2021-22555**)
    - **Threat Vector**: Manipulating plaintext `freelist_ptr` in unallocated chunks (Free Slots) within SLUB allocator (`kmalloc-128`) to hijack subsequent `kmalloc` calls, causing arbitrary kernel critical data structures (such as bipedal gait balance PID telemetry) to be returned to the attacker (Freelist Poisoning)
    - **Cyber-Physical Hazard**: Bipedal gait balance PID gain runaway (Pitch Kp: 150.0 -> 9500.0), damping elimination (Kd: 12.0 -> 0.0), yaw spin divergence (Yaw: 32.5 rad/s), causing mechanical resonance runaway, gear fracture, and catastrophic ground tip-over
    - **Primary Defense**: Kernel SLAB pointer obfuscation and cryptographic validation **`CONFIG_SLAB_FREELIST_HARDENED`** (XOR random cookie + byte-swap verification)
    - **Supplementary Defenses**: Low-overhead production sampled guard page allocator **KFENCE (`CONFIG_KFENCE`)** and freelist randomization **`CONFIG_SLAB_FREELIST_RANDOM`**

---

## 1. Real-World Attack Analysis: CVE-2022-0185 / CVE-2021-22555 & Humanoid Gait Destruction

Dynamic heap memory allocators (SLAB/SLUB) represent one of the most critical attack surfaces in modern operating systems:

```
[Robot User Space (Locomotion Planner / C2: Ring 3)]
                 │
                 │ (1) fs_context / netfilter vulnerable syscall invoked
                 ▼
[Kernel Heap Space (SLUB kmalloc-128 Cache)]
 ┌──────────────────────┐      ┌──────────────────────┐
 │ Chunk 0 (Vulnerable) │ ───> │ Chunk 1 (Free Slot)  │ ───> Chunk 2 ...
 └──────────────────────┘  OOB └──────────────────────┘
            │          Overflown       │ (Plaintext freelist_ptr overwritten)
            └──────────────────────────┘
                                       ▼
                       [Poisoned Pointer: &victim_gait]
                                       │
                 │ (2) Subsequent kmalloc() -> Returns victim_gait struct!
                 ▼
[Robot Bipedal Balance Controller (robot_gait_config_t)]
 - Kp_pitch : 150.0  ──[Tampered]──> 9500.0 (Resonance Runaway)
 - Kd_pitch : 12.0   ──[Tampered]──> 0.0    (Damping Zeroed)
 - Yaw_rate : 1.2    ──[Tampered]──> 32.5   (High-Speed Spin Slip)
                 │
                 ▼
[💥 Catastrophic Ground Collapse: Gearbox rupture & structural tip-over damage]
```

### 1.1 Attack Vector and Root Cause Analysis

- **CVE-2022-0185 (fs_context Heap Buffer Overflow)**:
    - In `fs/fs_context.c` (`legacy_parse_param()`), an integer underflow combined with lack of boundary checking caused an out-of-bounds heap write beyond the 4KB page allocation, corrupting adjacent SLUB cache chunks.
- **CVE-2021-22555 (Netfilter Heap Corruption)**:
    - In `net/netfilter/x_tables.c`, a 32-bit compat layer offset calculation error resulted in an 8-byte out-of-bounds heap write.
- **Plaintext Freelist Exploitation (Freelist Poisoning)**:
    - In unhardened baseline SLUB caches, free objects store the pointer to the next free object directly inside their own data payload as a 64-bit plaintext pointer (`freelist_ptr`).
    - By overflowing into an adjacent free slot and overwriting `freelist_ptr` with the address of a victim kernel structure (`&victim_gait` or `struct cred`), the allocator treats the victim structure as a valid chunk on the next `kmalloc()`, giving the attacker write access to arbitrary kernel memory.

### 1.2 Cyber-Physical Hazard Analysis

Tampering with the gait control structure directly corrupts the closed-loop kinematics feedback loop of the humanoid robot:

- 🔴 **Pitch Axis Proportional Gain Runaway ($K_p$)**:
    - Nominal gain increases from 150.0 to 9500.0 (>63x surge), driving joint actuators into violent oscillations matching the natural resonance frequency of the mechanical limbs.
- 🔴 **Derivative Damping Nullification ($K_d$)**:
    - Damping factor zeroed out ($12.0 \to 0.0$), removing all oscillatory damping and resulting in undamped mechanical resonance.
- 🔴 **Yaw Spin Slip & Tip-Over**:
    - Yaw rate limit increases from 1.2 rad/s to 32.5 rad/s, causing the bipedal base to spin out of the stable support polygon and collapse violently onto the ground.

---

## 2. SLUB Allocator Architecture & Freelist Poisoning Mechanism

The Linux kernel utilizes the SLUB allocator to manage memory objects efficiently without external queue overhead.

### 2.1 SLUB Free Object Management Architecture

The SLUB allocator maintains a per-CPU `kmem_cache_cpu` structure that tracks free chunks via a singly linked list (Freelist):

```
[ kmem_cache_cpu ]
  freelist ──────┐
                 ▼
        ┌──────────────────┐      ┌──────────────────┐
        │ Object 0 (Free)  │      │ Object 1 (Free)  │
        ├──────────────────┤      ├──────────────────┤
        │ [freelist_ptr] ──┼─────>│ [freelist_ptr] ──┼───> NULL
        │  (Payload Data)  │      │  (Payload Data)  │
        └──────────────────┘      └──────────────────┘
```

1. **Inline Freepointers**:
    - When an object is unallocated (free), rather than storing metadata externally, the address of the next free chunk is placed directly inside the object's body (offset 0 or cache offset).
2. **Allocation & Deallocation Routine**:
    - `kmem_cache_alloc()`: Pops the object currently referenced by `freelist` and updates `freelist` to `object->freelist_ptr`.
    - `kmem_cache_free()`: Sets the freed object's `freelist_ptr` to the current `freelist` head and prepends the freed object.

### 2.2 Step-by-Step Freelist Poisoning Execution

In an unhardened environment (`CONFIG_SLAB_FREELIST_HARDENED=n`), the exploit proceeds as follows:

```
[Step 1: Heap Grooming]
 Attacker aligns vulnerable active buffer (Chunk 0) immediately adjacent to a free slot (Slot 1).

[Step 2: Boundary Overflow]
 Trigger CVE-2022-0185 1-byte heap overflow to overwrite Slot 1's plaintext freelist_ptr with &victim_gait.

[Step 3: Heap Hijack via Allocation]
 - Next kmalloc(128) pop: Chunk 0 allocated; freelist head updated to poisoned Slot 1.
 - Subsequent kmalloc(128) pop: Allocator reads poisoned freelist_ptr from Slot 1 and returns &victim_gait!

[Step 4: Arbitrary Kernel Struct Corruption]
 Attacker writes attacker-crafted telemetry directly into the hijacked memory, corrupting critical robot kinematics!
```

---

## 3. Interactive Architecture Diagrams (4 Sequential Phases)

Explore the 4 sequential attack and defense phases below, as well as the comprehensive architecture flow diagram with real-time theme synchronization.

### 3.1 [Phase 1] Normal SLUB Allocation & Freelist Traversal

<iframe src="../../assets/diagrams/heap-slab/phase1-normal.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.2 [Phase 2] Heap Out-of-Bounds & Plaintext Freelist Poisoning

<iframe src="../../assets/diagrams/heap-slab/phase2-attack.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.3 [Phase 3] Freelist Hardening XOR Verification & KFENCE Trap

<iframe src="../../assets/diagrams/heap-slab/phase3-trap.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.4 [Phase 4] Cyber-Physical Fail-Safe E-Stop & Joint Lock

<iframe src="../../assets/diagrams/heap-slab/phase4-failsafe.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.5 [Comprehensive Architecture] SLUB Hardening & KFENCE Defense Flow

<iframe src="../../assets/diagrams/heap-slab/architecture.html" width="100%" height="860" frameborder="0" style="border:none; border-radius:10px; margin-bottom:24px;"></iframe>

<script>
window.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'diagram-theme-change') {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      iframe.contentWindow.postMessage({
        type: 'set-diagram-theme',
        theme: e.data.theme
      }, '*');
    });
  }
});
</script>

---

## 4. Layered Defenses Matrix (Defense-in-Depth)

The Linux kernel implements layered mitigations against dynamic heap exploitation:

| Defense Technology | Kernel Kconfig Option | Mechanism & Trap Point | Performance Overhead |
| :--- | :--- | :--- | :--- |
| **SLAB Freelist Hardening** | `CONFIG_SLAB_FREELIST_HARDENED=y` | XOR random cookie & byte-swapped pointer obfuscation on `kmem_cache_alloc` | **< 0.5% (Negligible)** |
| **KFENCE (Kernel Electric-Fence)** | `CONFIG_KFENCE=y` | Sampled guard page allocator intercepting OOB/UAF via hardware `#PF` | **< 1.0% (Production-ready)** |
| **SLAB Freelist Randomization** | `CONFIG_SLAB_FREELIST_RANDOM=y` | Fisher-Yates shuffle randomization of initial freelist order | **One-time at boot (< 0.1%)** |
| **Zero Memory Sanitization** | `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` | Zeroes freed objects immediately to purge residual pointers & UAF leaks | **~1.5% - 2.5%** |

### 4.1 [Primary Defense] `CONFIG_SLAB_FREELIST_HARDENED`

<div class="grid cards vertical" markdown>

-   __⚙️ Mechanism__

    ---

    1.  **Cookie Generation & Encoding**:
        - Each `kmem_cache` receives a 64-bit CSPRNG secret (`s->random`) at creation.
        - Freepointers are stored using `ptr ^ s->random ^ swab64(ptr_addr)`, preventing plaintext exposure.
    2.  **Decoding & Pointer Integrity Verification**:
        - Upon allocation, the kernel decodes the freepointer and verifies that the target address is 8-byte aligned and falls within legitimate slab virtual address ranges.
        - If an attacker injects a plaintext address, decoding produces high-entropy non-canonical garbage (`0x756acb91f00cb3ce`), triggering an immediate kernel Oops/Panic trap.

-   __🛡️ Defense Impact__

    ---

    1.  **Neutralizes Freelist Poisoning**:
        - Attackers cannot forge valid freepointer targets without leaking both `s->random` and the exact slot virtual address.
    2.  **Immediate Exploit Interception**:
        - Exploits abort before arbitrary write primitives can be detonated in kernel space.

</div>

### 4.2 [Production Guard] `CONFIG_KFENCE` (Kernel Electric-Fence)

<div class="grid cards vertical" markdown>

-   __⚙️ Mechanism__

    ---

    1.  **Sampled Guard Page Allocation**:
        - KFENCE carves out a dedicated pool of guard pages mapped with `PROT_NONE` surrounding sampled object slots.
        - Allocations are periodically sampled (e.g., every 100ms) and directed into KFENCE slots.
    2.  **Hardware MMU `#PF` Exception Trap**:
        - Out-of-bounds writes into guard pages trigger hardware page fault exceptions (`#PF`, Vector 14) instantly.

-   __🛡️ Defense Impact__

    ---

    1.  **Production-Grade Continuous Monitoring**:
        - Unlike KASAN (200-300% overhead), KFENCE runs with <1% overhead in mission-critical environments.
    2.  **Zero-Day Heap Flaw Interception**:
        - Captures heap corruption with full stack traces in `dmesg` before exploitation completes.

</div>

---

## 5. Hands-on Lab & Exploit PoC Demonstration (`slab_demo.c`)

This lab includes an interactive C simulation (`slab_demo.c`) modeling CVE-2022-0185 / CVE-2021-22555 heap corruption and validating `CONFIG_SLAB_FREELIST_HARDENED` mitigation behavior.

### 5.1 Simulator Architecture (`slab_demo.c`)

- **Lab Source Code**: [`slab_demo.c`](../../assets/labs/scenarios/04-heap-slab/slab_demo.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/scenarios/04-heap-slab/slab_demo.c)
- **Memory Layout**: Models a SLUB `kmalloc-128` cache pool and adjacent humanoid locomotion kinematics structure (`robot_gait_config_t`).
- **Mitigation Logic**: Implements kernel-grade pointer obfuscation and de-obfuscation routines from `mm/slub.c`.

```c
/* Pointer obfuscation routines from labs/scenarios/04-heap-slab/slab_demo.c */
static inline uint64_t encode_freepointer(mock_kmem_cache_t *cache, uint64_t next_obj_addr, uint64_t slot_addr) {
    if (!cache->hardened_enabled) {
        return next_obj_addr; /* Plaintext baseline */
    }
    return next_obj_addr ^ cache->random_cookie ^ swab64(slot_addr);
}

static inline uint64_t decode_freepointer(mock_kmem_cache_t *cache, uint64_t stored_val, uint64_t slot_addr) {
    if (!cache->hardened_enabled) {
        return stored_val; /* Plaintext baseline */
    }
    return stored_val ^ cache->random_cookie ^ swab64(slot_addr);
}
```

---

### 5.2 Attack Execution & Cyber-Physical Hazards Log

Execution log when attacking an unhardened SLUB cache (`SLAB_HARDENED=n`):

```bash
# Run attack simulation in vulnerable mode
cd labs/scenarios/04-heap-slab && make run-attack
```

**Runtime Telemetry Log**:
```text
======================================================================
 🤖 Humanoid Robot Kernel Heap Overflow & SLAB Hardening Lab (CVE-2022-0185) 
======================================================================

[MODE 2: HEAP OVERFLOW & FREELIST POISONING WITHOUT HARDENING (SLAB_HARDENED=n)]
[*] Initializing baseline SLUB cache: Plaintext freelist pointers...
[*] Attacker triggers CVE-2022-0185 1-byte heap out-of-bounds write on Chunk 0...
    [!] Vulnerable write overflows Chunk 0 boundary into Free Slot 1's freelist pointer!
    [!] Freelist poisoned: Slot 1 -> freelist_ptr overwritten to 0x7ffd26e601b0 (Victim Gait Config)
[*] Attacker requests kmalloc-128: Allocator returns hijacked address: 0x7ffd26e601b0!
[*] Attacker writes malicious kinematics configuration directly into kernel heap memory...

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Kernel Heap Arbitrary Overwrite! 
======================================================================
  [*] SLUB Freelist Hijacked: Target object allocated into arbitrary kernel struct!
  [*] Current Memory: Kernel Heap Space (SLUB kmalloc-128)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & BIPEDAL BALANCE COLLAPSE] ---
  [🔴 PHYSICAL HAZARD] Pitch Axis Proportional Gain: 150.0 -> 9500.0 (RESONANCE RUNAWAY)
  [🔴 PHYSICAL HAZARD] Damping Factor (Kd): 12.0 -> 0.0 (ZERO DAMPING: UNDAMPED OSCILLATION)
  [🔴 PHYSICAL HAZARD] Yaw Spin Oscillation: 1.2 -> 32.5 rad/s (HIGH-SPEED DISORIENTING TIP-OVER)
  [🔴 ROBOT COLLAPSE] Bipedal balance loop failed: Violent ground impact & gear breakage!
```

---

### 5.3 Hardened Defense & Kernel Interception Log

Execution log under `CONFIG_SLAB_FREELIST_HARDENED=y`:

```bash
# Run simulation in hardened defense mode
cd labs/scenarios/04-heap-slab && make run-hardened
```

**Hardened Defense & Fail-Safe Telemetry Log**:
```text
======================================================================
 🤖 Humanoid Robot Kernel Heap Overflow & SLAB Hardening Lab (CVE-2022-0185) 
======================================================================

[MODE 3: HEAP ATTACK INTERCEPTED BY SLAB FREELIST HARDENING & KFENCE]
[*] Initializing Hardened SLUB cache (CONFIG_SLAB_FREELIST_HARDENED=y)...
[*] Attacker triggers CVE-2022-0185 heap overflow: Attempts to poison Slot 1's freelist pointer...
    [!] Slot 1 poisoned with plaintext address: 0xffff888012345678
[*] Kernel executes kmalloc-128: Attempting to de-obfuscate Slot 1 freelist pointer...
    [*] Decoded address using XOR cookie & byte-swap: 0x756acb91f00cb3ce

======================================================================
 [🛡️ SLUB FREELIST CORRUPTION DETECTED] kmem_cache_alloc Trap! 
======================================================================
  [!] SLUB INTEGRITY TRAP: Freelist pointer corrupt detected in cache 'kmalloc-128'!
  [!] Forensic Analysis:
      Expected Pointer Pattern = Valid decoded slab offset within page
      Found Pointer = 0x756acb91f00cb3ce (Non-canonical / Corrupted Entropy Garbage)
      Defense Mechanism = CONFIG_SLAB_FREELIST_HARDENED XOR Cookie Validation
  [!] Allocation aborted: Arbitrary write hijacked: 0%. Kernel Panic / Oops triggered.

  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Spring-loaded parking brakes LOCKED. Robotic joints secured safely!
```

---

### 5.4 Architectural Analysis: Rooting (UID 0 / Ring 3) vs Kernel Heap Control (Ring 0)

Gaining root access versus seizing kernel heap control represents fundamentally different security tiers:

```
[Security Boundary]          [Root Access (UID 0 / Ring 3)]          [Kernel Heap Control (Ring 0)]
Execution Privilege Level    CPU Ring 3 (User Space Mode)           CPU Ring 0 (Supervisor Kernel Mode)
Memory Access Scope          Constrained by virtual MMU mappings    Unrestricted read/write to all RAM
Hardware MMIO Controls       Restricted via driver APIs             Direct raw writes to actuator buses
Mandatory Access Control     Enforced by SELinux / AppArmor         Bypasses/patches security hooks directly
Fail-Safe Interlocks         Cannot tamper with hardware timers     Can halt hardware watchdog counters
```

1. **Limitations of Root Privileges (UID 0)**:
    - Root users can access user-space configuration files and terminate user processes, but CPU execution remains strictly bound to **Ring 3**.
    - Direct kernel memory writes, unverified interrupt handler registration, and hardware timing register modifications are blocked by MMU and hardware CPU rings.
2. **Omnipotence of Kernel Heap Control (Ring 0)**:
    - Once attackers seize kernel heap structures, code executes at **Ring 0** with complete control over CPU execution and memory translation.
    - Attackers can neutralize SELinux security hooks (`security_hook_heads`), overwrite credential structures (`commit_creds`), and tamper with actuator control loops directly.

---

## 6. Engineering Deep Dive

### 6.1 Mathematical Cryptographic Validation of Freepointer Obfuscation

The pointer encoding formula defined in Linux kernel `mm/slub.c`:

$$\text{Encoded} = \text{ptr} \oplus s\text{->random} \oplus \text{swab64}(\text{ptr\_addr})$$

- **XOR Symmetry**:
  $$\text{Decoded} = \text{Encoded} \oplus s\text{->random} \oplus \text{swab64}(\text{ptr\_addr}) = \text{ptr}$$
- **Entropy Diffusion via Byte Swapping**:
  - Simple $s\text{->random}$ XOR masks are vulnerable if an attacker leaks a single freelist pointer, as all chunks in the cache share the same cookie.
  - By XORing with the 64-bit byte-swapped address (`swab64`) of the object itself, variations in lower page offset bits diffuse across high-order address bits, ensuring each slot has a distinct cryptographic key.

### 6.2 KFENCE Guard Page Mapping & Hardware `#PF` Interceptions

KFENCE uses virtual memory page protections to detect heap corruptions with zero execution overhead on common paths:

```
[KFENCE Virtual Memory Pool Layout]
┌──────────────────┬──────────────────┬──────────────────┐
│  Guard Page 0    │  Sampled Object  │  Guard Page 1    │
│  (PROT_NONE)     │  (Allocated)     │  (PROT_NONE)     │
└──────────────────┴──────────────────┴──────────────────┘
         ▲                                     ▲
         │ (Underflow -> Immediate #PF)        │ (Overflow -> Immediate #PF)
```

1. **Clear PTE `Present` Bit**: Guard pages have their `_PAGE_PRESENT` bit cleared in the page table entries.
2. **Hardware MMU Intercept**: Any out-of-bounds byte write triggers an immediate CPU Page Fault (`#PF`, Vector 14).
3. **Exception Handler Triage**: The kernel's `do_page_fault()` identifies the fault within the KFENCE range, records the offending call stack to `dmesg`, and denies corrupt allocation.

### 6.3 SLUB Redzones & Object Poisoning

Additional mitigations available via boot parameters (`slub_debug=FZP`):

- **Redzones (`CONFIG_SLUB_DEBUG`)**:
  - Appends 16-byte padding with canary patterns (`0xcc` or `0xbb`) around each slab object.
  - Verifies integrity upon free to detect heap overflows retrospectively.
- **Poisoning**:
  - Fills unallocated objects with `0x6b` patterns and freed memory with `0xa5` patterns, ensuring Use-After-Free attempts dereference invalid addresses and crash immediately.

### 6.4 Robot Cyber-Physical Fail-Safe Architecture

Hardware protection chain preventing cyber compromises from detonating physical damage:

1. **Hardware Safety Watchdog**:
   - Locomotion controllers transmit high-frequency heartbeats to an isolated physical safety MCU.
   - Kernel panic or SLUB integrity traps interrupt heartbeats within 100 μs, firing an emergency interlock.
2. **Depower & Mechanical Clamping**:
   - De-energizes 48V servo motor bus relays to cut motor power to 0W.
   - Power-off engaged spring-loaded electronic parking brakes clamp all 12 joint axes within 5ms.

---

## 7. Official Documentation & Security References

- [Linux Kernel Documentation - SLUB Allocator](https://www.kernel.org/doc/html/latest/mm/slub.html)
- [Linux Kernel Documentation - Kernel Electric-Fence (KFENCE)](https://www.kernel.org/doc/html/latest/dev-tools/kfence.html)
- [CVE-2022-0185: Heap Overflow in Linux Kernel fs_context (NIST NVD)](https://nvd.nist.gov/vuln/detail/CVE-2022-0185)
- [CVE-2021-22555: 15 Years Old Linux Kernel Privilege Escalation in Netfilter](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
- [Alexander Popov: Linux Kernel Defense-in-Depth - Slab Freelist Hardening](https://a13xp0p0v.github.io/2020/02/15/slab-freelist-hardened.html)
