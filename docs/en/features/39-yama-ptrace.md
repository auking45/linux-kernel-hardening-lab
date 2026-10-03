# Yama LSM & Ptrace Scope Restrictions

## 1. Overview & Threat Model

**Yama LSM (`CONFIG_SECURITY_YAMA`)** is a dedicated Linux Security Module that **restricts the scope of the `ptrace()` system call among processes operating under the same user ID (Same UID), blocking lateral movement, memory inspection, and code injection attacks**.

Under the traditional Unix Discretionary Access Control (DAC) model, any process belonging to a user can attach to any other process owned by that same user via `ptrace(PTRACE_ATTACH)`, reading and modifying its memory space without requiring root privileges:

1. **Same-UID Sibling Process Exploitation**:
   - An attacker achieves code execution inside a low-privilege user application (e.g. a sandboxed web browser, chat client, or compromised utility).
   - The attacker issues `ptrace(PTRACE_ATTACH)` against other background processes running under the same user account (such as `ssh-agent`, `gpg-agent`, password managers, or browser processes with active cookies).
   - Without root privileges, the attacker dumps plaintext cryptographic private keys, steals credentials, and injects in-memory shellcode.
2. **Balancing Debugger Functionality**:
   - Legitimate debugging utilities (such as GDB) typically spawn their target processes as direct children via `fork()`. Security policies should permit legitimate hierarchical debugging while strictly prohibiting lateral attacks between arbitrary sibling processes.
3. **Four-Tier Yama Ptrace Scope Levels (`kernel.yama.ptrace_scope`)**:
   - `0`: Classic DAC (unrestricted same-UID ptrace).
   - `1`: **Restricted Ptrace (Default)**: Direct child processes or targets granting permission via `prctl(PR_SET_PTRACER)`.
   - `2`: Admin Only (`CAP_SYS_PTRACE` required).
   - `3`: No Ptrace (system-wide permanent disablement until reboot).

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/yama-ptrace/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Inter-Desk Isolation in a Research Lab

The mechanism of Yama LSM functions identically to **strict privacy partitions between researchers in the same laboratory**:

```
[ Disabled Mode (Scope 0: Classic DAC) ]
  Intruder:     "I stole Researcher Bob's ID badge (compromised browser process)!"
  Intruder:     "Because I hold Bob's ID badge, I will search Bob's personal desk drawers
                 (SSH agent, password manager) and take his master cryptographic keys!"
  Security:     "Badge matches. Access granted to all desks belonging to Bob." (Disastrous credential theft)

[ Yama Scope 1 Active (Restricted Mode) ]
  Intruder:     "Attempting to attach to Bob's SSH agent process via ptrace(PTRACE_ATTACH)!"
  Yama Hook:    "security_ptrace_access_check() checks process hierarchy!"
  Decision:     "The browser is NOT the parent of SSH agent! No PR_SET_PTRACER permit exists!"
  Action:       "Attachment blocked immediately with -EPERM! SSH private key remains secure in memory!"
```

---

### 3. Yama Ptrace Scope Four-Tier Decision Matrix

| Ptrace Scope | Policy Name | Permitted Relationships | Security Impact & Characteristics |
| :---: | :--- | :--- | :--- |
| **0** | **Classic DAC** | Any same-UID process can ptrace any other same-UID process | Insecure. Malware can snoop any user process without root |
| **1** | **Restricted (Recommended)** | Direct descendant child processes (`fork()`) or targets declaring `prctl(PR_SET_PTRACER)` | Default in Ubuntu/Debian. Blocks sibling attacks while preserving GDB functionality |
| **2** | **Admin Only** | Only processes possessing `CAP_SYS_PTRACE` (root) can attach | Disables unprivileged debugging entirely. Ideal for production servers |
| **3** | **No Ptrace** | Ptrace is completely disabled system-wide (even for root) | **One-way ratchet**. Cannot be restored to 0-2 without rebooting. Mission-critical defense |

---

## 3. Configuration & Sysctl Parameters

### 1. Kconfig Fragment

```ini
# configs/features/yama.config
CONFIG_SECURITY=y
CONFIG_SECURITY_YAMA=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 2. Runtime Control Interfaces & Sysctls

| Interface / Parameter | Default | Description |
| :--- | :--- | :--- |
| `/proc/sys/kernel/yama/ptrace_scope` | `1` | Configures active ptrace scope level (0, 1, 2, 3) |
| `prctl(PR_SET_PTRACER, pid, 0, 0, 0)` | User API | Target process explicitly grants permission to a specific tracer PID |
| `lsm=...,yama,...` | Kernel cmdline | Registers Yama in the active LSM ordering stack at boot time |

---

## 4. Hands-on Verification & Exploit PoC

### 1. Test Scenario Overview

- Execute tests under non-root account (`lab`, UID 1000):
  - **Phase 1: Scope 0 (Classic DAC)**:
    - Child process trace and sibling process trace are both permitted.
  - **Phase 2: Scope 1 (Restricted Yama)**:
    - Child process trace succeeds cleanly (`ret = 0`).
    - Sibling process trace is intercepted and terminated with `-EPERM`.
  - **Phase 3: Live Sibling Process Ptrace Test**:
    - Spawns two synchronized sibling processes (Sibling A and Sibling B).
    - Sibling B attempting `ptrace(PTRACE_ATTACH)` on Sibling A returns `-EPERM`.
    - Sibling B attaching to its own direct child succeeds as expected.

### 2. Dual-Architecture Execution Logs

=== "ARM64: Yama LSM Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-yama/arch/arm64/boot/Image --test test_yama_ptrace
    ```
    ```
    ================================================================
       Lab 39: Yama LSM Ptrace Scope Verification Suite             
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting kernel Yama ptrace_scope parameter...
        kernel.yama.ptrace_scope: 1
    [*] Step 2: Checking target driver at /proc/vuln_yama...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Yama PoC as user 'lab'...
    ================================================================
      Linux Yama LSM Ptrace Scope Restrictions Verification PoC    
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Kernel Yama Sysctl (/proc/sys/kernel/yama/ptrace_scope): 1
    [*] Initial Target Driver Status:
    ========================================================
            Linux Yama LSM Ptrace Scope Status              
    ========================================================
    Current Ptrace Scope    : [1] 1 (Restricted: Parent-Child only)
    LSM Registered          : CONFIG_SECURITY_YAMA=y
    Total Ptrace Probes     : 0
    Ptrace Attach Granted   : 0
    Ptrace Attach Denied    : 0 (-EPERM)
    ========================================================

    [*] PHASE 1: Evaluating Scope 0 (Classic DAC)
        -> Tracing child process... (GRANTED)
        -> Tracing sibling process with same UID... (GRANTED)

    [*] PHASE 2: Evaluating Scope 1 (Restricted Parent-Child)
        -> Tracing child process (expecting GRANTED: ret = 0)... (GRANTED)
        -> Tracing sibling process (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Live Sibling Process Ptrace Injection Test
        [Attacker 1082] Attempting ptrace(PTRACE_ATTACH) to Sibling A (1081)...
        [Attacker 1082] [+] SUCCESS: Sibling ptrace was BLOCKED by Yama! (Operation not permitted: errno=1)
                     -> Sibling process memory cannot be snooped or altered!
        [Attacker 1082] Testing allowed parent-to-child ptrace on Child C (1083)...
        [Attacker 1082] [+] SUCCESS: Parent-to-child ptrace succeeded as expected!

    [+] Yama LSM Verification Complete: Sibling Process Tampering Blocked!

    [*] Step 5: Inspecting kernel dmesg for Yama events:
    [    4.110290] yama: [DENIED] Sibling ptrace attack blocked! Sibling-to-sibling ptrace forbidden under Scope 1 (-EPERM)
    ================================================================
       Lab 39 Test Complete: Verified Yama LSM Ptrace Restrictions  
    ================================================================
    ```

=== "x86_64: Yama LSM Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-yama/arch/x86/boot/bzImage --test test_yama_ptrace
    ```
    ```
    ================================================================
       Lab 39: Yama LSM Ptrace Scope Verification Suite             
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting kernel Yama ptrace_scope parameter...
        kernel.yama.ptrace_scope: 1
    [*] Step 2: Checking target driver at /proc/vuln_yama...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Yama PoC as user 'lab'...
    ================================================================
      Linux Yama LSM Ptrace Scope Restrictions Verification PoC    
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Kernel Yama Sysctl (/proc/sys/kernel/yama/ptrace_scope): 1
    [*] PHASE 1: Evaluating Scope 0 (Classic DAC)
        -> Tracing child process... (GRANTED)
        -> Tracing sibling process with same UID... (GRANTED)

    [*] PHASE 2: Evaluating Scope 1 (Restricted Parent-Child)
        -> Tracing child process (expecting GRANTED: ret = 0)... (GRANTED)
        -> Tracing sibling process (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Live Sibling Process Ptrace Injection Test
        [Attacker 2095] Attempting ptrace(PTRACE_ATTACH) to Sibling A (2094)...
        [Attacker 2095] [+] SUCCESS: Sibling ptrace was BLOCKED by Yama! (Operation not permitted: errno=1)
                     -> Sibling process memory cannot be snooped or altered!
        [Attacker 2095] Testing allowed parent-to-child ptrace on Child C (2096)...
        [Attacker 2095] [+] SUCCESS: Parent-to-child ptrace succeeded as expected!

    [+] Yama LSM Verification Complete: Sibling Process Tampering Blocked!

    [*] Step 5: Inspecting kernel dmesg for Yama events:
    [    8.230190] yama: [DENIED] Sibling ptrace attack blocked! Sibling-to-sibling ptrace forbidden under Scope 1 (-EPERM)
    ================================================================
       Lab 39 Test Complete: Verified Yama LSM Ptrace Restrictions  
    ================================================================
    ```

---

## 5. Performance & Operational Considerations

1. **Zero Workload Penalty**:
   - Yama LSM evaluates lineage logic strictly on `ptrace` system call entry. Normal instruction execution across processes experiences 0% overhead.
2. **Debugger Compatibility (GDB & LLDB)**:
   - Workflows where GDB executes a program (`gdb ./app`) succeed automatically under Scope 1 because the debugger is the parent.
   - Workflows attaching to pre-existing processes (`gdb -p <pid>`) require either root privileges or the target program invoking `prctl(PR_SET_PTRACER)`.
3. **Production Recommendations**:
   - Workstations should mandate Scope 1, while locked-down cloud instances should enforce Scope 2 or Scope 3 via `/etc/sysctl.d/99-yama.conf`.

---

## 6. Lecture & Presentation Script

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In standard Linux discretionary access control, all processes running under the same user ID are considered equal peers. While this seems intuitive, it creates a fatal lateral movement vector. If an adversary gains remote execution inside an unprivileged desktop application—like a web browser or chat client—they can simply call `ptrace(PTRACE_ATTACH)` on the user's `ssh-agent`, password vault, or GPG daemon. Without needing root privileges, they can dump cryptographic keys directly from memory. Today, we examine the standard defense against sibling process tampering: **Yama LSM and Ptrace Scope Restrictions**."

#### 2. Diagram & Architecture Walkthrough
> "Please examine our interactive architecture simulator on the screen. Look at the relationship hierarchy. Under traditional Scope 0, any same-UID process can attach to any other process. But when Yama LSM is activated under Scope 1, the `security_ptrace_access_check()` hook evaluates process lineage. A parent process—such as GDB launching a child binary—is granted access cleanly. However, if a sibling process attempts an uninvited attach without prior authorization via `prctl(PR_SET_PTRACER)`, Yama intercepts the system call and immediately terminates it with `-EPERM`."

#### 3. Live Demo Commentary
> "In our live verification on ARM64 and x86_64, look at the transition across test phases. In Phase 1 with Scope 0, sibling attachment succeeds unimpeded. But when we switch to Scope 1, our live sibling exploit test demonstrates that Sibling B's attempt to attach to Sibling A is decisively rejected with `Operation not permitted (errno=1)`. Concurrently, when Sibling B forks its own direct child, the attach succeeds without error. Standard developer debugging remains fully intact, while lateral process eavesdropping is completely neutralized."

#### 4. Key Takeaways & Production Advice
> "To conclude: Yama LSM provides surgical protection against credential dumping and in-memory shellcode injection across same-user processes. Enforcing `kernel.yama.ptrace_scope = 1` should be the standard default on all workstations, while production servers and container hosts should consider elevating to Scope 2 or Scope 3 to permanently close the ptrace attack surface."
