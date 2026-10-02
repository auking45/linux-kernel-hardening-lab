# Seccomp-BPF Syscall Filtering & Sandboxing

## 1. Overview & Threat Model

**Seccomp (Secure Computing Mode with BPF Filters)** is a foundational Linux isolation and hardening mechanism that **cryptographically and logically restricts the set of system calls available to a process, drastically reducing the kernel attack surface**.

While the contemporary Linux kernel provides over 450 distinct system calls, standard microservices, web servers (Nginx), browser renderers, and containerized processes typically require only 30 to 50 basic syscalls during normal operation. The remaining hundreds of specialized syscalls represent an enormous attack surface for local privilege escalation (LPE) vulnerabilities:

1. **Kernel Attack Surface Exposure**:
   - Following memory corruption (RCE) in a userland service, attackers exploit complex, obscure kernel subsystems (e.g., `ptrace`, `bpf`, `io_uring`, `unshare`, `keyctl`) to execute local privilege escalation exploits into Ring 0.
2. **Container Escape Vectors**:
   - In shared-kernel container environments, adversaries call namespace-manipulating syscalls (`setns`, `unshare`, `mount`) or management interfaces (`reboot`, `kexec_load`) to escape container boundaries and compromise the host node.
3. **Least Privilege Sandboxing via Seccomp-BPF**:
   - By attaching a cBPF (Classic BPF) filter program to a process, the kernel inspects the architecture (`arch`), system call number (`nr`), and arguments (`args`) in real time.
   - Any unauthorized system call invocation is intercepted immediately, returning an error (`SECCOMP_RET_ERRNO -EPERM`) or terminating the task (`SECCOMP_RET_KILL_PROCESS`), cutting off exploit chains before kernel code executes.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/seccomp/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Security Metal Detector & Gate in High-Security Vaults

The operational mechanism of Seccomp-BPF closely resembles **checkpoint screening at a bank vault**:

```
[ Disabled Mode (Traditional Unrestricted Environment) ]
  Visitor:      "I will bring pens, hammers, dynamite, and drills (all 450 system calls) into the vault!"
  Guard:        "You have valid credentials, so we cannot restrict which tools you bring inside." (Vulnerability risk)

[ Enforced Seccomp-BPF Sandbox ]
  Visitor:      "I promise I will only use write() and read() to sign documents (BPF whitelist installed)!"
  Interlock:    "PR_SET_NO_NEW_PRIVS engaged! One-way ratchet prevents escalating privileges permanently!"
  Scenario 1:   "Visitor calls write() -> Sensor allows through -> SECCOMP_RET_ALLOW (Normal execution)."
  Scenario 2:   "Visitor attempts to pull out ptrace or reboot tools -> Alarm triggers!"
  Outcome:      "Syscall handler bypassed! Intercepted immediately with -EPERM or process evicted via SIGSYS!"
```

---

### 3. Seccomp Operating Modes & Return Actions

#### 1) Three Operating Modes

- **`SECCOMP_MODE_DISABLED` (0)**: System call filtering is inactive. All kernel syscalls are permitted.
- **`SECCOMP_MODE_STRICT` (1)**: Only `read()`, `write()`, `_exit()`, and `sigreturn()` are permitted. Any other call results in instantaneous `SIGKILL`.
- **`SECCOMP_MODE_FILTER` (2)**: Executes developer-defined cBPF bytecode rules evaluating syscall numbers and arguments.

#### 2) Major Seccomp Return Action Constants

| Action Constant | Hex Value | Process Behavior & Kernel Action |
| :--- | :--- | :--- |
| `SECCOMP_RET_KILL_PROCESS` | `0x00000000` | Abruptly terminates the entire thread group / process (core dump eligible) |
| `SECCOMP_RET_KILL_THREAD` | `0x00000000` | Abruptly terminates the calling thread |
| `SECCOMP_RET_TRAP` | `0x00030000` | Sends uncatchable `SIGSYS` signal to process with detailed `siginfo_t` |
| `SECCOMP_RET_ERRNO` | `0x00050000` | Bypasses syscall handler, returning specified `errno` (e.g. `EPERM`) to caller |
| `SECCOMP_RET_USER_NOTIF` | `0x7fc00000` | Forwards syscall decision to an unprivileged supervisor file descriptor |
| `SECCOMP_RET_LOG` | `0x7ffc0000` | Allows syscall execution, but generates an audit log record |
| `SECCOMP_RET_ALLOW` | `0x7fff0000` | Permits normal syscall handler execution |

---

## 3. Configuration & Boot Parameters

### 1. Kconfig Fragment

```ini
# configs/features/seccomp.config
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
```

### 2. Runtime Control Interfaces & Control Flags

| Interface / Node | Description |
| :--- | :--- |
| `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` | Prevents unprivileged processes from gaining elevated permissions via SUID binaries (Mandatory prerequisite for Seccomp-BPF) |
| `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` | Dedicated system call to attach BPF syscall filter bytecode |
| `/proc/sys/kernel/seccomp/actions_avail` | Lists supported Seccomp return action codes in current kernel |
| `/proc/sys/kernel/seccomp/actions_logged` | Configures which actions trigger audit log entries |
| `/proc/[pid]/status` (`Seccomp: N`) | Displays active Seccomp mode for target process (`0`: Disabled, `1`: Strict, `2`: Filter) |

---

## 4. Hands-on Verification & Exploit PoC

### 1. Test Scenario Overview

- Execute tests under non-root account (`lab`, UID 1000):
  - **Phase 1: Baseline (Disabled Mode)**:
    - Safe (`write`) and dangerous (`ptrace`) syscalls are both permitted.
  - **Phase 2: Hardened (Target Driver BPF Filter Mode)**:
    - Target driver validates policy, returning `SECCOMP_RET_ALLOW` for safe calls and `SECCOMP_RET_ERRNO` (`-EPERM`) for prohibited calls.
  - **Phase 3: Native Process Seccomp-BPF Program**:
    - Child process locks credentials via `PR_SET_NO_NEW_PRIVS` and attaches a native BPF filter.
    - Safe call (`getpid()`) succeeds cleanly.
    - Prohibited call (`ptrace()`) is trapped by the kernel BPF engine, returning `-1` with `errno == EPERM`.

### 2. Dual-Architecture Execution Logs

=== "ARM64: Seccomp-BPF Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-seccomp/arch/arm64/boot/Image --test test_seccomp
    ```
    ```
    ================================================================
       Lab 35: Seccomp-BPF Syscall Sandbox Verification Suite        
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting process status Seccomp field...
    Seccomp:	0
    Seccomp_filters:	0

    [*] Step 2: Checking target driver at /proc/vuln_seccomp...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Seccomp PoC as user 'lab'...
    ================================================================
      Seccomp-BPF Syscall Filtering Sandbox PoC Exploit             
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
          Linux Seccomp-BPF Sandbox Status Report           
    ========================================================
    Current Seccomp Mode    : [2] BPF Filter (2: Fine-grained BPF Program)
    Caller Seccomp Status   : mode=0
    Total Syscalls Screened : 0
    Syscalls Allowed (RET_ALLOW) : 0
    Syscalls Denied (RET_ERRNO) : 0
    Syscalls Killed (RET_KILL)  : 0
    ========================================================

    [*] PHASE 1: Evaluating Baseline (Mode: Disabled - 0)
        -> Executing safe syscall... (GRANTED)
        -> Executing restricted attack syscall... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: BPF Filter - 2)
        -> Executing safe syscall (expecting GRANTED: ret = 0)... (GRANTED)
        -> Executing restricted syscall (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Testing Native In-Process Seccomp-BPF Filter
        [Child 1042] Setting PR_SET_NO_NEW_PRIVS...
        [Child 1042] Installing BPF syscall filter via prctl(PR_SET_SECCOMP)...
        [Child 1042] Filter installed successfully! Testing allowed syscall (getpid)...
        [Child 1042] getpid() succeeded: 1042
        [Child 1042] Attempting forbidden syscall (ptrace)...
        [Child 1042] [+] SUCCESS: ptrace was intercepted by Seccomp-BPF and returned -EPERM!
    [+] Native Seccomp-BPF test completed successfully!

    [+] Seccomp-BPF Verification Complete: Attack Surface Effectively Reduced!

    [*] Step 5: Inspecting kernel dmesg for Seccomp events:
    [    4.910201] seccomp: [ALLOW] Comm="exploit_seccomp" pid=1041 executed safe syscall -> SECCOMP_RET_ALLOW (ret = 0)
    [    4.910350] seccomp: [DENIED] Comm="exploit_seccomp" attempted restricted syscall -> SECCOMP_RET_ERRNO (-EPERM)
    ================================================================
       Lab 35 Test Complete: Verified Seccomp-BPF Syscall Filtering 
    ================================================================
    ```

=== "x86_64: Seccomp-BPF Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-seccomp/arch/x86/boot/bzImage --test test_seccomp
    ```
    ```
    ================================================================
       Lab 35: Seccomp-BPF Syscall Sandbox Verification Suite        
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting process status Seccomp field...
    Seccomp:	0
    Seccomp_filters:	0

    [*] Step 2: Checking target driver at /proc/vuln_seccomp...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Seccomp PoC as user 'lab'...
    ================================================================
      Seccomp-BPF Syscall Filtering Sandbox PoC Exploit             
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode: Disabled - 0)
        -> Executing safe syscall... (GRANTED)
        -> Executing restricted attack syscall... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: BPF Filter - 2)
        -> Executing safe syscall (expecting GRANTED: ret = 0)... (GRANTED)
        -> Executing restricted syscall (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Testing Native In-Process Seccomp-BPF Filter
        [Child 2055] Setting PR_SET_NO_NEW_PRIVS...
        [Child 2055] Installing BPF syscall filter via prctl(PR_SET_SECCOMP)...
        [Child 2055] Filter installed successfully! Testing allowed syscall (getpid)...
        [Child 2055] getpid() succeeded: 2055
        [Child 2055] Attempting forbidden syscall (ptrace)...
        [Child 2055] [+] SUCCESS: ptrace was intercepted by Seccomp-BPF and returned -EPERM!
    [+] Native Seccomp-BPF test completed successfully!

    [+] Seccomp-BPF Verification Complete: Attack Surface Effectively Reduced!

    [*] Step 5: Inspecting kernel dmesg for Seccomp events:
    [    8.210112] seccomp: [ALLOW] Comm="exploit_seccomp" pid=2054 executed safe syscall -> SECCOMP_RET_ALLOW (ret = 0)
    [    8.210255] seccomp: [DENIED] Comm="exploit_seccomp" attempted restricted syscall -> SECCOMP_RET_ERRNO (-EPERM)
    ================================================================
       Lab 35 Test Complete: Verified Seccomp-BPF Syscall Filtering 
    ================================================================
    ```

---

## 5. Performance & Container Industry Practice

1. **Microscopic BPF Overhead**:
   - cBPF filters evaluate directly upon CPU register entry. With in-kernel BPF JIT enabled, filter execution takes tens of nanoseconds (< 1-2% overhead), making it suitable even for high-throughput network daemons.
2. **Container Security Standards (Docker & Kubernetes)**:
   - The default Docker seccomp profile disables over 44 hazardous system calls (`acct`, `add_key`, `bpf`, `clock_settime`, `kexec_load`, `ptrace`, `unshare`), mitigating the vast majority of local kernel privilege escalation vulnerabilities before exploits can reach the kernel.
3. **Non-Revocable Inheritance**:
   - Seccomp filters persist across `fork()`, `clone()`, and `execve()`. Once attached, filters cannot be uninstalled or relaxed, guaranteeing immutable sandboxing throughout the application lifecycle.

---

## 6. Lecture & Presentation Script

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In contemporary cloud computing and containerized environments, the Linux kernel exposes more than 450 distinct system calls. However, typical web services, database daemons, or container microservices utilize only a modest subset of around 30 to 50 calls. The remaining 400 system calls—such as `ptrace`, `bpf`, `unshare`, and `keyctl`—represent an unnecessarily enormous attack surface. If a remote attacker achieves code execution inside a workload, they routinely exploit vulnerabilities in these obscure syscalls to achieve kernel Ring 0 privilege escalation. Today, we demonstrate the quintessential tool for attack surface reduction: **Seccomp-BPF**."

#### 2. Diagram & Architecture Walkthrough
> "Please direct your attention to our interactive architecture simulator. When an application initiates a syscall instruction—like `syscall` on x86_64 or `svc #0` on ARM64—the kernel traps the request inside `__secure_computing()` before dispatching it to the system call table. Seccomp packages the architecture, syscall number, and arguments into `struct seccomp_data` and executes an in-kernel BPF filter. If the system call matches our whitelist, it returns `SECCOMP_RET_ALLOW`. If an adversary invokes a prohibited call like `ptrace` or `reboot`, the engine bypasses the kernel handler entirely, returning an immediate `-EPERM` via `SECCOMP_RET_ERRNO` or terminating the hostile thread with `SECCOMP_RET_KILL_PROCESS`."

#### 3. Live Demo Commentary
> "In our live verification on ARM64 and x86_64, look at the progression across our test phases. In Phase 1, without filtering, restricted calls succeed unimpeded. In Phase 2, our target driver filters prohibited requests with `-EPERM`. In Phase 3, we execute a native in-process Seccomp-BPF filter using `prctl()`. We lock down the child process with `PR_SET_NO_NEW_PRIVS` and install a BPF program. Whitelisted calls like `getpid()` execute flawlessly. But the moment the child calls `ptrace()`, Seccomp intercepts the trap and forces a clean return value of `-1` with `errno` set to `EPERM`. The attack surface is completely neutralized without crashing the rest of the host."

#### 4. Key Takeaways & Production Advice
> "To conclude: Seccomp-BPF is the cornerstone of modern Linux sandboxing, underpinning container security in Docker, Kubernetes, and browser isolation in Chrome. By defining strict whitelist profiles and enforcing `PR_SET_NO_NEW_PRIVS`, organizations eliminate the vast majority of local privilege escalation vectors before vulnerabilities can ever be triggered."
