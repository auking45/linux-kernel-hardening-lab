# SELinux Type Enforcement (TE), Domain Transitions, and MLS Security Context

## 1. Overview & Background

**SELinux (Security-Enhanced Linux)** is the industry-standard Mandatory Access Control (MAC) architecture developed collaboratively by the United States National Security Agency (NSA) and the Linux open-source community. Under traditional Linux Discretionary Access Control (DAC: UID/GID permissions), an attacker who escalates privileges to root (UID 0) inherits unrestricted control over all system assets.

SELinux remedies this fundamental design vulnerability by labeling every subject (process) and object (file, socket, IPC, directory) with a cryptographically enforced **Security Context**, enforcing the **Principle of Least Privilege** directly at the kernel boundary:
1. **Type Enforcement (TE)**:
   - The central pillar of SELinux. Access between a process domain (Domain/Type) and a target object type (Type) is governed by an explicit policy matrix. Unless explicitly permitted, all actions are blocked by default (Default Deny).
2. **Multi-Level Security (MLS)**:
   - Implements the mathematical Bell-LaPadula (BLP) confidentiality model by assigning sensitivity tiers ($s_0 \sim s_{15}$) and compartments/categories ($c_0 \sim c_{1023}$) to prevent unauthorized data exfiltration.
3. **Domain Transitions**:
   - Strictly controls process elevation and role changes across binary execution (`execve`) through pre-authorized entrypoint rules, preventing unauthorized code execution or privilege hijacking.
4. **Access Vector Cache (AVC)**:
   - High-performance in-kernel caching subsystem that stores access decisions produced by the Security Server, enabling near $O(1)$ lookup times on system call hot paths.

---

## 2. Real-World Analogy: National Intelligence Agency Clearance Protocol

The operational structure of `SELinux` directly resembles **physical access compartmentalization and security clearance badges within a national intelligence agency**:

```
[ Traditional DAC Environment (Omnipotent Superuser: One key opens every vault) ]
  Janitor (Compromised Web Service): "I found the Director's Master Badge (UID 0 / Root)!"
  Guard (Kernel DAC):                 "Master badge verified! Unlocking all top-secret safes (/etc/shadow)."
  Outcome:                            Compromising a low-privileged service allows complete system compromise!

[ SELinux Permissive Mode (Audit/Observation: Flag infractions without physical denial) ]
  Web Daemon (httpd_t):  "Accessing HR Personnel Vault (shadow_t) and reading Top Secret briefing (s1:c0)!"
  Audit Officer (AVC):   "Policy violation detected! (TE violation: httpd_t -> shadow_t, MLS No-Read-Up violation).
                          However, system is in permissive mode. Action allowed, violation recorded in audit log."
  Outcome:               Normal operations continue while fine-grained AVC audit trails are gathered for policy tuning.

[ SELinux Enforcing Mode (Ironclad Enforcement: Instant denial and containment) ]
  Web Daemon (httpd_t):  "Accessing HR Personnel Vault (shadow_t)!"
  Audit Officer (AVC):   "httpd_t is strictly confined to web documents (httpd_sys_content_t)!
                          Access to shadow_t denied immediately (-EACCES)!"
  Web Daemon (httpd_t):  "Attempting unauthorized domain transition into administrative unconfined_t!"
  Audit Officer (AVC):   "Invalid entrypoint and unauthorized transition! Request blocked (-EACCES)!"
  Web Daemon (httpd_t):  "Attempting to read higher classification document (s1:c0)!"
  Audit Officer (AVC):   "Bell-LaPadula No-Read-Up violated! Lower level (s0) cannot read higher level (s1)!"

  Final Result: Even with root UID, the compromised process cannot escape its httpd_t containment cell!
```

---

## 3. Core Architecture & Internal Mechanisms

### 3.1 Security Context Structure

Every subject and object under SELinux is identified by a standardized four-part security label:

$$\text{user} : \text{role} : \text{type} : \text{level (MLS)}$$

| Component | Example Value | Description |
| :--- | :--- | :--- |
| **User** | `system_u`, `unconfined_u` | SELinux logical identity (independent of Linux UID) |
| **Role** | `system_r`, `object_r` | RBAC attribute determining which domains a user may assume |
| **Type / Domain** | `httpd_t`, `shadow_t` | Type Enforcement identifier (called Domain for processes, Type for objects) |
| **MLS Level** | `s0`, `s1:c0.c1023` | Sensitivity tier and category compartments for multi-level data protection |

---

### 3.2 Type Enforcement (TE) Syntax & Rules

Policy source files (`te` rules) govern permissible operations through explicit statements:

```text
# Syntax: rule_type source_type target_type : class { permissions };
allow httpd_t httpd_sys_content_t : file { read open getattr ioctl };

# Invariant constraint checked at policy compilation
neverallow httpd_t shadow_t : file { read write execute };
```

- **Default Deny**: Any interaction not explicitly permitted by an `allow` statement is denied at the kernel level.
- **Neverallow Rules**: Compile-time assertions preventing accidental misconfigurations or overly permissive rules from entering the active policy.

---

### 3.3 Bell-LaPadula Multi-Level Security (MLS) Model

MLS mathematically enforces two mandatory security properties:

1. **Simple Security Property (No Read Up)**:
   - Subject $S$ may read object $O$ if and only if the clearance of $S$ dominates ($\ge$) the classification of $O$:
   $$L(S) \ge L(O) \iff S \text{ dominates } O$$
   - A standard clearance process ($s0$) cannot read classified intelligence ($s1$).
2. **$\star$-Property (No Write Down)**:
   - Subject $S$ may write to object $O$ only if the classification of $O$ dominates the clearance of $S$:
   $$L(O) \ge L(S)$$
   - A classified process ($s1$) cannot leak classified data into an unclassified document ($s0$).

---

### 3.4 Access Vector Cache (AVC) Pipeline

System calls invoke LSM hooks, which evaluate access through the AVC:

```
[ User System Call (e.g., sys_open) ]
                 │
                 ▼
     [ LSM Hook: selinux_file_open() ]
                 │
                 ▼
       [ AVC Cache Lookup ] ──(Cache Hit)──► [ Instant Allow / Deny Decision ]
                 │ (Cache Miss)
                 ▼
      [ SELinux Security Server ] ──► Policy DB & MLS Constraints Check
                 │
                 ▼
     [ Populate AVC & Audit Engine ] ──► Dispatches audit(avc): denied on denial
```

- **`permissive=0`**: Enforcing mode. Denials return `-EACCES` and log audit events.
- **`permissive=1`**: Permissive mode. Denials are logged to audit logs, but the kernel permits the call to succeed (`return 0`).

---

## 4. Interactive Architecture Simulator

The interactive simulator below demonstrates the security context resolution pipeline, the AVC caching mechanism, Type Enforcement rule evaluation, Bell-LaPadula MLS properties, and dynamic Permissive vs Enforcing mode transitions:

<iframe src="../../assets/diagrams/selinux/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. Attack Vectors & Lab Structure

### 5.1 Target Driver (`/proc/vuln_selinux`)

- **Source File**: `labs/28-selinux/vuln_selinux.c`
- **Proc Interface**: `/proc/vuln_selinux` (permissions `0666`)
- **Control Commands**:
  - `echo 'mode permissive' > /proc/vuln_selinux`: Switch to Mode 0 (Permissive mode: AVC audit logging without blocking)
  - `echo 'mode enforcing' > /proc/vuln_selinux`: Switch to Mode 1 (Enforcing mode: strict `-EACCES` denial for TE and MLS violations)
  - `echo 'test content' > /proc/vuln_selinux`: Test authorized web content access (`httpd_sys_content_t`)
  - `echo 'test shadow' > /proc/vuln_selinux`: Test unauthorized shadow file read (`shadow_t` TE violation)
  - `echo 'test mls' > /proc/vuln_selinux`: Test unauthorized MLS Read-Up from $s0$ to $s1:c0$
  - `echo 'test transition' > /proc/vuln_selinux`: Test unauthorized domain escalation to `unconfined_t`
  - `echo 'run_bench' > /proc/vuln_selinux`: Execute in-kernel automated benchmark and verification suite

---

### 5.2 Userland PoC Exploit (`exploit_selinux`)

- **Source File**: `labs/28-selinux/exploit.c`
- **Execution Workflow**:
  1. **Pre-flight Checks**: Inspect `/proc/self/attr/current`, `/sys/fs/selinux/enforce`, and `/sys/kernel/security/lsm`.
  2. **Phase 1 (Permissive Mode Verification)**:
     - Confirms that shadow access, MLS read-up, and domain transition requests succeed (ALLOWED) while triggering AVC audit warnings.
  3. **Phase 2 (Enforcing Mode Verification)**:
     - Confirms authorized content read succeeds (GRANTED).
     - Confirms shadow access, MLS read-up, and domain transition are strictly blocked with `-EACCES`.

---

### 5.3 In-Guest Test Runner (`test_selinux`)

- **Source File**: `labs/28-selinux/test.sh` (installed to `/bin/test_selinux` in rootfs)
- **Validation Steps**:
  1. Ensure `securityfs` and `selinuxfs` are mounted.
  2. Confirm presence of `/proc/vuln_selinux`.
  3. Run `/bin/exploit_selinux` as unprivileged user `lab` (UID 1000).
  4. Inspect kernel `dmesg` for standard AVC audit logs (`type=1400 audit(avc): denied ... permissive=0/1`).

---

## 6. Kconfig Configuration Comparison

### 6.1 Defense Enabled (`configs/features/selinux.config`)
```ini
CONFIG_NET=y
CONFIG_INET=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS=9
CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE=256
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_LSM="landlock,lockdown,yama,selinux,bpf"
```

> [!NOTE]
> `CONFIG_SECURITY_SELINUX` depends on `SECURITY && NET`. Networking configurations (`CONFIG_NET=y`, `CONFIG_INET=y`) must be enabled.

### 6.2 Defense Disabled (`configs/features/selinux-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LSM="capability"
```

---

## 7. Verification & QEMU Execution

### 7.1 Root Filesystem Build
```bash
./scripts/build_rootfs.sh --arch arm64 --force
./scripts/build_rootfs.sh --arch x86_64 --force
```

### 7.2 Kernel Compilation
```bash
# ARM64 Build
./scripts/build_kernel.sh --arch arm64 --feature selinux

# x86_64 Build
./scripts/build_kernel.sh --arch x86_64 --feature selinux
```

### 7.3 QEMU Automated Verification
```bash
# ARM64 Test
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-selinux/arch/arm64/boot/Image --test test_selinux --timeout 60

# x86_64 Test
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-selinux/arch/x86/boot/bzImage --test test_selinux --timeout 60
```
