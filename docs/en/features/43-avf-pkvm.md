# Android Virtualization Framework (AVF) & pKVM

## 1. Overview & Threat Model

**Android Virtualization Framework (AVF) and pKVM (`CONFIG_KVM`, Protected KVM)** is a groundbreaking hardware-enforced virtualization security architecture introduced in Android 13+. It **deprivileges the Host Android Operating System (EL1) and leverages the EL2 hypervisor to enforce Stage-2 Page Table (S2PT) isolation, making micro-virtual machine (pVM) guest memory completely inaccessible to the host**.

In traditional virtualization models (Legacy KVM, Type-2 hypervisors) and standard containers, the host kernel completely owns and manages the physical memory mappings of every guest virtual machine:

1. **Host Compromise Leading to Complete Guest Data Exfiltration**:
   - If an adversary acquires root or kernel execution on the host Android OS (EL1) via local privilege escalation (Kernel LPE), the attacker can inspect `/dev/mem`, walk host page tables, or read hypervisor memory buffers directly.
   - This poses a critical risk to high-value assets such as biometric facial/fingerprint templates, DRM master keys, digital car keys, and hardware crypto credentials.
2. **The pKVM Deprivileging Innovation**:
   - Under Protected KVM (pKVM), the Host Android OS (EL1) is formally classified as an **untrusted entity**.
   - An ultra-compact, audited hypervisor running at EL2 manages Stage-2 Page Tables (S2PT) independently.
   - When a micro-guest (pVM) is spawned, the host donates physical memory pages to the pVM. Crucially, pKVM **completely unmaps these physical pages from the Host's Stage-2 address space**.
   - Even if the host kernel is 100% rooted, any physical read or write attempted by the host against pVM memory triggers an architectural **Stage-2 Data Abort trapped at EL2**, permanently thwarting host snooping attacks.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/avf-pkvm/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Extraterritorial Embassy Safe in a Shared Hotel

AVF and pKVM function like an **extraterritorial sovereign embassy safe located inside a commercial hotel**:

```
[ Legacy Virtualization Model ]
  Intruder:  "I stole the hotel manager's master key (Host Kernel Root)!"
  Manager:   "I have keys to every room and vault in the building. Unlocking everything!" (All guest secrets stolen)

[ pKVM Architecture (Host Deprivileged & S2PT Unmapped) ]
  Hotel:     "Room #10 (pVM) has been donated to a sovereign foreign embassy. All master key access is permanently stripped from the hotel registry (Host S2PT)!"
  Intruder:  "Attempting to force open the embassy safe using the stolen master key!"
  Security:  "EL2 hypervisor security forces intervene instantly (Stage-2 Data Abort triggered, -EPERM returned)!"
  Outcome:   "Even if the hotel manager is held hostage, the diplomatic documents and biometric templates inside remain untouchable!"

[ Authorized Inter-VM Communication (virtio-vsock) ]
  Host:      "Sends verification request through the teller window (vsock port) without ever seeing the secret"
  pVM:       "Verifies credential internally and returns a simple 'VERIFIED: YES' token"
```

---

### 3. Mobile Isolation Technology Comparison Matrix

| Technology | Execution Domain | Hypervisor Layer | Protection if Host Kernel Rooted | Primary Scope & Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Linux Containers / Namespaces** | Host EL1 | None (Shared kernel) | **Total Failure** (Root escapes instantly) | Basic app separation (Weak security boundary) |
| **ARM TrustZone (TEE)** | Secure EL1 / EL3 | Secure World Partition | **Protected** | Vendor-proprietary, limited memory, difficult third-party deployment |
| **AVF / pKVM (Protected KVM)** | Non-Secure Guest EL1 | **ARMv8/v9 pKVM (EL2)** | **Complete Protection (Stage-2 Trap)** | Standard Android apps, scalable memory, biometric/AI enclave execution |

---

## 3. Kernel Configurations & Boot Arguments

### 1. Hardening Kconfig (`configs/features/avf-pkvm.config`)

```ini
# Linux Kernel Hardening Lab - AVF / pKVM Feature Config
CONFIG_KVM=y
CONFIG_VHOST_VSOCK=y
CONFIG_VIRTIO_VSOCK=y
CONFIG_ARM64_4K_PAGES=y
```

- `CONFIG_KVM=y`: Enables core KVM virtualization subsystem.
- `CONFIG_VHOST_VSOCK=y` & `CONFIG_VIRTIO_VSOCK=y`: Provides isolated socket-based inter-VM communication without direct memory page exposure.
- Boot argument: `kvm-arm.mode=protected` activates the EL2 pKVM hypervisor and deprivileges Host EL1 at boot.

---

## 4. Hands-on Lab: `labs/43-avf-pkvm`

### 1. Lab Components

1. **Target Driver (`labs/43-avf-pkvm/vuln_avf.c`)**:
   - Simulates pKVM memory donation, Stage-2 page table unmapping, and hypervisor trap handling.
   - Registered at `/proc/vuln_avf` (0666):
     - `create <id> <secret>`: Spawns a micro-guest pVM and applies Stage-2 unmapping.
     - `host_peek <id>`: Host attempts direct memory read into pVM (triggers Stage-2 Data Abort).
     - `host_tamper <id> <data>`: Host attempts memory overwrite (triggers Stage-2 Write Fault).
     - `vsock <id> <msg>`: Secure communication over isolated virtio-vsock socket.
     - `mode <pkvm|legacy>`: Toggles between pKVM hardened mode and unhardened legacy KVM.
2. **Exploit PoC Binary (`labs/43-avf-pkvm/exploit.c`)**:
   - Stage 1: Demonstrates legacy virtualization memory snooping by compromised host.
   - Stage 2: Deploys pKVM micro-guest with donated, unmapped physical pages.
   - Stage 3: Verifies pKVM EL2 intercepting direct host memory reads (`-EPERM` / Stage-2 Abort).
   - Stage 4: Verifies pKVM EL2 intercepting memory tampering attempts.
   - Stage 5: Validates legitimate communication over virtio-vsock channel.
3. **Automated Test Runner (`labs/43-avf-pkvm/test.sh`)**:
   - Checks KVM devices, evaluates driver presence, executes PoC, and inspects dmesg logs.

---

### 2. Execution Guide

```bash
# 1. Launch ARM64 virtual machine
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. Check for KVM character device
ls -l /dev/kvm

# 3. Run automated verification suite
/bin/test_avf_pkvm
```

### 3. Expected Test Output

```text
================================================================
   Lab 43: Android Virtualization Framework & pKVM Suite        
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking KVM virtualization subsystem...
[+] /dev/kvm character device present!

[*] Step 2: Checking target driver at /proc/vuln_avf...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== Android Virtualization Framework (AVF / pKVM) Status ===
pKVM Protection Mode     : ENABLED (Protected KVM Active)
Total Host Access Events : 0
Host Peeks Blocked (S2PT): 0
Host Tampers Blocked     : 0
Vsock RPC Exchanges      : 0
Active Micro-Guests (pVMs):
============================================================

[*] Step 4: Running AVF / pKVM PoC...
===============================================================
   Android Virtualization Framework (AVF / pKVM) PoC           
===============================================================

[*] Stage 1: Evaluating Legacy KVM (Unhardened Host Snooping)...
[!] VULNERABLE: Host kernel successfully inspected guest memory!
    In legacy virtualization, compromised host can steal all guest secrets.

[*] Stage 2: Enabling pKVM (Protected KVM) and Spawning pVM #1...
[+] pVM #1 memory donated and unmapped from Host Stage-2 Page Tables (S2PT).

[*] Stage 3: Rooted Host attempts to dump pVM #1 memory directly...
[+] DEFENSE SUCCESS: pKVM EL2 intercepted host read! (errno=1: Operation not permitted)
    Hypervisor Stage-2 Data Abort prevented host kernel snoop!

[*] Stage 4: Rooted Host attempts to overwrite pVM #1 memory...
[+] DEFENSE SUCCESS: pKVM EL2 intercepted host write! (errno=1: Operation not permitted)
    Memory write forbidden in Stage-2 page table; pVM integrity intact!

[*] Stage 5: Legitimate RPC over isolated virtio-vsock channel...
[+] SUCCESS: Vsock RPC communication handled securely by pVM enclave.

[*] Final AVF / pKVM Driver Diagnostics Report:
=== Android Virtualization Framework (AVF / pKVM) Status ===
pKVM Protection Mode     : ENABLED (Protected KVM Active)
Total Host Access Events : 3
Host Peeks Blocked (S2PT): 1
Host Tampers Blocked     : 1
Vsock RPC Exchanges      : 1
Active Micro-Guests (pVMs):
  [pVM #1] Stage-2 Isolated: YES, Secret Status: [SECURED]
============================================================
[+] AVF / pKVM verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for AVF / pKVM events:
[   72.101412] avf_pkvm: [PVM-CREATE] Micro-guest pVM #0 spawned. Memory donated. Stage-2 Isolated: NO
[   72.102315] avf_pkvm: [VULNERABLE SNOOP] Host read pVM #0 memory (Legacy KVM without pKVM Stage-2 isolation)
[   72.103102] avf_pkvm: [PVM-CREATE] Micro-guest pVM #1 spawned. Memory donated. Stage-2 Isolated: YES (Unmapped from Host S2PT)
[   72.103890] avf_pkvm: [STAGE-2 DATA ABORT] Host EL1 tried to read pVM #1 memory! pKVM EL2 intercepted and blocked access (-EPERM)
[   72.104612] avf_pkvm: [STAGE-2 WRITE FAULT] Host EL1 tried to overwrite pVM #1 memory! Blocked by pKVM hypervisor (-EPERM)
[   72.105340] avf_pkvm: [VSOCK RPC] Authenticated request processed by pVM #1 enclave.

================================================================
   Lab 43 Test Complete: Verified Android Virtualization & pKVM 
================================================================
```

---

## 5. Security Checklist & Best Practices

| Control Measure | Recommended Value | Security Guarantee |
| :--- | :--- | :--- |
| **pKVM Hypervisor Boot** | `kvm-arm.mode=protected` | Enforces deprivileging of the Host Android OS at the EL2 boundary |
| **Stage-2 Unmapping** | Automated page donation | Permanently unmaps physical memory from the host upon pVM startup |
| **Isolated IPC Channel** | `CONFIG_VIRTIO_VSOCK=y` | Prohibits raw shared memory; routes inter-VM traffic via vsock RPC |
| **Memory Scrubbing** | Zeroing on destruction | Guarantees zero residual secret leakage when micro-guests are torn down |
| **Minimal TCB** | Micro-guest Linux images | Restricts pVM size to minimal attack surface (sub-10MB kernels) |
