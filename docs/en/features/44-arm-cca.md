# Arm Confidential Compute Architecture (Arm CCA)

## 1. Overview & Threat Model

**Arm CCA (`CONFIG_ARM64_RME`, ARMv9-A)** is a transformative confidential computing architecture designed for public clouds and multi-tenant virtualization. It **formally classifies the host operating system and cloud hypervisor as untrusted adversaries (Untrusted Hypervisor), using hardware-enforced 4-World isolation and Granule Protection Checks (GPC) to guarantee the cryptographic confidentiality and execution integrity of tenant confidential virtual machines (Realm VMs)**.

In standard cloud computing environments, cloud service providers (CSPs), hypervisor operators, and rogue administrators possess unrestricted physical access to all guest memory:

1. **The Untrusted Cloud Infrastructure Threat**:
   - Attackers exploiting hypervisor vulnerabilities, malicious cloud employees, or legal subpoenas can dump tenant physical RAM directly.
   - Proprietary artificial intelligence (AI) model weights, private database keys, confidential financial records, and cryptographic credentials are exposed to persistent exfiltration.
2. **The 4-World Security Model Innovation**:
   - Expands hardware privilege realms beyond the traditional 2-World model (Secure vs Non-Secure) into **four discrete execution worlds**:
     - **Root World (EL3)**: Platform security monitor and silicon root of trust.
     - **Realm World (R-EL2 / R-EL1)**: Realm VMs executing confidential tenant workloads under the oversight of the Realm Management Monitor (RMM).
     - **Secure World (S-EL1 / S-EL0)**: Traditional TrustZone / OP-TEE.
     - **Non-Secure World (NS-EL2 / NS-EL1)**: Normal Host Linux OS / Cloud Hypervisor (KVM).
3. **Hardware Granule Protection Table (GPT) & Granule Protection Checks (GPC)**:
   - Physical memory granules (4KB) are assigned an architectural world tag.
   - When a granule is transitioned to `GPT_REALM`, the hardware MMU strictly prohibits access from Non-Secure World.
   - Any attempt by the untrusted hypervisor to read or write Realm physical memory immediately triggers a hardware **Granule Protection Fault (GPF)**.
4. **Cryptographic Remote Attestation**:
   - Tenants verify cryptographic SHA-256 measurement tokens signed by the silicon root of trust before uploading sensitive workloads to the cloud.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/arm-cca/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Swiss Bank Armored Vault in a Commercial Warehouse

Arm CCA functions identically to an **independent Swiss bank armored vault installed inside a public commercial warehouse**:

```
[ Legacy Cloud Virtualization Model ]
  Intruder:  "I gained root control over the warehouse master keys (Cloud Hypervisor)!"
  Hypervisor:"Since I own the warehouse, I will unlock all tenant shipping containers and steal their trade secrets!" (Total Confidentiality Loss)

[ Arm CCA: Physical Memory Delegation (RMI_GRANULE_DELEGATE) ]
  Tenant:    "Registering my storage vault with the Swiss bank (Realm World) and engaging hardware interlocks (GPT_REALM)!"
  Hypervisor:"Attempting to read customer vault memory directly!"
  Silicon:   "Silicon MMU Granule Protection Check (GPC) activates: 'Non-Secure access forbidden'!"
  Action:    "Physical bus lines clamped shut! Granule Protection Fault (-EPERM) raised! Data exfiltration aborted!"

[ Remote Attestation: Mathematical Seal Verification ]
  Tenant:    "Verifying the silicon digital signature from the central security authority (Root EL3) against our golden SHA-256 hash!"
  Verdict:   "Measurement matches perfectly! The vault has not been tampered with. Uploading confidential AI model weights!"
```

---

### 3. Confidential Computing Architecture Comparison Matrix

| Architectural Dimension | Arm CCA (`CONFIG_ARM64_RME`) | AMD SEV-SNP | Intel TDX |
| :--- | :--- | :--- | :--- |
| **Isolation Primitive** | **4-World Hardware Segregation (RMM + GPT)** | Hardware Memory Encryption (AES-128/256) | Trust Domains (SEAM / KeyLocker) |
| **Physical Memory Defense** | **Granule Protection Check (GPC)** | Reverse Map Table (RMT) | Secure EPT (S-EPT) |
| **Hypervisor Role** | CPU scheduling & I/O only (Zero memory access) | Page mapping only (Memory contents encrypted) | Resource management only (Access blocked) |
| **Remote Attestation** | RMM SHA-256 measurements + RoT signature | VCEK-signed attestation reports | Quote Generation Service (QGS) |
| **Memory Metadata Cost** | GPT table (~1.5% system RAM overhead) | Encryption tag overhead | TDX Control Structure memory |

---

## 3. Kernel Configurations & Hardening Flags

### 1. Hardening Kconfig (`configs/features/arm-cca.config`)

```ini
# Linux Kernel Hardening Lab - Arm CCA Feature Config
CONFIG_KVM=y
CONFIG_ARM64_RME=y
CONFIG_CRYPTO=y
CONFIG_CRYPTO_SHA256=y
CONFIG_ARM64_4K_PAGES=y
```

- `CONFIG_ARM64_RME=y`: Enables Realm Management Extension (RME) subsystem support within the host Linux KVM hypervisor.
- `CONFIG_KVM=y`: Provides standard KVM hypervisor APIs for scheduling and dispatching Realm virtual CPUs.
- `CONFIG_CRYPTO_SHA256=y`: Computes and verifies cryptographic attestation measurement digests.

---

## 4. Hands-on Lab: `labs/44-arm-cca`

### 1. Lab Components

1. **Target Driver (`labs/44-arm-cca/vuln_cca.c`)**:
   - Models the 4-World security boundary, Granule Protection Table (GPT) transitions, and GPC hardware filtering.
   - Registered at `/proc/vuln_cca` (0666):
     - `create <id>`: Spawns Realm VM instance in Realm World.
     - `delegate <id> <secret>`: Delegates 4KB physical memory granule to `GPT_REALM`.
     - `host_read <id>`: Untrusted host attempts direct read (triggers Granule Protection Fault).
     - `host_write <id> <data>`: Untrusted host attempts code injection (triggers GPC Write Fault).
     - `attest <id>`: Requests and validates cryptographic SHA-256 attestation measurements.
     - `mode <cca|legacy>`: Toggles between Arm CCA GPC enforcement and legacy unhardened cloud VM.
2. **Exploit PoC Binary (`labs/44-arm-cca/exploit.c`)**:
   - Stage 1: Demonstrates unprotected tenant data exfiltration by rogue cloud hypervisor.
   - Stage 2: Deploys Realm VM and delegates memory to `GPT_REALM`.
   - Stage 3: Verifies hardware Granule Protection Fault (`-EPERM`) upon direct host read.
   - Stage 4: Verifies hardware GPC blocking code injection and memory tampering.
   - Stage 5: Validates cryptographic remote attestation proof.
3. **Automated Test Runner (`labs/44-arm-cca/test.sh`)**:
   - Evaluates CPU architecture, confirms driver availability, executes PoC, and inspects dmesg logs.

---

### 2. Execution Guide

```bash
# 1. Launch ARM64 virtual machine
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. Inspect CPU RME capability
cat /proc/cpuinfo | grep -i rme

# 3. Run automated verification suite
/bin/test_arm_cca
```

### 3. Expected Test Output

```text
================================================================
   Lab 44: Arm Confidential Compute Architecture (Arm CCA)      
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking CPU Architecture and Arm CCA hardware support...
    Architecture: aarch64

[*] Step 2: Checking target driver at /proc/vuln_cca...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== Arm Confidential Compute Architecture (Arm CCA) Status ===
Hardware CCA Engine      : ENABLED (Granule Protection Active)
Security World Model     : 4-World (Root, Realm, Secure, Non-Secure)
Total Host Access Events : 0
GPC Read Faults (GPF)    : 0
GPC Write Faults (GPF)   : 0
Attestation Verifications: 0
Active Realm VMs (R-EL1):
==============================================================

[*] Step 4: Running Arm CCA PoC...
===============================================================
   Arm Confidential Compute Architecture (Arm CCA) PoC         
===============================================================

[*] Stage 1: Evaluating Legacy Cloud Hypervisor (Unhardened)...
[!] VULNERABLE: Cloud hypervisor stole tenant private key!
    In standard cloud setups, rogue hypervisors have complete memory access.

[*] Stage 2: Deploying Confidential Realm VM #1 under Arm CCA...
[+] Physical memory granules transitioned to GPT_REALM under RMM control.

[*] Stage 3: Untrusted Cloud Hypervisor attempts to inspect Realm VM #1...
[+] DEFENSE SUCCESS: Hardware GPC raised Granule Protection Fault! (errno=1: Operation not permitted)
    Silicon MMU prevented Non-Secure CPU core from reading Realm memory!

[*] Stage 4: Untrusted Cloud Hypervisor attempts to inject code into Realm...
[+] DEFENSE SUCCESS: Hardware GPC blocked write! (errno=1: Operation not permitted)
    Physical memory write-protect enforced by Granule Protection Table!

[*] Stage 5: Performing Cryptographic Remote Attestation...
[+] SUCCESS: Remote attestation report cryptographically verified!
    Proves Realm code integrity and uncompromised initial state.

[*] Final Arm CCA Driver Diagnostics Report:
=== Arm Confidential Compute Architecture (Arm CCA) Status ===
Hardware CCA Engine      : ENABLED (Granule Protection Active)
Security World Model     : 4-World (Root, Realm, Secure, Non-Secure)
Total Host Access Events : 3
GPC Read Faults (GPF)    : 1
GPC Write Faults (GPF)   : 1
Attestation Verifications: 1
Active Realm VMs (R-EL1):
  [Realm #1] GPT State: GPT_REALM (Hardware Protected), Measurement: a3f5b721e89b4317...
==============================================================
[+] Arm CCA verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for Arm CCA events:
[   81.101200] arm_cca: [RMI_REALM_CREATE] Realm VM #0 created in Realm World (R-EL1).
[   81.101912] arm_cca: [VULNERABLE SNOOP] Host read tenant VM #0 memory! (Legacy Hypervisor)
[   81.102640] arm_cca: [RMI_REALM_CREATE] Realm VM #1 created in Realm World (R-EL1).
[   81.103310] arm_cca: [RMI_GRANULE_DELEGATE] Physical granule transitioned to GPT_REALM. Managed by RMM.
[   81.104012] arm_cca: [GRANULE PROTECTION FAULT] Host read denied! GPC: Non-Secure CPU cannot read GPT_REALM (-EPERM)
[   81.104715] arm_cca: [GRANULE PROTECTION FAULT] Host write denied! GPC: Non-Secure CPU cannot write GPT_REALM (-EPERM)
[   81.105410] arm_cca: [RMI_ATTESTATION] Cryptographic measurement validated: a3f5b721e89b4317...

================================================================
   Lab 44 Test Complete: Verified Arm Confidential Compute (CCA)
================================================================
```

---

## 5. Security Checklist & Best Practices

| Control Measure | Recommended Value | Security Guarantee |
| :--- | :--- | :--- |
| **Enable RME Support** | `CONFIG_ARM64_RME=y` | Activates Realm Management Extension support within KVM |
| **Verify Granule Delegation** | `GPT_REALM` state verification | Enforces hardware GPC filtering on tenant physical memory |
| **Mandate Remote Attestation** | Client-side token verification | Authenticates initial measurement hash before dispatching secrets |
| **Zero-Memory Scrubbing** | Undelegation memory zeroing | Completely scrubs residual data before returning pages to host |
| **Block Non-Secure Access** | Granule Protection Fault | Prevents cloud hypervisors and root admins from reading tenant RAM |
