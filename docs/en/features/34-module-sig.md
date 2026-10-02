# Module Signature Verification

## 1. Overview & Threat Model

**Kernel Module Signature Verification** is a core Linux security defense that **cryptographically verifies the integrity and authenticity of dynamically loaded kernel modules (`.ko`, LKM) against in-kernel trusted keyrings before mapping or executing code in Ring 0**.

Because Linux loadable kernel modules execute with full kernel privileges in Ring 0, the unauthorized insertion of a single malicious module can immediately compromise the entire system (including LSMs, Seccomp, and page table isolation):

1. **LKM Rootkit Insertion Threat**:
   - An adversary who acquires root privileges or arbitrary write access in `/lib/modules/` can drop an LKM rootkit and load it via `insmod` or `modprobe`.
   - Such rootkits can conceal processes, hook the system call table, eavesdrop on network traffic, and tamper with audit logs directly inside the kernel.
2. **Tampered Driver Exploitation**:
   - Attackers can modify binary instructions inside an otherwise legitimate hardware driver to inject backdoors or disable memory protections upon driver initialization.
3. **Mandatory Verification via CONFIG_MODULE_SIG_FORCE**:
   - Enforcing strict signature checking ensures that any module lacking a valid cryptographic signature verified against `.builtin_trusted_keys` is immediately rejected (`-ENOKEY`, `-EKEYREJECTED`), preventing Ring 0 compromise.

---

## 2. Architecture & Mechanism

### 1. Interactive Architecture Simulator

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/module-sig/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. Real-World Analogy: Anti-Counterfeiting Holographic Passports in Air Traffic Control

The mechanism of Module Signature Verification functions identically to **biometric and cryptographic badge verification at an international airport control tower**:

```
[ Permissive Mode (sig_enforce=0) ]
  Intruder:      "I have no official security badge (unsigned rootkit), but I want to enter the control tower (Ring 0)!"
  Security:      "We will log a visitor warning stamp (TAINT_UNSIGNED_MODULE), but allow you in anyway." (Severe security hazard)

[ Enforced Mode (CONFIG_MODULE_SIG_FORCE=y / sig_enforce=1) ]
  Intruder:      "Attempts to enter the control tower with an unsigned or forged badge!"
  Security Gate: "Verifying badge against the National Security Cryptographic Keyring (.builtin_trusted_keys)!"
  Decision 1:    "No cryptographic signature block detected -> Rejected with -ENOKEY! Badge shredded!"
  Decision 2:    "Signature present but payload hash mismatch -> Rejected with -EKEYREJECTED! Entry denied!"
  Outcome:       "Only certified personnel bearing genuine, tamper-proof credentials enter Ring 0."
```

---

### 3. Module Format & Cryptographic Validation Flow

During compilation, the kernel build system appends a cryptographic signature trailer to the module ELF binary:

```
+-------------------------------------------------------+
|                ELF Module Binary Body                 |
|             (.text, .data, .rodata, etc.)             |
+-------------------------------------------------------+
|            PKCS#7 / CMS Cryptographic Signature       |
|          (Signed SHA-256 Digest via X.509 Key)        |
+-------------------------------------------------------+
|  struct module_signature {                            |
|      u8 algo;    /* Hash algo: SHA-256 */             |
|      u8 hash;    /* Public key algo: RSA/ECDSA */     |
|      u8 id_type; /* PKEY_ID_PKCS7 */                  |
|      __be32 sig_len; /* Length of PKCS#7 block */     |
|  }                                                    |
+-------------------------------------------------------+
|  Magic String: "~Module signature append~" (28 bytes) |
+-------------------------------------------------------+
```

1. **Magic String Detection (`module_sig_check`)**:
   - When `init_module()` or `finit_module()` is invoked, the kernel inspects the final 28 bytes of the binary buffer to verify the existence of `~Module signature append~`.
2. **Trailer Extraction & ELF Restoration**:
   - The kernel strips the magic string, metadata structure, and PKCS#7 block, isolating the clean ELF module image.
3. **Keyring Lookup & Digest Verification (`verify_pkcs7_signature`)**:
   - The kernel queries `.builtin_trusted_keys` for the corresponding X.509 public key certificate.
   - It computes the SHA-256 digest across the ELF binary sections and verifies it against the signed PKCS#7 signature.
4. **Enforcement Decision**:
   - Valid signature: The module is mapped into kernel memory and initialized.
   - Missing or invalid signature (`sig_enforce=1`): The module is immediately freed and rejected with `-ENOKEY` or `-EKEYREJECTED`.

---

## 3. Configuration & Boot Parameters

### 1. Kconfig Fragment

```ini
# configs/features/module-sig.config
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
```

### 2. Runtime Control Interface & Boot Parameters

| Parameter / Node | Default | Description |
| :--- | :--- | :--- |
| `module.sig_enforce=1` | Kernel cmdline | Enforces signature verification at boot time (equivalent to `CONFIG_MODULE_SIG_FORCE=y`) |
| `/sys/module/module/parameters/sig_enforce` | `Y` or `N` | Query sysfs node for active module signature enforcement |
| `/proc/keys` | R-only | Inspect registered certificates in `.builtin_trusted_keys` |
| `/proc/sys/kernel/tainted` | Integer flags | Tainted with `TAINT_UNSIGNED_MODULE` (bit 13, value 8192) when unsigned modules load |

---

## 4. Hands-on Verification & Exploit PoC

### 1. Test Scenario Overview

- Evaluate module loading behavior under both unprivileged (`lab`, UID 1000) and root contexts:
  - **Phase 1: Baseline (Permissive Mode - sig_enforce=0)**:
    - Signed module: Loads successfully (`ret = 0`).
    - Unsigned module: Loads with kernel taint warning (`TAINT_UNSIGNED_MODULE`).
    - Tampered module: Loads with verification warning.
  - **Phase 2: Hardened (Enforced Mode - CONFIG_MODULE_SIG_FORCE=y)**:
    - Signed module: Loads successfully (`ret = 0`).
    - Unsigned module: Intercepted and blocked with `-ENOKEY`.
    - Tampered module: Intercepted and blocked with `-EKEYREJECTED`.

### 2. Dual-Architecture Execution Logs

=== "ARM64: Module Signature Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-modsig/arch/arm64/boot/Image --test test_module_sig
    ```
    ```
    ================================================================
       Lab 34: Module Signature Verification Suite                  
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting kernel module signature status...
        Module sig_enforce status: Y
    [*] Step 2: Inspecting kernel trusted keyrings (/proc/keys)...
        00000002 I--Q---     1 perm 1f3f0000     0     0 keyring   .builtin_trusted_keys: 1
        071d2ea4 I--Q---     1 perm 1f010000     0     0 asymmetric Kernel Build Signing Key: X.509
    [*] Step 3: Checking target driver at /proc/vuln_module_sig...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Module Sig PoC as user 'lab'...
    ================================================================
      Module Signature Verification (CONFIG_MODULE_SIG_FORCE) PoC  
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
       Kernel Module Signature Verification Status Report   
    ========================================================
    Signature Enforcement   : ENFORCED (Strict: -ENOKEY / -EKEYREJECTED) (sig_enforce=1)
    Trusted Keyring Support : CONFIG_SYSTEM_TRUSTED_KEYRING=y
    Signature Hash Algorithm: SHA-256 (PKCS#7 / CMS format)
    Total Load Requests     : 0
    Modules Loaded (Granted): 0
    Modules Denied          : 0
      - Unsigned Denials    : 0 (-ENOKEY)
      - Tampered Denials    : 0 (-EKEYREJECTED)
    ========================================================

    [*] PHASE 1: Evaluating Baseline (Mode: Permissive - sig_enforce=0)
        -> Loading validly signed module (PKCS#7 X.509)... (GRANTED)
        -> Loading unsigned module (rootkit / untrusted .ko)... (GRANTED)
        -> Loading tampered module (corrupted cryptographic signature)... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: Enforce - CONFIG_MODULE_SIG_FORCE=y)
        -> Loading validly signed module (expecting GRANTED: ret = 0)... (GRANTED)
        -> Loading unsigned module (expecting BLOCKED: -ENOKEY)... (BLOCKED: -ENOKEY)
        -> Loading tampered module (expecting BLOCKED: -EKEYREJECTED)... (BLOCKED: -EKEYREJECTED)

    [+] Module Signature Verification Complete: Unsigned Rootkits Prevented!

    [*] Step 6: Inspecting kernel dmesg for Module Signature events:
    [    5.120401] module_sig: [VERIFIED] Valid PKCS#7 signature verified against .builtin_trusted_keys (ret = 0)
    [    5.120580] module_sig: [REJECTED] Loading of unsigned module is rejected: -ENOKEY
    [    5.120610] PKCS#7 signature missing or not found in kernel trusted keyring
    [    5.121890] module_sig: [REJECTED] Module signature verification failed: -EKEYREJECTED (hash mismatch / key invalid)
    [    5.121920] PKCS#7 signature digest does not match module payload
    ================================================================
       Lab 34 Test Complete: Verified Module Signature Verification 
    ================================================================
    ```

=== "x86_64: Module Signature Verification Log"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-modsig/arch/x86/boot/bzImage --test test_module_sig
    ```
    ```
    ================================================================
       Lab 34: Module Signature Verification Suite                  
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting kernel module signature status...
        Module sig_enforce status: Y
    [*] Step 2: Inspecting kernel trusted keyrings (/proc/keys)...
        00000002 I--Q---     1 perm 1f3f0000     0     0 keyring   .builtin_trusted_keys: 1
        182b8ea0 I--Q---     1 perm 1f010000     0     0 asymmetric Kernel Build Signing Key: X.509
    [*] Step 3: Checking target driver at /proc/vuln_module_sig...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Module Sig PoC as user 'lab'...
    ================================================================
      Module Signature Verification (CONFIG_MODULE_SIG_FORCE) PoC  
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode: Permissive - sig_enforce=0)
        -> Loading validly signed module (PKCS#7 X.509)... (GRANTED)
        -> Loading unsigned module (rootkit / untrusted .ko)... (GRANTED)
        -> Loading tampered module (corrupted cryptographic signature)... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: Enforce - CONFIG_MODULE_SIG_FORCE=y)
        -> Loading validly signed module (expecting GRANTED: ret = 0)... (GRANTED)
        -> Loading unsigned module (expecting BLOCKED: -ENOKEY)... (BLOCKED: -ENOKEY)
        -> Loading tampered module (expecting BLOCKED: -EKEYREJECTED)... (BLOCKED: -EKEYREJECTED)

    [+] Module Signature Verification Complete: Unsigned Rootkits Prevented!

    [*] Step 6: Inspecting kernel dmesg for Module Signature events:
    [    9.340112] module_sig: [VERIFIED] Valid PKCS#7 signature verified against .builtin_trusted_keys (ret = 0)
    [    9.340280] module_sig: [REJECTED] Loading of unsigned module is rejected: -ENOKEY
    [    9.340310] PKCS#7 signature missing or not found in kernel trusted keyring
    [    9.341490] module_sig: [REJECTED] Module signature verification failed: -EKEYREJECTED (hash mismatch / key invalid)
    [    9.341520] PKCS#7 signature digest does not match module payload
    ================================================================
       Lab 34 Test Complete: Verified Module Signature Verification 
    ================================================================
    ```

---

## 5. Performance & Compatibility

1. **One-Time Load Overhead**:
   - Module signature verification occurs only once when a module is loaded via `init_module()`.
   - Once initialized in kernel space, running driver functions execute with zero overhead (0% runtime penalty).
2. **Third-Party & DKMS Drivers**:
   - Out-of-tree drivers built on target systems (such as NVIDIA drivers or ZFS) will fail to load under enforced mode unless signed using a Machine Owner Key (MOK) enrolled in the system keyring.
3. **Private Key Management**:
   - The private key used during module signing must be safeguarded. Build pipelines should leverage ephemeral keys or Hardware Security Modules (HSMs) to prevent unauthorized key exfiltration.

---

## 6. Lecture & Presentation Script

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In modern Linux infrastructure, loadable kernel modules represent both incredible architectural flexibility and an existential security threat. Because kernel modules execute in Ring 0 with unrestricted system privileges, an attacker who obtains root access or local write permissions could inject an unsigned LKM rootkit. This rootkit can hook system calls, hide processes, and disable security subsystems without leaving traces. Today, we delve into **Kernel Module Signature Verification**."

#### 2. Diagram & Architecture Walkthrough
> "Please examine our interactive architecture simulator on the screen. Look at the structure of a signed kernel module: it contains the compiled ELF binary, followed by a PKCS#7 cryptographic signature, a module signature metadata header, and the magic trailer `~Module signature append~`. When `init_module()` or `finit_module()` is invoked, the kernel extracts the signature and recalculates the SHA-256 digest over the ELF sections. This digest is cryptographically compared against the trusted X.509 certificates stored in `.builtin_trusted_keys`. When `CONFIG_MODULE_SIG_FORCE=y` is enforced, any unsigned or tampered module is rejected before a single instruction can execute in kernel space."

#### 3. Live Demo Commentary
> "In our live verification on ARM64 and x86_64, look at the difference between Permissive and Enforced modes. In Permissive mode, unsigned modules are allowed to load, but the kernel sets the `TAINT_UNSIGNED_MODULE` flag. However, when we switch to Enforced mode, the unsigned rootkit attempt is instantaneously terminated with `-ENOKEY`, and our tampered module test fails with `-EKEYREJECTED`. The kernel log explicitly notes that the cryptographic signature failed to validate against the trusted keyring. The unauthorized Ring 0 execution attempt is completely thwarted."

#### 4. Key Takeaways & Production Advice
> "To summarize: Enabling `CONFIG_MODULE_SIG_FORCE=y` ensures that only authorized, cryptographically signed drivers can enter the kernel perimeter. In mission-critical enterprise environments, combining module signature enforcement with UEFI Secure Boot and lockdown policies establishes a complete, unbreakable chain of trust from firmware up to running kernel drivers."
