# CONFIG_RANDOMIZE_BASE: KASLR & nokaslr Boot Parameter Verification

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/kaslr/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="KASLR Architecture Diagram"></iframe>
</div>

---

## 1. Overview & Threat Model

### 1.1 The Threat: Deterministic Address Mapping & Hardcoded ROP Gadgets

- **Vulnerability of Static Address Spaces**:
  - In kernels without KASLR (`nokaslr` boot parameter or `CONFIG_RANDOMIZE_BASE=n`), the kernel text start address (`_text`) is statically mapped at a fixed virtual address (e.g. `0xffffffff81000000` on x86_64).
  - An attacker analyzing an offline `vmlinux` binary or distribution `System.map` can determine the exact addresses of critical functions (`commit_creds`, `init_cred`) and Return-Oriented Programming (ROP) gadgets ahead of time.
  - As a result, a single control-flow hijacking vulnerability (e.g. buffer overflow, dangling pointer) enables a 100% reliable privilege escalation exploit.
- **Defense Mechanism of KASLR**:
  - During early decompression, the kernel extracts hardware entropy to select a random **KASLR Slide (offset)**, scattering the kernel code and static data across hundreds to thousands of possible slots.
  - Unless an attacker first discovers a memory disclosure (infoleak) vulnerability to compute the slide, blind attacks jumping to hardcoded addresses hit unmapped memory, immediately triggering a Page Fault and neutralizing the exploit.

### 1.2 The Moving Safehouse Metaphor

- **Analogy**:
  - Think of the kernel text and core data structures as a **covert military safehouse**.
  - **Before Hardening (Base Kernel / `nokaslr`)**: The safehouse is permanently built at a fixed, publicly known map coordinate (`0xffffffff81000000`). Enemies (attackers) do not need recon; they simply aim long-range artillery (hardcoded ROP chains) directly at the known coordinate and destroy it on the first shot.
  - **With KASLR Hardening**: The safehouse is completely mobile, quietly relocating to one of hundreds of secret decoy coordinates every night (upon every boot). Shells fired at yesterday's coordinate land in empty space (Unmapped Page). To mount an effective strike, the enemy must first plant a spy (an infoleak vulnerability) to extract today's relocated coordinates.

---

## 2. Kernel Internal Architecture

### 2.1 Early Decompressor Slide Selection

- **Boot-Time Random Positioning**:
  - Before the main kernel is uncompressed and virtual paging is engaged, early bootstrap routines (`arch/x86/boot/compressed/kaslr.c`, `arch/arm64/kernel/kaslr.c`) execute.
  - Random seeds are harvested from CPU hardware instructions (`RDRAND`), time-stamp counters (`RDTSC`), firmware interfaces (UEFI RNG protocol), or virtualization devices (`virtio-rng`).
- **Slot Alignment and Entropy (x86_64 vs ARM64)**:
  - **x86_64**: Randomly selects a 2MB-aligned slot (PMD boundary) within a 1GB window starting from `__START_KERNEL_map` (`0xffffffff80000000`), yielding up to 512–1024 slots (9–10 bits of entropy).
  - **ARM64**: Shifts `_text` by a randomized offset avoiding module and vmalloc ranges, providing robust layout obfuscation.

### 2.2 Command Line Override (`nokaslr`)

- Early bootstrap code inspects the boot command line for the `nokaslr` parameter:
  ```c
  /* arch/x86/boot/compressed/kaslr.c */
  if (cmdline_find_option_bool("nokaslr")) {
      warn("KASLR disabled: 'nokaslr' on cmdline.");
      return;
  }
  ```
- When `nokaslr` is present, random slide generation is bypassed, and the kernel loads at the static default base (`STATIC_TEXT_BASE`). This is widely used during development and kernel debugging (GDB, KGDB).

---

## 3. Hands-on Lab & Exploit PoC

### 3.1 Vulnerable Target Driver (`vuln_kaslr.c`)

- Exposes `/proc/vuln_kaslr` (mode `0666`):
  - **Telemetry Reader (Read)**: Reports current runtime `_text` location, static compile-time baseline, active KASLR slide, and randomization status.
  - **Arbitrary Function Dispatch (Write)**: Simulates an attacker dispatching a hijacked function pointer by testing whether a submitted address hits `kaslr_target_function`.

### 3.2 Dual-Arch Verification & Live Output Comparison

```bash
# 1. Base Kernel (Vulnerable nokaslr)
./scripts/run_lab.sh --arch x86_64 --feature kaslr-disabled --test test_kaslr

# 2. Hardened Kernel (KASLR Active)
./scripts/run_lab.sh --arch x86_64 --feature kaslr --test test_kaslr
```

=== "Base Kernel (Vulnerable: nokaslr Static Exploit Succeeded)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - KASLR Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] Kernel Memory Layout Telemetry:
        Current Text Base:   0xffffffff81000000
        Static Default Base: 0xffffffff81000000
        Target Function:     0xffffffff8143f210
        KASLR Slide:         0x0000000000000000
        KASLR Status:        DISABLED (Deterministic)

    =========================================================
    [*] Stage 1: Blind Attack (Without Kernel Infoleak)
        Attempting call to precomputed static address: 0xffffffff8143f210
    =========================================================
    [!] VULNERABILITY CONFIRMED: KASLR IS DISABLED (nokaslr)
    [!] Static gadget address 0xffffffff8143f210 matched target perfectly!
    [!] Attackers can execute arbitrary ROP chains with 100% certainty.
    ```
    > **Analysis:** With KASLR disabled, the kernel text base is fixed at `0xffffffff81000000` and the slide is `0x0`. A precomputed static address lands squarely on target without needing any infoleak.

=== "Hardened Kernel (Mitigated: KASLR Slide Deflected Attack)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - KASLR Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] Kernel Memory Layout Telemetry:
        Current Text Base:   0xffffffff9bc00000
        Static Default Base: 0xffffffff81000000
        Target Function:     0xffffffff9c03f210
        KASLR Slide:         0x000000001ac00000
        KASLR Status:        ENABLED

    =========================================================
    [*] Stage 1: Blind Attack (Without Kernel Infoleak)
        Attempting call to precomputed static address: 0xffffffff8143f210
    =========================================================
    [+] DEFENSE ACTIVE: KASLR RANDOMIZATION VERIFIED!
    [+] Blind static address missed the target by 0x1ac00000 bytes.
    [+] Execution hijacked to invalid/unmapped memory is foiled!

    =========================================================
    [*] Stage 2: Infoleak-Assisted Attack (Simulated Infoleak)
        Applying known KASLR slide 0x1ac00000 -> Adjusted Address: 0xffffffff9c03f210
    =========================================================
    [*] Infoleak-adjusted dispatch completed.
    [*] Key Takeaway: KASLR forces attackers to find an infoleak first,
        proving why Category 1 defenses (e.g. STACKLEAK) are vital!
    ```
    > **Analysis:** The hardened kernel randomly shifted by `0x1ac00000` bytes. The blind attack missed by over 400MB, conclusively demonstrating that KASLR mandates an infoleak for successful exploitation.

---

## 4. Runtime Administration & Telemetry

### 4.1 `/proc/cmdline` Inspection

- Verify whether `nokaslr` was passed during boot:
  ```bash
  cat /proc/cmdline | grep -o "nokaslr" || echo "KASLR is ACTIVE"
  ```

### 4.2 Restricting Address Leaks via `kptr_restrict`

- To preserve the effectiveness of KASLR, unprivileged access to kernel pointers must be restricted:
  ```bash
  sysctl -w kernel.kptr_restrict=1
  ```

---

## 5. Performance & Overhead Analysis

- **Runtime Execution Overhead: 0.0%**:
  - KASLR randomization occurs exclusively once during early boot when the initial page tables are established.
  - Once running, the MMU handles address translation directly with **zero ongoing CPU runtime penalty**.
- **Boot Time Impact**:
  - Entropy harvesting and page offset calculations take only a few fractions of a millisecond.

---

## 6. Presentation Script & Vocabulary

### 6.1 Presentation Script (English & Korean)

```text
[Step 1: Hook - The Peril of Static Coordinates]
"If a burglar possesses your exact home address and pre-written lock combinations,
 no matter how fortified your door is, a single break-in guarantees complete disaster.
 This is precisely the vulnerability of an unrandomized kernel.
 With fixed addresses at 0xffffffff81000000, attackers execute pre-computed ROP chains with 100% certainty."

[Step 2: Metaphor & Architecture - The Moving Safehouse]
"KASLR transforms the kernel into a moving safehouse that quietly shifts coordinates upon every boot.
 Using hardware entropy, it generates a unique KASLR Slide—such as 0x1ac00000—offsetting all text and symbols.
 Any blind attack targeted at static addresses strikes unmapped space and collapses.
 This compels attackers to find a secondary infoleak vulnerability just to calculate the shift."

[Step 3: Demo & Proof - The Case for Defense-in-Depth]
"As verified live in our QEMU environment, the nokaslr kernel succumbed instantly to static payloads,
 whereas the KASLR-enabled kernel deflected blind attacks by a wide margin.
 This conclusively demonstrates why Category 1 defenses like STACKLEAK are indispensable:
 KASLR and stack poisoning work hand-in-glove to deliver true Defense-in-Depth."
```

### 6.2 Key Presentation Phrases

| English Speaking Phrase                                 | Technical Context & Usage Tip                      |
| :------------------------------------------------------ | :------------------------------------------------- |
| _"randomize the kernel image base at early boot"_       | Describing the core definition and timing of KASLR |
| _"render hardcoded ROP gadgets utterly obsolete"_       | Emphasizing the neutralization of static exploits  |
| _"apply a dynamic KASLR slide across the text segment"_ | Explaining the technical slide mechanics           |
| _"compel adversaries to chain a prerequisite infoleak"_ | Explaining elevated attacker complexity            |
| _"imposes zero runtime performance penalty"_            | Highlighting the 0.0% operational performance cost |
