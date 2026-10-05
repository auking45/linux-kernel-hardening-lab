# 05. Classic Buffer Overflow and RIP/PC Hijacking (Buffer Overflow & Control Flow Hijack)

Analyzing foundational binary exploitation principles where missing boundary checks in C allow attacker-supplied input to overflow stack memory limits, **corrupt function pointers and return addresses, and hijack the CPU instruction pointer (PC / RIP)**. Features **AArch64 (ARM64)** as the primary target for device and mobile system security, with comparative analysis against **x86_64** and next-generation hardware defense mechanisms (ARM PAC/BTI vs. Intel CET).

---

## 1. Learning Objectives & Overview

- Identify vulnerabilities in unconstrained memory copy functions (`memcpy()`, `strcpy()`).
- Analyze control flow hijacking targets across AArch64 and x86_64 stack frame layouts (adjacent function pointers vs. Saved RET).
- Trace control flow diversion to an unreferenced administration function (`unreachable_admin_shell`) via CPU indirect branches (`blr xN` / `ret`).
- Evaluate the 3 foundational software mitigations (Stack Canary, NX/DEP, ASLR).
- Contrast next-generation hardware defenses: **ARM PAC (Pointer Authentication)** & **BTI (Branch Target Identification)** versus **Intel CET**.

---

## 2. Interactive Buffer Overflow & PC/RIP Hijack Simulator

Step through the 4 progressive stages (normal state ➔ buffer overflow ➔ pointer corruption ➔ PC/RIP redirection) in the interactive simulation below:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/05-bof-rip.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. Vulnerability Mechanism: Boundless Memory Copy

```c
struct ServiceSession {
    char stack_buffer[64];
    void (*dispatch_handler)(void);
};

void vulnerable_service(const char *user_input, size_t input_len) {
    volatile struct ServiceSession session;
    session.dispatch_handler = normal_worker;

    /* Flaw: copies input without enforcing 64-byte stack_buffer boundary */
    memcpy((void *)session.stack_buffer, user_input, input_len);

    /* Indirect branch jumps to the potentially corrupted function pointer */
    session.dispatch_handler();
}
```

- Stack memory writes proceed sequentially from lower to higher memory addresses.
- Exceeding the 64-byte boundary of `stack_buffer` immediately overflows into the adjacent **function pointer (`dispatch_handler`, 8 bytes)** located at the next offset.

---

## 4. Architectural Control Flow Hijacking Mechanisms

=== "AArch64 (ARM64 - Default Target)"
    Because AAPCS64 positions the frame record (`X29`/`X30`) at the base of the allocated frame (`[sp]`), intra-frame control flow hijacking primarily exploits adjacent stack function pointers:

    ```
    [Exploit Payload Layout (72 bytes total)]
    [0x00 .. 0x3F] (64 bytes) : 'A' * 64 (Buffer padding)
    [0x40 .. 0x47] ( 8 bytes) : 0x0000000000400908 (Target address of unreachable_admin_shell)
    ```

    ```mermaid
    sequenceDiagram
        autonumber
        actor Attacker as Attacker
        participant Stack as Stack Memory (Session)
        participant CPU as CPU Registers (X0~X30 / PC)

        Attacker->>Stack: Inject 72-byte crafted payload (memcpy)
        Note over Stack: stack_buffer[64] ➔ 'A'*64<br/>dispatch_handler[8] ➔ 0x400908 (Hijacked!)
        CPU->>Stack: ldr x3, [sp, #64] (Load dispatch_handler)
        CPU->>CPU: blr x3 (Execute indirect call!)
        Note over CPU: PC = 0x400908 (<unreachable_admin_shell>)
        CPU->>Attacker: Unauthorized admin routine invoked!
    ```

=== "x86_64 (AMD64 - Comparative Target)"
    On x86_64, local variables reside below the saved return address, allowing linear overflows to overwrite Saved RIP directly:

    ```
    [Exploit Payload Layout (80 bytes total)]
    [0x00 .. 0x3F] (64 bytes) : 'A' * 64 (Buffer padding)
    [0x40 .. 0x47] ( 8 bytes) : 'B' * 8  (Saved RBP / SFP)
    [0x48 .. 0x4F] ( 8 bytes) : 0x0000000000401156 (Saved RET Address)
    ```

    - The `ret` instruction pops the corrupted address into `RIP`, redirecting execution.

---

## 5. Lab Source Code & Hijack Verification

- **Lab Source Code**: [`bof_demo.c`](../../assets/labs/principles/05-bof-rip/bof_demo.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/05-bof-rip/bof_demo.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/05-bof-rip/Makefile)

### 5.1 Normal Mode Execution

=== "AArch64 (Default Target)"
    ```bash
    cd labs/principles/05-bof-rip
    make run-normal
    ```

    ```
    === [1] Running Normal Mode [aarch64] ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./bof_demo
    ============================================================
     Classic Buffer Overflow & PC Hijacking Simulator [AArch64]
    ============================================================
    [*] Target Function unreachable_admin_shell : 0x400908
    [*] main() Function                         : 0x400bc8

    === [Mode 1: Normal In-Bounds Operation] ===
    [+] Sending safe payload (33 bytes) into 64-byte buffer.
    --- [Stack State Before Input Copy] ---
      session.stack_buffer[0] Address : 0x4000007feca8
      session.dispatch_handler Addr  : 0x4000007fece8 (points to: 0x4008e8)
      Saved Frame Pointer (FP/RBP)   : 0x4000007fec80
      Saved Return Address (LR/RIP)  : 0x400ae4
      Buffer to Handler Distance     : 64 bytes
    ---------------------------------------
    [+] vulnerable_service() invoking session.dispatch_handler()...
    [+] Normal worker executed safely. Workflow completed.
    ```

=== "x86_64 (Comparative Target)"
    ```bash
    cd labs/principles/05-bof-rip
    make ARCH=x86_64 run-normal
    ```

### 5.2 Exploit Mode Execution (PC / RIP Hijack)

=== "AArch64 (Default Target)"
    ```bash
    make run-attack
    ```

    ```
    === [2] Running Control Flow Hijack Attack [aarch64] ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./bof_demo --attack
    ============================================================
     Classic Buffer Overflow & PC Hijacking Simulator [AArch64]
    ============================================================
    [*] Target Function unreachable_admin_shell : 0x400908
    [*] main() Function                         : 0x400bc8

    === [Mode 2: Buffer Overflow & Control Flow Hijack Attack] ===
    [+] Fabricated Exploit Payload (72 bytes):
        [0..63]  Buffer Padding   : 64 bytes of 'A' (0x41)
        [64..71] Hijacked Target  : 0x400908 (unreachable_admin_shell)

    [!] Delivering exploit payload into vulnerable_service()...
    --- [Stack State After Input Copy] ---
      session.dispatch_handler now   : 0x400908
    ---------------------------------------
    [+] vulnerable_service() invoking session.dispatch_handler()...

    ============================================================
     [!] CRITICAL SECURITY COMPROMISE: Control Flow Hijacked!
    ============================================================
     [★] CPU Instruction Pointer (RIP / PC) redirected to:
         unreachable_admin_shell() at 0x400908!
     [★] Attacker gained arbitrary code execution in target process.
    ============================================================
    ```

=== "x86_64 (Comparative Target)"
    ```bash
    make ARCH=x86_64 run-attack
    ```

    - Verifies function pointer overwrite to `unreachable_admin_shell` on native x86_64.

---

## 6. Modern Hardware Hardening & Architectural Defenses

Modern computing platforms deploy defense-in-depth across compiler and hardware layers:

| Defense Layer | AArch64 (ARMv8.3+ / ARMv8.5+) | x86_64 (Intel CET) | Operating Principle |
| :--- | :--- | :--- | :--- |
| **Return Address Protection** | **PAC (Pointer Authentication)**<br/>(`paciasp` / `autiasp`) | **CET Shadow Stack** | Cryptographically signs return pointers or maintains an isolated hardware return stack to detect corruption. |
| **Indirect Branch Protection** | **BTI (Branch Target Identification)**<br/>(`bti c`, `bti j`) | **CET IBT**<br/>(`ENDBR64` landing pads) | Hardware exceptions trigger if indirect branches land anywhere other than approved landing-pad instructions. |
| **Stack Canaries** | Stack Canary (`-fstack-protector`) | Stack Canary (`-fstack-protector`) | Random sentinel values placed ahead of frame records abort execution upon corruption. |
| **Memory Execution Prohibition** | XN (Execute-Never / NX) | NX / DEP (No-Execute) | Strips execution rights from stack and heap data pages. |
| **Address Layout Randomization** | ASLR & PIE | ASLR & PIE | Randomizes segment base addresses on every run to prevent hardcoded address targeting. |

> [!TIP]
> With foundational hardware and memory principles established, continue to real-world embedded vulnerabilities and mitigation engineering in the **[Attack Scenarios Track](../scenarios/index.md)**.
