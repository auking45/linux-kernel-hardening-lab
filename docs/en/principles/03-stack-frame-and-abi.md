# 03. Stack Frame Mechanics and Calling Conventions (Stack Frame & ABI)

Dissecting the byte-by-byte mechanics of **stack frame creation and teardown**, along with the **calling conventions (System V AMD64 ABI vs ARM64 AAPCS)** that orchestrate function calls on modern 64-bit microprocessors.

---

## 1. Learning Objectives & Overview

- Understand why stacks grow downward from high memory to low memory.
- Analyze how the `call` instruction pushes the Return Address (RET) onto the stack.
- Trace register alterations during function prologues (`push rbp; mov rsp, rbp`) and epilogues (`leave; ret`).
- Compare integer and pointer argument delivery between the System V AMD64 ABI and ARM64 AAPCS.
- Calculate exact memory distances between local input buffers and the saved Return Address.

---

## 2. Interactive Stack Frame Generation & Teardown

Step through the phases below to observe memory allocations and register states during function execution:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/03-stack-frame.html" style="width: 100%; min-height: 680px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const h = this.contentWindow.document.documentElement.scrollHeight; if(h) this.style.height = (h + 30) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. Byte-Level Stack Frame Anatomy

During execution, a function stack frame follows a strict contiguous layout:

```
[High Memory]
─────────────────────────────────────────────────────────────
  +0x18(%rbp)  │ Caller Stack Frame (Spilled arguments > 6)
─────────────────────────────────────────────────────────────
  +0x08(%rbp)  │ Return Address (RET)  Pushed automatically by CALL
─────────────────────────────────────────────────────────────
   0x00(%rbp)  │ Saved Frame Pointer (SFP)  Caller's backed-up RBP
─────────────────────────────────────────────────────────────
  -0x20(%rbp)  │ Local Buffer [char buf[32]]  Local array buffer
─────────────────────────────────────────────────────────────
  -0x28(%rbp)  │ Local Variable (uint64_t val)  Current %rsp bottom
─────────────────────────────────────────────────────────────
[Low Memory (RSP grows downward)]
```

### 3.1 Function Prologue Assembly

Instructions establishing a new execution frame upon entry:

```nasm
push   %rbp         ; Back up caller's base pointer to stack (SFP, consumes 8 bytes)
mov    %rsp, %rbp   ; Set current top of stack as new base pointer (RBP)
sub    $0x30, %rsp  ; Decrement RSP by 48 bytes to allocate local variables
```

### 3.2 Function Epilogue Assembly

Instructions cleaning up the frame and returning execution safely:

```nasm
leave               ; mov %rbp, %rsp && pop %rbp (restores caller's RBP)
ret                 ; pop %rip (pops Return Address into Instruction Pointer)
```

---

## 4. Architectural Calling Convention Comparison: x86_64 vs ARM64

| Evaluation Criteria | x86_64 (System V AMD64 ABI) | ARM64 (AAPCS64) |
| :--- | :--- | :--- |
| **Argument Registers** | `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9` (Up to 6) | `X0` through `X7` (Up to 8) |
| **Return Value Register** | `RAX` (Auxiliary: `RDX`) | `X0` (Auxiliary: `X1`) |
| **Return Address Storage** | Automatically pushed to stack by `call` | Stored in Link Register `LR (X30)` by `bl` |
| **Frame Pointer** | `RBP` | `X29 (FP)` |
| **Stack Alignment** | 16-byte alignment before `call` | 16-byte alignment hardware enforced |

---

## 5. Lab Source Code & Offset Calculation

- **Lab Source Code**: [`stack_frame_demo.c`](../../assets/labs/principles/03-stack-frame/stack_frame_demo.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/03-stack-frame/stack_frame_demo.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/03-stack-frame/Makefile)

### 5.1 Running the Lab

```bash
cd labs/principles/03-stack-frame
make run
```

```
============================================================
 Stack Frame Anatomical Analysis (target_function)
============================================================
[ABI] Architecture: x86_64 (System V AMD64 ABI)
      Register Args: a1(RDI)=0x11, a2(RSI)=0x22, a3(RDX)=0x33
                     a4(RCX)=0x44, a5(R8)=0x55,  a6(R9)=0x66
      Stack Args   : a7=0x7ffe723a1a60 (0x77), a8=0x7ffe723a1a68 (0x88)
------------------------------------------------------------
[Stack Frame Memory Layout from Low to High Addresses]
  [Low Addr]  local_buffer[0]      : 0x7ffe723a1a20
              local_buffer[31]     : 0x7ffe723a1a3f
              local_var            : 0x7ffe723a1a18 (val=0xdeadbeefcafebabe)
              Saved Frame Pointer  : 0x7ffe723a1a40 (points to caller's frame)
  [High Addr] Return Address (RET) : 0x7ffe723a1a48 (caller: 0x55dc98a21182)
------------------------------------------------------------
[Buffer Overflow Math]
  * Distance from local_buffer[0] to Saved RBP (SFP) : 32 bytes
  * Distance from local_buffer[0] to Return Address  : 40 bytes
  => To smash Return Address: Provide [40 bytes of padding] + [8 bytes of target address]
============================================================
```

### 5.2 Disassembling Prologue and Epilogue

```bash
make disasm
```

- Inspect raw assembly generated for `target_function`, noting the prologue and epilogue sequences.

---

## 6. Summary & Next Chapter

- Because return addresses sit above local buffers in memory, omitting input bounds checks exposes execution control to memory overwrite.
- In the next chapter, we investigate the weaponized machine payload designed to be invoked upon hijacking: **[04. Shellcode Architecture and Opcode Engineering](04-shellcode-engineering.md)**.
