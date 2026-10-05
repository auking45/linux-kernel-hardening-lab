# 03. Stack Frame Anatomy and Calling Convention (Stack Frame & ABI)

A byte-level architectural dissection of **Stack Frame generation and teardown** during function invocation, alongside calling conventions under **AArch64 (AAPCS64)** and **x86_64 (System V AMD64 ABI)**.

---

## 1. Learning Objectives & Overview

- Understand the physical mechanics of why stack memory grows downward from high to low memory addresses.
- Contrast AArch64's Link Register (`X30 / LR`) return mechanism with x86_64's automatic stack push (`call`).
- Analyze AArch64 AAPCS64 prologue (`stp x29, x30, [sp, #-N]!`) and epilogue (`ldp x29, x30, [sp], #N; ret`) execution.
- Dissect the architectural difference in stack layout (frame record placement versus local variable offsets) between AArch64 and x86_64.
- Grasp the security implications of hardware-enforced 16-byte stack pointer alignment.

---

## 2. Interactive Stack Frame Lifecycle Diagram

Click through the interactive steps below to observe parameter passing, branch linking, prologue setup, local allocations, and epilogue teardown across memory and CPU registers:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/03-stack-frame.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. Architecture Stack Frame Anatomy

=== "AArch64 (AAPCS64 - Default Target)"
    On AArch64, function calls store return addresses directly into the Link Register (`X30 / LR`) rather than pushing them to the stack:

    ```
    [High Memory]
    ─────────────────────────────────────────────────────────────
      [sp, #0x50]  │ Caller Frame / Stack Arguments (args 9+)
    ─────────────────────────────────────────────────────────────
      [sp, #0x20]  │ Local Buffer [char buf[32]] (Higher offset)
    ─────────────────────────────────────────────────────────────
      [sp, #0x18]  │ Local Variable (uint64_t val)
    ─────────────────────────────────────────────────────────────
      [sp, #0x08]  │ Saved LR (X30)  Return address backup
    ─────────────────────────────────────────────────────────────
      [sp, #0x00]  │ Saved FP (X29)  Frame Pointer Record
    ─────────────────────────────────────────────────────────────
    [Low Memory (Current SP position)]
    ```

    #### AArch64 Prologue & Epilogue
    ```assembly
    // [Prologue] Decrement SP by 64 bytes and save FP/LR pair at the bottom of the frame
    stp    x29, x30, [sp, #-64]!
    mov    x29, sp

    // [Epilogue] Restore FP and LR, deallocate 64 bytes, and branch to LR
    ldp    x29, x30, [sp], #64
    ret
    ```

    > [!IMPORTANT]
    > **AArch64 Stack Buffer Overflow Characteristics**:
    > In AArch64 AAPCS64, the frame record (`X29`/`X30`) is stored at the base of the allocated stack frame (`[sp]`), while local variables are located at higher offsets (`[sp + 0x20]`, etc.). Therefore, an upward buffer overflow within the current function's local array overflows toward **higher addresses** (into adjacent variables or the caller's stack frame), rather than the current function's saved FP/LR.

=== "x86_64 (System V AMD64 ABI - Comparative Target)"
    On x86_64, the hardware `call` instruction pushes the Return Address directly onto the stack:

    ```
    [High Memory]
    ─────────────────────────────────────────────────────────────
      +0x18(%rbp)  │ Caller Stack Frame (Stack Arguments 7+)
    ─────────────────────────────────────────────────────────────
      +0x08(%rbp)  │ Return Address (RET)  Hardware pushed by CALL
    ─────────────────────────────────────────────────────────────
       0x00(%rbp)  │ Saved Frame Pointer (SFP)  Previous RBP backup
    ─────────────────────────────────────────────────────────────
      -0x20(%rbp)  │ Local Buffer [char buf[32]]  Negative offset
    ─────────────────────────────────────────────────────────────
      -0x28(%rbp)  │ Local Variable (uint64_t val)  %rsp location
    ─────────────────────────────────────────────────────────────
    [Low Memory (Current RSP position)]
    ```

    #### x86_64 Prologue & Epilogue
    ```nasm
    // [Prologue] Save RBP, establish frame anchor, subtract stack pointer
    push   %rbp
    mov    %rsp, %rbp
    sub    $0x40, %rsp

    // [Epilogue] Release local space, restore RBP, and pop return address into RIP
    leave
    ret
    ```

---

## 4. Comprehensive Calling Convention (ABI) Comparison

| Feature | AArch64 (AAPCS64 - Default) | x86_64 (System V AMD64 ABI) |
| :--- | :--- | :--- |
| **Integer / Pointer Argument Registers** | `X0` – `X7` (Up to 8 arguments) | `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9` (Up to 6) |
| **Return Value Registers** | `X0` (Secondary: `X1`) | `RAX` (Secondary: `RDX`) |
| **Return Address Storage** | Link Register `LR (X30)` (`bl`) | Pushed directly to stack (`call`) |
| **Frame Pointer Register** | `X29 (FP)` | `RBP` |
| **Stack Pointer Alignment** | Hardware-enforced 16-byte alignment on SP dereference | 16-byte alignment required before `call` |
| **Temporary Scratch Registers** | `X9` – `X15` (Caller-saved) | `R10`, `R11` (Caller-saved) |

---

## 5. Lab Source Code & Assembly Inspection

- **Lab Source Code**: [`stack_frame_demo.c`](../../assets/labs/principles/03-stack-frame/stack_frame_demo.c) (Local Asset) | [GitHub Source Code Repository :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/03-stack-frame/stack_frame_demo.c)
- **Dedicated Makefile**: [`Makefile`](../../assets/labs/principles/03-stack-frame/Makefile)

### 5.1 Running the Stack Frame Analysis

=== "AArch64 (Default Target)"
    ```bash
    cd labs/principles/03-stack-frame
    make run
    ```

    ```
    === Running stack_frame_demo on aarch64 ===
    qemu-aarch64 -L /usr/aarch64-linux-gnu ./stack_frame_demo
    [+] Calling target_function from main() (main=0x7e183c860a08)...

    ============================================================
     Stack Frame Anatomical Analysis (target_function)
    ============================================================
    [ABI] Architecture: ARM64 (AAPCS64)
          Register Args: a1(X0)=0x11, a2(X1)=0x22, a3(X2)=0x33
                         a4(X3)=0x44, a5(X4)=0x55, a6(X5)=0x66
                         a7(X6)=0x77, a8(X7)=0x88
    ------------------------------------------------------------
    [Stack Frame Memory Layout from Low to High Addresses]
      [Low Addr]  local_buffer[0]      : 0x4000007fed80
                  local_buffer[31]     : 0x4000007fed9f
                  local_var            : 0x4000007fed78 (val=0xdeadbeefcafebabe)
                  Saved Frame Pointer  : 0x4000007fed20 (points to caller's frame)
      [High Addr] Return Address (RET) : 0x4000007fed28 (caller: 0x7e183c860a48)
    ------------------------------------------------------------
    [Buffer Overflow Math]
      * Distance from local_buffer[0] to Saved FP (X29)  : -96 bytes
      * Distance from local_buffer[0] to Saved LR (X30)  : -88 bytes
      => In AAPCS64, Saved FP/LR sit at [sp] (lower address than local variables).
      => An upward stack buffer overflow corrupts adjacent variables or CALLER's frame!
    ============================================================
    ```

=== "x86_64 (Comparative Target)"
    ```bash
    cd labs/principles/03-stack-frame
    make ARCH=x86_64 run
    ```

    ```
    === Running stack_frame_demo on x86_64 ===
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

### 5.2 Disassembly Verification

```bash
make disasm
```

- AArch64: Inspect `stp x29, x30, [sp, #-N]!` prologue and `ldp x29, x30, [sp], #N; ret` epilogue.
- x86_64: Inspect `push %rbp`, `leave`, and `ret`.

---

## 6. Summary & Next Chapter

- On x86_64, `call` pushes the return address right above the local frame, making upward stack overflows directly smash RET.
- On AArch64, `bl` uses the Link Register and stores the frame record (`X29`/`X30`) at the bottom of the allocated stack frame, steering memory corruption attacks toward adjacent function pointers or caller frames.
- In the next chapter, we investigate the byte-level construction of injected code: **[04. Shellcode Engineering and Assembly Generation](04-shellcode-engineering.md)**.
