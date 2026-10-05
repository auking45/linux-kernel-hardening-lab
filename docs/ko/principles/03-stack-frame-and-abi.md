# 03. 스택 프레임 구조와 함수 호출 규약 (Stack Frame & ABI)

함수가 호출될 때마다 CPU와 메모리 스택 위에서 일어나는 **스택 프레임(Stack Frame)의 생성과 소멸**, 그리고 **AArch64(AAPCS64)**와 **x86_64(System V AMD64 ABI)**의 함수 호출 규약을 바이트 단위로 심층 해부함.

---

## 1. 학습 목표 및 개요

- 스택 메모리가 높은 주소에서 낮은 주소로 역방향 성장(Downward Growing)하는 물리적 구조를 규명함.
- AArch64의 링크 레지스터(`X30 / LR`)와 x86_64의 하드웨어 스택 PUSH(`call`) 간 복귀 메커니즘 차이를 분석함.
- AArch64 AAPCS64 프롤로그(`stp x29, x30, [sp, #-N]!`) 및 에필로그(`ldp x29, x30, [sp], #N; ret`) 메커니즘을 학습함.
- AArch64와 x86_64의 스택 레이아웃 차이(프레임 레코드 위치와 로컬 변수 오프셋)를 분석함.
- 16바이트 스택 정렬(16-byte Alignment) 하드웨어 강제 규칙의 보안적 의의를 이해함.

---

## 2. 인터랙티브 스택 프레임 생성 및 소멸 다이어그램

아래 스텝 버튼을 클릭하여 인자 전달부터 분기, 프롤로그, 로컬 변수 할당, 에필로그까지 스택 메모리와 CPU 레지스터의 동적 변화를 관찰 가능함:

<div style="width: 100%; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/03-stack-frame.html" style="width: 100%; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { const c = this.contentWindow.document.getElementById('diagramCanvas'); if(c) this.style.height = Math.ceil(c.getBoundingClientRect().height) + 'px'; } catch(e){}"></iframe>
</div>

---

## 3. 아키텍처별 스택 프레임 구조 심층 비교

=== "AArch64 (AAPCS64 - 기본 타깃)"
    AArch64는 함수 호출 시 복귀 주소를 스택에 기록하지 않고 링크 레지스터(`X30 / LR`)에 직접 저장함:

    ```
    [상위 주소: High Memory]
    ─────────────────────────────────────────────────────────────
      [sp, #0x50]  │ Caller Frame / 초과 인자 (9번째 이후)
    ─────────────────────────────────────────────────────────────
      [sp, #0x20]  │ Local Buffer [char buf[32]] (상위 오프셋에 위치)
    ─────────────────────────────────────────────────────────────
      [sp, #0x18]  │ Local Variable (uint64_t val)
    ─────────────────────────────────────────────────────────────
      [sp, #0x08]  │ Saved LR (X30)  직전 호출 복귀 주소 백업
    ─────────────────────────────────────────────────────────────
      [sp, #0x00]  │ Saved FP (X29)  Frame Pointer Record [x29]
    ─────────────────────────────────────────────────────────────
    [하위 주소: Low Memory (SP 현재 위치)]
    ```

    #### AArch64 프롤로그 & 에필로그
    ```assembly
    // [프롤로그] SP를 64바이트 하향 이동하고 새 프레임 기저에 FP(x29)와 LR(x30)을 동시 백업
    stp    x29, x30, [sp, #-64]!
    mov    x29, sp

    // [에필로그] FP와 LR을 원복하고 SP를 64바이트 환원한 뒤 LR 주소로 분기
    ldp    x29, x30, [sp], #64
    ret
    ```

    > [!IMPORTANT]
    > **AArch64 스택 버퍼 오버플로우의 구조적 특성**:
    > AArch64에서는 프레임 레코드(`X29`/`X30`)가 할당된 스택 프레임의 최하단(`[sp]`)에 배치되고 로컬 변수들이 그 상위 오프셋(`[sp + 0x20]` 등)에 배치됨. 따라서 현재 함수의 지역 배열에서 상위 주소로 오버플로우가 발생하면 현재 함수의 FP/LR이 아니라 **인접 지역 변수나 호출자(Caller)의 스택 프레임**을 덮어쓰게 됨.

=== "x86_64 (System V AMD64 ABI - 비교 타깃)"
    x86_64는 `call` 명령어가 스택 메모리에 자동으로 Return Address를 PUSH함:

    ```
    [상위 주소: High Memory]
    ─────────────────────────────────────────────────────────────
      +0x18(%rbp)  │ Caller Stack Frame (7번째 이후 초과 인자들)
    ─────────────────────────────────────────────────────────────
      +0x08(%rbp)  │ Return Address (RET)  CALL 명령어가 자동 PUSH
    ─────────────────────────────────────────────────────────────
       0x00(%rbp)  │ Saved Frame Pointer (SFP)  이전 함수의 RBP 백업
    ─────────────────────────────────────────────────────────────
      -0x20(%rbp)  │ Local Buffer [char buf[32]]  음수 오프셋에 위치
    ─────────────────────────────────────────────────────────────
      -0x28(%rbp)  │ Local Variable (uint64_t val)  %rsp 현재 위치
    ─────────────────────────────────────────────────────────────
    [하위 주소: Low Memory (RSP 현재 위치)]
    ```

    #### x86_64 프롤로그 & 에필로그
    ```nasm
    // [프롤로그] RBP 백업 후 현재 RSP를 새 기준점으로 지정하고 스택 공간 차감
    push   %rbp
    mov    %rsp, %rbp
    sub    $0x40, %rsp

    // [에필로그] 로컬 변수 해제 및 이전 RBP 복원 후 RET 주소 POP
    leave
    ret
    ```

---

## 4. 아키텍처별 호출 규약(ABI) 종합 비교

| 평가 항목 | AArch64 (AAPCS64 - 기본) | x86_64 (System V AMD64 ABI) |
| :--- | :--- | :--- |
| **정수/포인터 인자 레지스터** | `X0` ~ `X7` (최대 8개) | `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9` (최대 6개) |
| **함수 반환값 레지스터** | `X0` (보조: `X1`) | `RAX` (보조: `RDX`) |
| **복귀 주소 저장 방식** | 링크 레지스터 `LR (X30)`에 저장 (`bl`) | 스택 메모리에 하드웨어 자동 PUSH (`call`) |
| **프레임 포인터 레지스터** | `X29 (FP)` | `RBP` |
| **스택 포인터 정렬** | SP 역참조 시 16바이트 정렬 하드웨어 강제 | 함수 호출 시 16바이트 정렬 ABI 요구 |
| **임시 계산 레지스터** | `X9` ~ `X15` (Caller-saved) | `R10`, `R11` (Caller-saved) |

---

## 5. 실습 소스 코드 및 어셈블리 오프셋 계산

- **실습 소스 코드**: [`stack_frame_demo.c`](../../assets/labs/principles/03-stack-frame/stack_frame_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/03-stack-frame/stack_frame_demo.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/03-stack-frame/Makefile)

### 5.1 오프셋 계산 실습 실행

=== "AArch64 (기본 타깃)"
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

=== "x86_64 (비교 타깃)"
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

### 5.2 함수 역어셈블 확인

```bash
make disasm
```

- AArch64: `stp x29, x30, [sp, #-N]!` 프롤로그 및 `ldp x29, x30, [sp], #N; ret` 구조를 확인 가능함.
- x86_64: `push %rbp`, `leave`, `ret` 구조를 확인 가능함.

---

## 6. 요약 및 다음 강의

- x86_64는 `call` 명령어가 Return Address를 스택에 밀어 넣고 로컬 변수가 그 아래에 배치되어 단일 프레임 내 상향 오버플로우로 RET 변조가 직결됨.
- 반면 AArch64는 `bl` 분기 시 LR 레지스터를 활용하고 프레임 레코드(`X29`/`X30`)를 스택 프레임 최하단에 배치하므로 제어 흐름 공격 시 인접 함수 포인터나 호출자 프레임 변조가 타깃이 됨.
- 다음 강의에서는 탈취한 제어 흐름에 올려 실행시키는 기계어 조각인 **[04. 쉘코드 엔지니어링과 어셈블리 기계어 제작](04-shellcode-engineering.md)**을 학습함.
