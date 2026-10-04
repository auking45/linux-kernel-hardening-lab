# 03. 스택 프레임 구조와 함수 호출 규약 (Stack Frame & ABI)

함수가 호출될 때마다 CPU와 메모리 스택 위에서 일어나는 **스택 프레임(Stack Frame)의 생성과 소멸**, 그리고 x86_64 및 ARM64 아키텍처의 **함수 호출 규약(Calling Convention / ABI)**을 바이트 단위로 해부함.

---

## 1. 학습 목표 및 개요

- 스택 메모리가 왜 높은 주소에서 낮은 주소로 역방향 성장(Downward Growing)하는지 물리적 배경을 이해함.
- `call` 명령어가 반환 주소(Return Address)를 스택에 PUSH하는 하드웨어 메커니즘을 분석함.
- 함수 프롤로그(Prologue)와 에필로그(Epilogue)에서 일어나는 레지스터 조작(`RBP`, `RSP`, `RIP`)을 규명함.
- System V AMD64 ABI와 ARM64 AAPCS 호출 규약의 레지스터 인자 전달 규칙을 비교함.
- 로컬 버퍼 시작 지점에서 반환 주소(RET)까지의 바이트 오프셋 계산 공식을 도출함.

---

## 2. 인터랙티브 스택 프레임 생성 및 소멸 다이어그램

아래 스텝 버튼을 클릭하여 인자 전달부터 `call`, 프롤로그, 로컬 변수 할당, 에필로그까지 스택 메모리와 CPU 레지스터의 동적 변화를 관찰 가능함:

<div style="width: 100%; height: 600px; margin: 24px 0; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden;">
  <iframe src="../../assets/diagrams/principles/03-stack-frame.html" style="width: 100%; height: 100%; border: none;"></iframe>
</div>

---

## 3. 스택 프레임의 바이트 레벨 해부학

함수가 실행되는 동안 스택 메모리는 다음과 같은 계층 구조를 형성함:

```
[상위 주소: High Memory]
─────────────────────────────────────────────────────────────
  +0x18(%rbp)  │ Caller Stack Frame (7번째 이후 초과 인자들)
─────────────────────────────────────────────────────────────
  +0x08(%rbp)  │ Return Address (RET)  CALL 명령어가 자동 PUSH
─────────────────────────────────────────────────────────────
   0x00(%rbp)  │ Saved Frame Pointer (SFP)  이전 함수의 RBP 백업
─────────────────────────────────────────────────────────────
  -0x20(%rbp)  │ Local Buffer [char buf[32]]  지역 배열 변수
─────────────────────────────────────────────────────────────
  -0x28(%rbp)  │ Local Variable (uint64_t val)  %rsp 현재 위치
─────────────────────────────────────────────────────────────
[하위 주소: Low Memory (RSP가 아래로 확장)]
```

### 3.1 함수 프롤로그 (Prologue) 어셈블리

함수가 진입할 때 새 프레임을 구축하는 2개 명령어:

```nasm
push   %rbp         ; 이전 함수의 RBP를 스택에 백업 (SFP, 8바이트 소비)
mov    %rsp, %rbp   ; 현재 스택 최상단(RSP)을 새 프레임의 기준점(RBP)으로 설정
sub    $0x30, %rsp  ; 지역 변수를 위한 48바이트 공간 확보 (RSP 감소)
```

### 3.2 함수 에필로그 (Epilogue) 어셈블리

함수가 작업을 마치고 호출자로 안전하게 복귀하는 명령어:

```nasm
leave               ; mov %rbp, %rsp && pop %rbp (지역 변수 해제 및 이전 RBP 복원)
ret                 ; pop %rip (스택 최상단에 있는 Return Address를 꺼내 RIP에 적재)
```

---

## 4. 아키텍처별 호출 규약(ABI) 비교: x86_64 vs ARM64

| 평가 항목 | x86_64 (System V AMD64 ABI) | ARM64 (AAPCS64) |
| :--- | :--- | :--- |
| **정수/포인터 인자 레지스터** | `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9` (최대 6개) | `X0` ~ `X7` (최대 8개) |
| **함수 반환값 레지스터** | `RAX` (보조: `RDX`) | `X0` (보조: `X1`) |
| **복귀 주소 저장 방식** | 스택 메모리에 하드웨어 자동 PUSH (`call`) | 링크 레지스터 `LR (X30)`에 저장 (`bl`) |
| **프레임 포인터 레지스터** | `RBP` | `X29 (FP)` |
| **스택 포인터 정렬** | 함수 호출 시 16바이트 정렬 필수 | 16바이트 정렬 하드웨어 강제 |

---

## 5. 실습 소스 코드 및 어셈블리 오프셋 계산

- **실습 소스 코드**: [`stack_frame_demo.c`](../../assets/labs/principles/03-stack-frame/stack_frame_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/principles/03-stack-frame/stack_frame_demo.c)
- **전용 Makefile**: [`Makefile`](../../assets/labs/principles/03-stack-frame/Makefile)

### 5.1 오프셋 계산 실습 실행

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

### 5.2 함수 어셈블리 역어셈블 확인

```bash
make disasm
```

- 실제 `objdump` 출력에서 `push %rbp`, `mov %rsp, %rbp`, `sub $0x40, %rsp` 프롤로그와 `leave`, `ret` 에필로그 구조를 확인 가능함.

---

## 6. 요약 및 다음 강의

- 스택 프레임은 지역 변수보다 높은 주소에 SFP와 Return Address를 보관하므로, 버퍼 경계 검사가 누락되면 Return Address가 덮어씌워지는 구조적 약점을 안고 있음.
- 다음 강의에서는 탈취한 제어 흐름에 올려 실행시키는 기계어 조각인 **[04. 쉘코드 엔지니어링과 어셈블리 기계어 제작](04-shellcode-engineering.md)**을 학습함.
