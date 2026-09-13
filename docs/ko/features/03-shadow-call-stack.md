# CONFIG_SHADOW_CALL_STACK: ARM64 그림자 호출 스택 및 ROP 방어 메커니즘

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: 스택 복귀 주소 변조 및 ROP 공격
- **스택 기반 제어 흐름 가로채기 (Return Address Hijacking)**:
  - C 언어의 전통적인 함수 호출 규약(Calling Convention)은 로컬 버퍼 변수, 프레임 포인터, 그리고 함수 복귀 주소(`Return Address`)를 동일한 호출 스택(Call Stack, `SP`)에 혼합하여 적재함.
  - 공격자가 스택 버퍼 오버플로우를 발생시킬 경우, 인접한 복귀 주소를 임의의 악성 코드 주소나 기존 커널 내 명령어 조각들(ROP Gadgets)로 덮어쓸 수 있음.
- **ROP(Return-Oriented Programming) 체인의 위험성**:
  - `W^X`(Write XOR Execute) 또는 `CONFIG_STRICT_KERNEL_RWX`로 인해 스택에 직접 쉘코드를 주입하여 실행하는 것은 불가능함.
  - 그러나 ROP 공격은 커널 텍스트 영역에 이미 존재하는 유효한 명령어 조각들(`gadget`) 끝의 `ret` 명령어를 연쇄적으로 실행(Chaining)하여, 공격자가 원하는 임의의 제어 흐름(특권 상승 `commit_creds()`, 보호 기능 비활성화 등)을 달성함.
- **기존 방어 기법(Stack Canary)의 한계**:
  - `CONFIG_STACKPROTECTOR`는 지역 변수와 복귀 주소 사이에 난수 카나리를 삽입하지만, 정보 누출(Infoleak) 취약점을 통해 카나리가 유출되거나, 비선형 배열 인덱스 쓰기(`buf[arbitrary_idx] = target`)로 카나리를 건너뛰고 복귀 주소만 직접 조작할 경우 방어가 무력화됨.

### 1.2 SHADOW_CALL_STACK (SCS)의 핵심 방어 철학
- **역방향 제어 흐름 무결성 (Backward-edge Control Flow Integrity)**:
  - 함수 호출 복귀 지점(`ret`)을 오직 안전하게 보관된 원래의 복귀 주소로만 한정하는 하드웨어/컴파일러 협력 보안 기술임.
  - **이중 스택(Dual-Stack) 분리**:
    1. **일반 호출 스택 (Regular Stack: `SP`)**: 지역 변수, 레지스터 스필(Spill), 프레임 포인터 등 데이터만 저장.
    2. **그림자 호출 스택 (Shadow Call Stack: `x18`)**: 오직 순수한 함수 복귀 주소(`x30`/`LR`)만을 독립된 메모리 공간에 격리 적재.
  - 일반 스택이 공격자의 버퍼 오버플로우로 완전히 파괴되더라도, 함수 에필로그는 일반 스택에 저장된 값을 철저히 무시하고 `x18` 레지스터가 가리키는 그림자 스택에서만 복귀 주소를 복원함. 따라서 복귀 주소 변조 기반 ROP 공격이 100% 원천 차단됨.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 ARM64 `x18` 플랫폼 레지스터 독점 활용
- ARM64(AArch64) 표준 ABI는 31개의 64비트 범용 레지스터 중 `x18`을 **플랫폼 예약 레지스터(Platform Register)** 로 지정함.
- 리눅스 커널 빌드 시 컴파일러 옵션 `-ffixed-x18`를 적용하여, GCC/Clang이 `x18` 레지스터를 일반 지역 변수나 임시 계산 용도로 절대 할당하지 못하도록 고정함.
- 커널 태스크(스레드)가 생성될 때마다 커널은 태스크별로 독립된 그림자 스택 페이지(`SCS_SIZE`, 일반적으로 4KB~16KB)를 할당하고, 해당 태스크가 CPU에서 실행될 때 `x18` 레지스터에 그림자 스택의 현재 최상단 주소를 바인딩함.

### 2.2 함수 프롤로그 및 에필로그 어셈블리 변환

=== "SCS 활성화 (Hardened: 이중 스택 격리)"

    ```armasm
    ; [함수 프롤로그 (Prologue)]
    str   x30, [x18], #8          ; 1. 링크 레지스터(x30/LR)를 섀도 스택(x18)에 푸시 후 x18을 8바이트 후증가
    stp   x29, x30, [sp, #-32]!   ; 2. 일반 스택(SP)에 FP, LR 저장 (디버거 스택 트레이스용)
    mov   x29, sp                 ; 3. 현재 스택 프레임 기준 설정

    ; [함수 본문 실행 중: 스택 버퍼 오버플로우로 [sp, #8]이 악성 주소로 변조됨]

    ; [함수 에필로그 (Epilogue)]
    ldr   x30, [x18, #-8]!        ; 1. [핵심 방어] x18(섀도 스택)에서 오염되지 않은 순수 LR 인출!
    ldp   x29, xzr, [sp], #32     ; 2. 일반 스택의 오염된 LR은 버리고(xzr) 프레임 포인터만 복원
    ret                           ; 3. 순수 LR(x30)로 안전하게 복귀 -> ROP 분기 무력화!
    ```

=== "SCS 비활성화 (Base: 단일 스택 취약 구조)"

    ```armasm
    ; [함수 프롤로그 (Prologue)]
    stp   x29, x30, [sp, #-32]!   ; 일반 스택(SP)에만 FP, LR 적재
    mov   x29, sp

    ; [함수 본문 실행 중: 스택 버퍼 오버플로우로 [sp, #8]이 악성 주소로 변조됨]

    ; [함수 에필로그 (Epilogue)]
    ldp   x29, x30, [sp], #32     ; [취약점] 일반 스택의 변조된 LR을 그대로 x30 레지스터로 로드!
    ret                           ; 변조된 LR 주소(scs_hijacked_target)로 점프 -> 커널 제어권 탈취!
    ```

### 2.3 듀얼 스택 아키텍처 인터랙티브 다이어그램

아래 인터랙티브 다이어그램을 통해 ARM64 하드웨어 레지스터 `x18`과 일반 스택 `SP` 간의 상호작용 및 ROP 방어 시퀀스를 시각적으로 체험할 수 있음:

<iframe src="../../../assets/diagrams/shadow-call-stack/architecture.html" width="100%" height="700px" style="border:none; border-radius:12px; margin: 16px 0; background: #0f172a;" title="Shadow Call Stack Architecture Map"></iframe>

---

## 3. 활성화 방법 및 Kconfig 설정 (Configuration)

### 3.1 컴파일러 및 커널 요구사항
- **컴파일러**: Clang >= 7.0 또는 GCC >= 12.0.0 (옵션 `-fsanitize=shadow-call-stack -ffixed-x18` 지원 필수).
- **아키텍처**: ARM64 (`ARCH_SUPPORTS_SHADOW_CALL_STACK=y`).
- **추적기 제약**: `DYNAMIC_FTRACE_WITH_ARGS` 지원 또는 `!FUNCTION_GRAPH_TRACER` 조건 만족 필요.

### 3.2 Kconfig 설정 프래그먼트

```kconfig
# /configs/features/shadow-call-stack.config
CONFIG_SHADOW_CALL_STACK=y
```

취약 베이스라인 비교 설정:
```kconfig
# /configs/features/shadow-call-stack-disabled.config
# CONFIG_SHADOW_CALL_STACK is not set
```

---

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

본 랩에서는 비특권 일반 사용자(`lab`, UID 1000)가 `/proc/vuln_scs` 인터페이스를 대상으로 128바이트 크기의 스택 오버플로우 페이로드를 주입하여, 함수의 복귀 주소(`x30`/`LR`)를 `scs_hijacked_target()` 주소로 덮어쓰는 실전 Exploit PoC를 구동함.

1. **[Test 1/2] 실전 커널 SCS Exploit PoC (`/bin/exploit_shadow_call_stack`)**:
   - 취약 드라이버 `vuln_scs.c` 내의 `vulnerable_scs_worker()` 함수는 `__no_stack_protector` 속성을 부여하여 Stack Protector 간섭을 배제하고 순수 복귀 주소 탈취 효과만을 격리 검증함.
   - **Base 커널**: 일반 스택의 `LR`이 `scs_hijacked_target`으로 덮어써져 함수 복귀 시 `[!] CONTROL FLOW HIJACKED` 패닉 발생.
   - **Hardened 커널**: 일반 스택이 오염되어도 `x18` 레지스터를 통해 순수 복귀 주소가 복원되어 정상 호출자에게 복귀 (`[+] DEFENSE ACTIVE: Returned safely to vuln_scs_write!`).
2. **[Test 2/2] 커널 내장 LKDTM 표준 테스트 (`CFI_BACKWARD`)**:
   - 커널 충돌 주입 프레임워크를 통해 강제 복귀 주소 리디렉션 시도 검증.

---

### 4.1 원클릭 검증 명령어 및 실측 결과 로그

=== "ARM64: Hardened (보호 활성화: x18 복귀 무결성 - 권장)"

    ```bash
    # ARM64 Hardened 커널 실행 및 SCS 테스트 구동
    ./scripts/run_lab.sh --arch arm64 --feature shadow-call-stack --test test_shadow_call_stack
    ```

    **런타임 실측 출력 로그 (SCS 안전 복구 및 LKDTM 방어 성공)**:
    ```text
    =========================================================
      [Test 1/2] Real-World Kernel Shadow Call Stack Exploit PoC
      Target:       /proc/vuln_scs (Return Address / LR Hijack)
      Exploit:      /bin/exploit_shadow_call_stack
      Runner:       lab (UID 1000, non-privileged)
    =========================================================
    [*] Launching stack overwrite payload against 32-byte worker target...
    [*] If CONFIG_SHADOW_CALL_STACK is active, pristine LR restored from x18!

    =========================================================
      Linux Kernel Hardening Lab - Shadow Call Stack PoC
      Target Architecture: aarch64 (ARM64)
      Current User: UID = 1000 (non-root)
    =========================================================
    [*] Target hijack function address: 0xffff80008032ac34
    [*] Kernel SCS status reported:     ENABLED
    [*] Buffer size: 32 bytes
    [*] Prepared overflow payload: 64 bytes
    [*] Injecting payload into /proc/vuln_scs...
    [*] [Hardened Kernel Expected]: Epilogue restores pristine LR from x18 -> Safe return.
    [*] [Vulnerable Kernel Expected]: Epilogue restores corrupted LR from stack -> Hijacked control flow!

    [+] write() returned successfully (64 bytes written).

    [*] Write completed without process crash!
    [+] DEFENSE ACTIVE: Function returned safely to caller.
    [+] Shadow Call Stack protected the Link Register from being overwritten.

    [    1.387005] [vuln_scs] Interface /proc/vuln_scs created (target: 0xffff80008032ac34, SCS=1)
    [    2.510878] [vuln_scs] Write received: 64 bytes from PID 47 (exploit_shadow_)
    [    2.511152] [vuln_scs] Calling vulnerable_scs_worker(target=0xffff80008032ac34)...
    [    2.511226] [vuln_scs] vulnerable_scs_worker: saved stack LR = ffff80008032ae4c, target = ffff80008032ac34
    [    2.511259] [vuln_scs] Overwriting saved stack LR with target address...
    [    2.511289] [vuln_scs] Epilogue executing: if SCS is active, x18 restores true LR...
    [    2.511332] [vuln_scs] [+] DEFENSE ACTIVE: Returned safely to vuln_scs_write!
    [    2.511354] [vuln_scs] [+] Shadow Call Stack (x18) thwarted return address hijacking!

    =========================================================
      [Test 2/2] Triggering LKDTM CFI_BACKWARD Test
      Kernel Architecture: aarch64
      Kernel Release:      6.12.109
    =========================================================
    [*] Triggering checked stack return address redirection via LKDTM...

    [    1.386523] lkdtm: No crash points registered, enable through debugfs
    [    2.648968] lkdtm: Performing direct entry CFI_BACKWARD
    [    2.650366] lkdtm: Attempting unchecked stack return address redirection ...
    [    2.650561] lkdtm: ok: redirected stack return address.
    [    2.650599] lkdtm: Attempting checked stack return address redirection ...
    [    2.650701] lkdtm: Eek: return address mismatch! ffff80008032a338 != ffff80008032a278
    [    2.650852] lkdtm: ok: control flow unchanged.
    ```
    > **분석:** 공격자가 스택에 복귀 주소 덮어쓰기 페이로드를 전달하여 스택 상의 `LR`을 `0xffff...`로 변조했음에도 불구하고, 에필로그에서 `ldr x30, [x18, #-8]!`이 수행되어 원본 호출자의 진짜 주소(`ffff80008032ae4c`)가 안전하게 복원됨. 그 결과 제어 흐름 탈취가 100% 무력화되고 유저 프로세스는 정상 복귀함. LKDTM 역시 `Eek: return address mismatch!`를 감지하고 `ok: control flow unchanged.`를 보고함.

=== "ARM64: Base (보호 비활성화: ROP 분기 탈취 성공)"

    ```bash
    # 보호 옵션이 비활성화된 ARM64 커널 실행
    ./scripts/run_lab.sh --arch arm64 --feature shadow-call-stack-disabled --test test_shadow_call_stack
    ```

    **런타임 실측 출력 로그 (스택 LR 변조로 인한 제어권 피탈)**:
    ```text
    =========================================================
      [Test 1/2] Real-World Kernel Shadow Call Stack Exploit PoC
      Target:       /proc/vuln_scs (Return Address / LR Hijack)
      Exploit:      /bin/exploit_shadow_call_stack
      Runner:       lab (UID 1000, non-privileged)
    =========================================================
    [*] Target hijack function address: 0xffff800080312304
    [*] Kernel SCS status reported:     DISABLED
    [*] Buffer size: 32 bytes
    [*] Prepared overflow payload: 64 bytes
    [*] Injecting payload into /proc/vuln_scs...
    [*] [Hardened Kernel Expected]: Epilogue restores pristine LR from x18 -> Safe return.
    [*] [Vulnerable Kernel Expected]: Epilogue restores corrupted LR from stack -> Hijacked control flow!

    [    1.250084] [vuln_scs] [!] =========================================================
    [    1.252367] [vuln_scs] [!] CONTROL FLOW HIJACKED: Successfully executed scs_hijacked_target()!
    [    1.253111] [vuln_scs] [!] Overwritten stack return address (LR) was branched to by 'ret'.
    [    1.255882] [vuln_scs] [!] Shadow Call Stack is NOT active on this kernel (Vulnerable Baseline).
    [    1.256355] [vuln_scs] [!] =========================================================
    [    1.257173] Kernel panic - not syncing: vuln_scs: Control flow hijacking confirmed via smashed stack return address
    [    1.258823] CPU: 0 UID: 1000 PID: 47 Comm: exploit_shadow_ Not tainted 6.12.109 #2
    [    1.260114] Call trace:
    [    1.260607]  dump_backtrace+0x90/0xe8
    [    1.261638]  show_stack+0x18/0x24
    [    1.261950]  dump_stack_lvl+0x34/0x8c
    [    1.262484]  dump_stack+0x18/0x24
    [    1.263725]  panic+0x388/0x39c
    [    1.264051]  vulnerable_scs_worker+0x0/0x54
    [    1.264289]  scs_hijacked_target+0x0/0x58
    ```
    > **분석:** SCS가 비활성화된 커널에서는 일반 스택의 변조된 `x30`이 그대로 로드되어, 함수가 종료되는 즉시 공격자가 유도한 `scs_hijacked_target()` 함수로 분기함. 공격자가 복귀 주소를 완전히 장악하여 ROP 실행 체인을 형성할 수 있음을 증명함.

---

### 4.2 아키텍처별 ROP 방어 메커니즘 심층 대조 (ARM64 vs x86_64)

| 항목 | ARM64 (AArch64) | x86_64 (AMD64) |
| :--- | :--- | :--- |
| **복귀 주소 처리 레지스터** | 전용 링크 레지스터 `x30` (`LR`) | 스택(`RSP`)에 직접 `RIP` 복귀 주소 푸시 |
| **분기 명령어** | `ret` (`br x30`과 동일한 의미) | `ret` (`pop rip`과 유사한 동작) |
| **소프트웨어 그림자 스택** | **완벽 지원** (플랫폼 예약 레지스터 `x18` 활용) | **미지원** (범용 레지스터 부족 및 레지스터 기아 현상) |
| **하드웨어 그림자 스택** | ARMv8.3-A PAC (Pointer Authentication) & BTI (Task 6-3) | **Intel CET Shadow Stack** (`ssp` 레지스터 기반, Task 6-2) |
| **주요 방어 철학** | 레지스터 기반 섀도 스택 포인터 초고속 참조 | 하드웨어 페이지 테이블 토큰 및 CPU MSR 직접 관리 |

---

## 5. 성능 및 오버헤드 분석 (Performance & Overhead)

- **CPU 연산 오버헤드**:
  - 함수 호출 및 복귀 시 추가되는 어셈블리 명령어는 `str x30, [x18], #8` (1사이클) 및 `ldr x30, [x18, #-8]!` (1사이클)에 불과함.
  - 리눅스 커널 벤치마크 기준 전체 CPU 연산 오버헤드는 **0.5% 미만**으로 측정되어 프로덕션 환경(Android 커널 기본 채택)에 최적화됨.
- **메모리 공간 오버헤드**:
  - 스레드당 기본 1개의 전용 vmalloc 페이지(4KB~16KB)가 그림자 스택 용도로 할당됨.
  - 가드 페이지(Guard Page)가 상하단에 배치되어 그림자 스택 자체의 오버플로우 침범을 하드웨어 MMU 수준에서 차단함.

---

## 6. 발표 대본 및 핵심 표현 (Presentation Script & Vocabulary)

### 6.1 프레젠테이션 발표 대본 (Korean & English)

```text
[1단계: Hook - ROP의 공포와 스택 카나리의 한계]
"스택 버퍼 오버플로우를 막기 위해 우리는 보통 '스택 카나리'를 떠올립니다.
 하지만 실제 고급 공격자들은 메모리 주소 유출(Infoleak)이나 비선형 메모리 쓰기로
 카나리를 건드리지 않고 복귀 주소만 정확히 골라내어 ROP 체인을 실행합니다.
 복귀 주소가 일반 데이터와 같은 스택에 섞여 있는 한, 이 위험은 근본적으로 사라지지 않습니다."

"When we think of buffer overflow protection, Stack Canaries usually come to mind first.
 However, advanced exploit writers bypass canaries effortlessly via infoleaks or non-linear writes,
 jumping straight into Return-Oriented Programming (ROP) chains.
 As long as return addresses reside on the same memory stack as local variables,
 the threat remains fundamentally unresolved."

[2단계: Diagram - 도미노와 비밀 금고의 비유]
"이 문제를 해결하는 ARM64의 혁신이 바로 'Shadow Call Stack'입니다.
 집 안에 현관 열쇠를 두면 도둑이 집을 부수었을 때 열쇠까지 빼앗길 수 있습니다.
 SCS는 열쇠(복귀 주소)를 집(일반 스택)에 두지 않고, x18 레지스터로만 열 수 있는
 '비밀 금고(그림자 스택)'에 따로 보관하는 원리입니다.
 일반 스택이 공격으로 완전히 무너져도, 문을 닫고 나갈 때는 비밀 금고의 진짜 열쇠만 사용합니다."

"This is precisely why ARM64 introduced the Shadow Call Stack.
 Storing your safe keys inside the living room means an intruder who breaks the door gets the keys too.
 SCS takes those return address keys and places them into an isolated safe pointed exclusively by register x18.
 Even if an attacker obliterates the normal stack frame with arbitrary bytes,
 the CPU only looks inside the x18 vault to return safely."

[3단계: Live Demo - 실제 커널 Exploit 실측 대조]
"실제 QEMU 환경에서 이를 입증했습니다.
 SCS가 꺼진 베이스라인 커널에서는 128바이트 오버플로우로 인해 scs_hijacked_target으로
 제어 흐름이 탈취되어 커널 패닉이 유발되었습니다.
 반면 CONFIG_SHADOW_CALL_STACK이 켜진 커널에서는, 동일한 128바이트 공격을 가해도
 에필로그가 x18에서 순수 복귀 주소를 즉시 복원하여 단 한 치의 오차도 없이 정상 복귀했습니다."

"We proved this live inside our QEMU environment.
 On the unhardened kernel, our 128-byte payload hijacked the Link Register directly into scs_hijacked_target.
 But once we enabled CONFIG_SHADOW_CALL_STACK, that identical attack was completely neutralized:
 the epilogue effortlessly retrieved the pristine LR from x18, allowing normal execution to proceed safely."
```

### 6.2 핵심 프레젠테이션 영어 표현 (Key Presentation Phrases)

| 한국어 표현 | 권장 영어 스피킹 표현 | 용례 및 발화 팁 |
| :--- | :--- | :--- |
| **"단일 신뢰 원천을 분리하다"** | _"decouple return addresses from mutable stack frames"_ | 이중 스택 구조의 근본적 당위성을 설명할 때 |
| **"역방향 제어 흐름 무결성"** | _"guarantees airtight backward-edge CFI"_ | 기능의 학술적/보안적 공식 명칭 강조 시 |
| **"오염된 스택을 철저히 무시하다"** | _"simply discards the corrupted stack value in favor of x18"_ | 에필로그의 복원 메커니즘을 시각적으로 묘사할 때 |
| **"ROP 가젯 체이닝을 원천 봉쇄하다"** | _"completely closes the door on ROP gadget chaining"_ | 공격자의 제어권 박탈 효과를 단정할 때 |
| **"하드웨어 레지스터 독점 예약"** | _"dedicates the architectural x18 platform register"_ | AArch64 하드웨어/ABI 연계의 특수성을 강조할 때 |
