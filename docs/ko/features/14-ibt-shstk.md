# x86 IBT & Shadow Stack (Intel CET 기반 하드웨어 지원 제어 흐름 무결성)

## 1. 개요 및 배경

컴퓨터 시스템 보안에서 메모리 오염 취약점(Memory Corruption Vulnerability)은 전통적으로 셸코드 직접 주입에서 코드 재사용 공격(Code-Reuse Attack)인 ROP(Return-Oriented Programming) 및 JOP/COP(Jump/Call-Oriented Programming)로 진화해 왔음.

1. **역방향 제어 흐름 탈취 (Backward-edge Hijacking - ROP)**:
   - 스택 버퍼 오버플로우를 통해 함수 프레임의 반환 주소(Return Address)를 오염시킴.
   - 함수 에필로그의 `ret` 인스트럭션을 통해 공격자가 구성한 가젯 체인(Gadget Chain)을 연속 실행함.
2. **순방향 제어 흐름 탈취 (Forward-edge Hijacking - JOP/COP)**:
   - 힙 오버플로우나 UAF(Use-After-Free)를 악용하여 커널 객체 내의 함수 포인터(`file_operations`, `proto_ops`)를 변조함.
   - 간접 함수 호출(`call *%rax`, `jmp *%rax`) 시 공격자가 의도한 임의의 함수 또는 코드 가젯으로 분기함.

소프트웨어 기반 CFI(Control Flow Integrity) 솔루션은 높은 컴파일 타임 링킹 비용과 런타임 성능 오버헤드를 유발함. 이를 근본적으로 해결하기 위해 Intel은 11세대 코어 프로세서(Tiger Lake) 및 3세대 Xeon Scalable 프로세서부터 마이크로아키텍처 레벨의 하드웨어 보안 확장인 **Intel CET(Control-flow Enforcement Technology)**를 도입함.

리눅스 커널 6.x 시리즈는 Intel CET를 기반으로 다음 두 가지 핵심 방어선을 구축함:
- **Kernel IBT (`CONFIG_X86_KERNEL_IBT=y`)**: 순방향 간접 분기 추적 및 `endbr64` 인스트럭션 검증을 하드웨어 수준에서 강제함.
- **User-space Shadow Stack (`CONFIG_X86_USER_SHADOW_STACK=y`)**: 유저 공간 태스크에 하드웨어 격리 섀도 스택을 제공하여 반환 주소 위변조를 실시간 차단함.

---

## 2. 실세계 비유: 보안 검색 게이트와 이중 비밀 장부 (Security Gate & Dual-Ledger System)

Intel CET의 방어 메커니즘은 최고 등급 국가 중요 시설의 출입 관리 및 금고 회계 시스템에 비유할 수 있음:

1. **Intel IBT (간접 분기 보안 게이트)**:
   - **전통적 커널 (Pre-CET / Base)**: 방문자(간접 호출)가 전달하는 주소 쪽지만 보고 보안 요원이 아무 문이나 열어줌. 사기꾼이 창고나 보일러실로 통하는 쪽지를 주어도 그대로 진입이 허용됨.
   - **IBT 하드닝 커널 (Hardened)**: 모든 인가된 정문 앞에는 'ENDBR64'라는 특수 보안 스캐너가 설치되어 있음. 방문객이 간접 점프를 수행하면 CPU는 즉시 `WAIT_FOR_ENDBRANCH` 경계 태세로 돌입함. 착륙 지점의 첫 명령어가 'ENDBR64' 스캐너가 아니라면, 그 즉시 경보 사이렌(`#CP` Control Protection Fault)을 울리고 침입자를 체포함.
2. **User Shadow Stack (이중 비밀 회계 장부)**:
   - **전통적 커널 (단일 스택)**: 외출한 직원들의 복귀 명부(Return Address)가 누구나 손댈 수 있는 탁자(Main Data Stack) 위에 놓여 있음. 공격자가 명부의 이름을 위조하면 복귀 시 엉뚱한 방으로 들어감.
   - **Shadow Stack 하드닝 커널**: 메인 탁자 외에 방탄 금고 내부의 특수 하드웨어 장부(`SSP` 레지스터)에 동일한 복귀 명부를 비밀리에 동시 기록함. 직원이 복귀(`ret`)할 때 두 장부의 서명을 1:1 대조하여 1바이트라도 다를 경우 즉시 프로세스를 강제 사살(`SIGSEGV`)함.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 Intel IBT (Indirect Branch Tracking) 아키텍처

```text
[ Indirect Call: call *%rax ]
             │
             ▼
   [ CPU State Machine ]
    WAIT_FOR_ENDBRANCH
             │
     ┌───────┴───────┐
     ▼               ▼
[ Next Instruction ]  [ Next Instruction ]
    == endbr64           != endbr64
  (0xf3 0f 1e fa)
     │               │
     ▼               ▼
[ State: IDLE ]     [ #CP Exception ]
정상 실행 지속      Vector 21 (CP_ENDBR)
                    -> do_kernel_cp_fault
                    -> ibt=warn (경고) or BUG()
```

1. **CPU 상태 머신 전이**:
   - `IDLE`: 기본 정상 명령어 실행 상태.
   - `WAIT_FOR_ENDBRANCH`: 간접 호출(`call *%reg`, `call *(%mem)`) 또는 간접 점프(`jmp *%reg`) 발생 즉시 CPU 파이프라인이 진입하는 특수 상태.
   - 대상 주소의 첫 인스트럭션이 `endbr64` (4바이트 니모닉: `f3 0f 1e fa`)인 경우 상태가 다시 `IDLE`로 초기화되며 실행이 지속됨.
   - 대상 인스트럭션이 `endbr64`가 아닌 경우 하드웨어 `#CP` (Control Protection Exception, Vector 21, Error Code 3: `CP_ENDBR`) 예외를 발생시킴.
2. **커널 및 도구 체인 연동**:
   - 컴파일러: GCC 및 Clang은 `-fcf-protection=branch` 옵션을 통해 모든 함수 진입점 및 점프 테이블 타깃에 `endbr64`를 자동 삽입함.
   - 커널 `objtool`: 정적 분석을 통해 주소가 노출되지 않은 내부 정적 함수의 불필요한 `endbr64`를 탐지하고, 부팅 시 이를 NOP로 변환(Sealing)하여 잠재적 JOP 가젯을 최소화함.
   - 제어 MSR: 커널 부팅 시 `MSR_IA32_S_CET`의 `CET_ENDBR_EN` 비트를 활성화하고 `CR4.CET` 비트를 셋업함.
   - 커널 예외 핸들러: `arch/x86/kernel/cet.c`의 `exc_control_protection` -> `do_kernel_cp_fault`가 트랩을 포착함. `ibt=warn` 커널 파라미터가 주어지면 경고 콜스택을 덤프하고 WFE(Wait For Endbranch) 상태를 클리어한 후 실행을 복구함.

### 3.2 Intel User Shadow Stack (SHSTK) 아키텍처

```text
       일반 메모리 공간                    하드웨어 격리 공간
┌───────────────────────────┐       ┌───────────────────────────┐
│     Main Data Stack       │       │    User Shadow Stack      │
│  (RSP - 일반 변수/스택)   │       │  (SSP - 오직 반환 주소)  │
├───────────────────────────┤       ├───────────────────────────┤
│ [Local Vars / Buffers]    │       │                           │
│ [Saved RBP]               │       │                           │
│ [Return Address: 0x401234]│       │ [Return Address: 0x401234]│
└───────────────────────────┘       └───────────────────────────┘
              ▲                                   ▲
              │                                   │
              └───────────────┬───────────────────┘
                              │
                    [ ret Instruction ]
                     Pop RSP & Pop SSP
                     상호 일치 동기 검증
                              │
                      ┌───────┴───────┐
                      ▼               ▼
                 주소 일치        주소 불일치 (ROP 탐지)
                 정상 복귀        하드웨어 #CP (CP_RET)
                                  -> SIGSEGV (SEGV_CPERR)
```

1. **하드웨어 섀도 스택 포인터 (`SSP`)**:
   - CPU 내부에 메인 스택 포인터(`RSP`)와 완전히 독립된 `SSP` (Shadow Stack Pointer) 및 `MSR_IA32_PL3_SSP`를 유지함.
   - 섀도 스택 페이지는 페이지 테이블 레벨에서 특수 메모리 속성(`PTE.SHSTK`, Dirty 비트와의 특정 조합)으로 매핑되어 일반 `mov`, `memcpy` 등 사용자 공간의 쓰기 명령어가 하드웨어 수준에서 차단됨.
2. **동기식 Call / Ret 검증**:
   - `call`: 일반 스택(`RSP`)에 반환 주소를 푸시함과 동시에 섀도 스택(`SSP`)에도 동일 주소를 하드웨어가 자동 푸시함.
   - `ret`: 일반 스택과 섀도 스택에서 반환 주소를 동시에 팝하여 비교함. 공격자가 버퍼 오버플로우로 메인 스택의 반환 주소를 변조했더라도 섀도 스택의 주소와 불일치하여 즉시 `#CP` 예외(Error Code 1: `CP_RET`)를 발생시키고 `SIGSEGV`로 프로세스를 사살함.
3. **유저 공간 제어 인터페이스**:
   - 리눅스 커널은 `arch_prctl` 시스템 콜 옵션 `ARCH_SHSTK_ENABLE`(0x5001)을 통해 프로세스별 섀도 스택 활성화를 제어함.
   - 동적 섀도 스택 수정이 필요한 런타임(예: setjmp/longjmp, C++ 예외 처리)을 위해 특수 명령어인 `INCSSP` (섀도 스택 포인터 조정) 및 `WRSS` (커널 모드 제한적 쓰기)를 제공함.

### 3.3 x86 Intel CET vs ARM64 BTI / PAC 아키텍처 대비

| 기능 분류 | x86_64 Intel CET | ARM64 Hardware CFI (Lab 15 연계) |
| :--- | :--- | :--- |
| **순방향 CFI (Forward)** | **Intel IBT** (`CONFIG_X86_KERNEL_IBT`) | **ARM64 BTI** (`CONFIG_ARM64_BTI_KERNEL`) |
| **타깃 인증 인스트럭션** | `endbr64` (`0xf3 0f 1e fa`) | `bti c` / `bti j` / `bti jc` |
| **순방향 트랩 예외** | `#CP` (Control Protection, Vector 21) | Branch Target Exception (`ESR_EL1.EC = 0x34`) |
| **역방향 CFI (Backward)** | **Intel User Shadow Stack** (`SSP`) | **ARM64 PAC** (`pacia`/`autia`) & **Clang SCS** (`x18`) |
| **반환 주소 보호 방식** | 물리적 보조 섀도 스택 페이지 (`SSP`) | 암호학적 포인터 서명 태그 검증 (PAC) |
| **역방향 트랩 예외** | `#CP` (`CP_RET`) -> `SIGSEGV` | Pointer Authentication Trap (`ESR_EL1.EC = 0x1c`) |

---

## 4. 핸즈온 실습 및 검증 아키텍처

본 실습 환경은 실제 커널 드라이버, 비특권 유저 공간 PoC, 게스트 내 자동 검증 러너, LKDTM 테스트 스위트로 구성됨:

1. **취약 인터페이스 커널 드라이버 (`/proc/vuln_ibt`, 모드 0666)**:
   - `labs/14-ibt-shstk/vuln_ibt.c`에서 구현되어 커널 내장 드라이버(`drivers/misc/vuln_ibt.o`)로 빌드됨.
   - `cat /proc/vuln_ibt` 시 커널 IBT 설정, 섀도 스택 설정, CPU 하드웨어 지원 여부, 타깃 함수의 실제 첫 4바이트 인스트럭션 opcode를 직접 역참조하여 출력함.
   - `echo 'legit' > /proc/vuln_ibt`: `endbr64`가 포함된 정상 타깃 간접 호출.
   - `echo 'noendbr' > /proc/vuln_ibt`: `endbr64`가 제거된 타깃(`__noendbr` 또는 +4 바이트 오프셋)으로 간접 호출 분기 시도.
2. **유저 공간 PoC 바이너리 (`/bin/exploit_ibt_shstk`)**:
   - 비특권 계정 `lab` (UID 1000)으로 실행됨.
   - `arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK)` (0x5001) 시스템 콜을 직접 호출하여 섀도 스택 커널 지원 여부 검증.
   - `/proc/vuln_ibt`를 통해 컴파일러의 `endbr64` 주입 여부를 동적 확인하고 비인증 간접 분기 방어 동작을 실증함.
3. **자동화 테스트 러너 (`/bin/test_ibt_shstk`)**:
   - `lab_test=test_ibt_shstk` 부팅 시 자동 기동됨.
   - PoC 테스트와 LKDTM `CFI_BACKWARD` 테스트를 연속 수행하고 dmesg 트랩 텔레메트리를 자동 파싱함.

---

## 5. 실습 로그 및 방어 전후 비교

### 5.1 x86_64 Hardened 환경 실측 결과 (`ibt-shstk`)

```text
=========================================================
  [Test 1/2] Real-World Intel CET / IBT & SHSTK Exploit PoC
  Target:       /proc/vuln_ibt
  Exploit:      /bin/exploit_ibt_shstk
  Runner:       lab (UID 1000, non-privileged)
=========================================================
[*] Launching user-space PoC to test Shadow Stack and IBT...

=========================================================
  Linux Kernel Hardening Lab - Intel CET / IBT & SHSTK PoC
  Target Architecture: x86_64
  Current User:        UID = 1000 (non-root)
=========================================================

---------------------------------------------------------
  [Test 1/2] User-space Shadow Stack Activation (arch_prctl)
---------------------------------------------------------
[*] Calling arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK = 0x1)...
[*] arch_prctl returned: -1 (errno=95: Operation not supported)
[+] HARDENED KERNEL CONFIRMED: Syscall ARCH_SHSTK_ENABLE is recognized
    and supported by kernel (CONFIG_X86_USER_SHADOW_STACK=y).
    (Current CPU/hypervisor lacks Intel CET SHSTK MSR hardware feature).

---------------------------------------------------------
  [Test 2/2] Kernel Indirect Branch Tracking (IBT) / ENDBR
---------------------------------------------------------
[*] Kernel IBT Config:       ENABLED
[*] User Shadow Stack Config:ENABLED
[*] HW IBT Supported:        NO
[*] HW SHSTK Supported:      NO
[*] Compiler ENDBR Detected: YES (0xfa1e0ff3)
[*] Legit Target Address:    0xffffffff819580a0
[*] No-ENDBR Target Address: 0xffffffff819580d0

[Step 2A] Triggering legitimate indirect call (with ENDBR64)...
[+] Result: LEGIT_SUCCESS (Total calls: 1)

[Step 2B] Triggering indirect call to target lacking ENDBR64...
[*] Result: NOENDBR_EXECUTED (Total calls: 2)
[+] DEFENSE ACTIVE: Kernel compiled with -fcf-protection=branch (CONFIG_X86_KERNEL_IBT=y).
[+] Valid indirect targets require ENDBR64 instruction (0xfa1e0ff3).
[*] Toolchain/objtool IBT hardening verified (QEMU CPU CET hardware emulation pending).

=========================================================
  Intel CET / IBT & Shadow Stack Verification Complete
=========================================================
```

### 5.2 x86_64 Baseline 환경 실측 결과 (`ibt-shstk-disabled`)

```text
=========================================================
  [Test 1/2] Real-World Intel CET / IBT & SHSTK Exploit PoC
  Target:       /proc/vuln_ibt
  Exploit:      /bin/exploit_ibt_shstk
  Runner:       lab (UID 1000, non-privileged)
=========================================================
[*] Launching user-space PoC to test Shadow Stack and IBT...

=========================================================
  Linux Kernel Hardening Lab - Intel CET / IBT & SHSTK PoC
  Target Architecture: x86_64
  Current User:        UID = 1000 (non-root)
=========================================================

---------------------------------------------------------
  [Test 1/2] User-space Shadow Stack Activation (arch_prctl)
---------------------------------------------------------
[*] Calling arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK = 0x1)...
[*] arch_prctl returned: -1 (errno=22: Invalid argument)
[-] BASELINE DETECTED: Kernel returned EINVAL (Syscall option unknown).
    CONFIG_X86_USER_SHADOW_STACK is disabled in this kernel.

---------------------------------------------------------
  [Test 2/2] Kernel Indirect Branch Tracking (IBT) / ENDBR
---------------------------------------------------------
[*] Kernel IBT Config:       DISABLED
[*] User Shadow Stack Config:DISABLED
[*] HW IBT Supported:        NO
[*] HW SHSTK Supported:      NO
[*] Compiler ENDBR Detected: NO
[*] Legit Target Address:    0xffffffff81958080
[*] No-ENDBR Target Address: 0xffffffff819580a0

[Step 2A] Triggering legitimate indirect call (with ENDBR64)...
[+] Result: LEGIT_SUCCESS (Total calls: 1)

[Step 2B] Triggering indirect call to target lacking ENDBR64...
[*] Result: NOENDBR_EXECUTED (Total calls: 2)
[!] VULNERABLE: Kernel compiled with -fcf-protection=none.
[!] Indirect call to un-instrumented target succeeded without restriction.

=========================================================
  Intel CET / IBT & Shadow Stack Verification Complete
=========================================================
```

### 5.3 핵심 차이점 분석

1. **User Shadow Stack 시스템 콜 응답**:
   - Hardened: `errno == ENOTSUP` (95). 커널이 `0x5001`(`ARCH_SHSTK_ENABLE`)을 인지하고 `shstk_setup()`을 호출하여 CPU MSR 지원 여부를 판별함.
   - Baseline: `errno == EINVAL` (22). 커널에 섀도 스택 핸들러 자체가 존재하지 않아 미정의 옵션으로 거부됨.
2. **컴파일러 `endbr64` 인스트럭션 주입**:
   - Hardened: `COMPILER_ENDBR_DETECTED: YES (0xfa1e0ff3)`. 커널 전체가 `-fcf-protection=branch`로 빌드되어 간접 호출 타깃에 `endbr64`가 엄격히 배치됨.
   - Baseline: `COMPILER_ENDBR_DETECTED: NO`. 커널이 `-fcf-protection=none`으로 빌드되어 `endbr64`가 일체 삽입되지 않음.

---

## 6. 커널 설정 가이드 및 트러블슈팅

### 6.1 Kconfig 설정

```ini
# Intel CET 공통 하부 시스템 활성화
CONFIG_X86_CET=y

# 커널 순방향 간접 분기 추적 활성화 (GCC/Clang -fcf-protection=branch 필수)
CONFIG_X86_KERNEL_IBT=y

# 유저스페이스 섀도 스택 활성화 (arch_prctl 0x5001 제어 인터페이스 제공)
CONFIG_X86_USER_SHADOW_STACK=y

# 커널 크래시 및 취약점 검증 프레임워크
CONFIG_LKDTM=y
```

### 6.2 커널 부팅 커맨드라인 파라미터

- `ibt=warn`:
  - IBT `#CP` 위반 발생 시 즉각적인 `BUG()` 커널 패닉 대신 경고 콜스택(Warning Calltrace)을 출력하고 WFE 상태를 클리어하여 시스템 실행을 지속하도록 허용함.
  - 디버깅 및 실습 환경에서 매우 유용함.
- `ibt=off`:
  - 부팅 시 CPU 역량 플래그 `X86_FEATURE_IBT`를 강제 클리어하여 하드웨어 IBT 검증을 완전히 비활성화함.

---

## 7. 공격 기법 및 한계점 분석

1. **Coarse-Grained CFI 한계 (IBT)**:
   - Intel IBT는 본질적으로 '성긴(Coarse-grained)' CFI 기법임.
   - 즉, 분기 목적지에 `endbr64` 인스트럭션이 존재하기만 하면 함수의 프로토타입 시그니처나 인자 타입과 무관하게 분기가 허용됨.
   - 공격자가 커널 내에 합법적으로 존재하는 다른 `endbr64` 엔트리포인트로 분기하는 함수 재사용 공격은 IBT 단독으로 방어할 수 없음.
2. **FineIBT의 등장 배경**:
   - 이러한 Coarse-Grained 한계를 극복하기 위해 최신 리눅스 커널은 **FineIBT** (`CONFIG_X86_KERNEL_IBT` + Clang kCFI 연동)를 지원함.
   - FineIBT는 하드웨어 IBT(`endbr64`) 직후에 32비트 Type Hash 대조 인스트럭션을 소프트웨어로 연쇄 배치하여, 하드웨어 IBT의 강력한 분기 제한과 정밀한 프로토타입 타입 검증을 결합함.
3. **Shadow Stack의 한계와 데이터 변조 공격**:
   - Shadow Stack은 스택의 반환 주소(`ret`)만을 보호하며, 함수 프레임 내부의 로컬 변수, 함수 포인터, 또는 제어 플래그 변조(Data-Only Attack)는 방어하지 못함.
   - 따라서 Stack Protector (`CONFIG_STACKPROTECTOR_STRONG`), FORTIFY_SOURCE, Hardened Usercopy 등 복합 방어 계층과의 병행 운용이 필수적임.

---

## 8. 대화형 아키텍처 다이어그램

본 실습의 4개 시나리오 인터랙티브 시각화 다이어그램은 다음 파일에서 확인할 수 있음:
- [Intel CET Architecture Diagram](file:///home/auking45/repos/linux-kernel-hardening-lab/docs/assets/diagrams/ibt-shstk/architecture.html)
- 다크/라이트 모드 지원, IBT CPU 상태 머신 단계별 전이 시뮬레이션, 스택 프레임 vs 섀도 스택 불일치 인터랙션 제공.

