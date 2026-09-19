# ARM64 BTI & PAC (Branch Target Identification 및 Pointer Authentication Code)

## 1. 개요 및 배경

ARM64(AArch64) 아키텍처 기반 모바일(Android/iOS), 서버(Neoverse), 임베디드 환경에서 메모리 취약점을 악용한 제어 흐름 탈취 공격(Control Flow Hijacking)은 지속적인 위협 요소로 자리잡고 있음. 공격자는 힙 오버플로우나 UAF(Use-After-Free)로 함수 포인터를 변조하는 **JOP/COP(Jump/Call-Oriented Programming)** 기법과 스택 프레임의 반환 주소(LR)를 오염시키는 **ROP(Return-Oriented Programming)** 기법을 결합하여 실행 흐름을 제어함.

소프트웨어 기반 CFI(Clang KCFI 등)는 전방향 간접 호출을 타입 해시로 검증할 수 있으나 컴파일 단위 제약이 존재하며, 스택 반환 주소를 완벽히 보호하기에는 한계가 존재함. 이를 근본적으로 해결하기 위해 Arm은 하드웨어 수준에서 명령어 세트(ISA)를 확장함:

1. **ARMv8.5-A BTI (Branch Target Identification)**:
   - 전방향 제어 흐름 무결성(Forward-edge CFI)을 하드웨어 파이프라인에서 직접 보장함.
   - 간접 분기(Indirect Branch: `BLR`, `BR`) 시 착륙 지점의 첫 명령어가 유효한 착륙 패드(`bti c`, `paciasp` 등)인지 검사함.
2. **ARMv8.3-A PAC (Pointer Authentication Code)**:
   - 후방향 제어 흐름 무결성(Backward-edge CFI)을 암호학적 서명(Cryptographic Signature)으로 보장함.
   - 함수 진입 시 반환 주소(LR/x30)의 상위 미사용 가상 주소 비트에 비밀 키 기반 서명(PAC)을 삽입하고, 복귀 시 이를 인증하여 ROP를 원천 무력화함.

리눅스 커널 6.12 LTS는 `CONFIG_ARM64_BTI_KERNEL=y` 및 `CONFIG_ARM64_PTR_AUTH_KERNEL=y`를 통해 커널 공간 및 사용자 공간 전반에 하드웨어 네이티브 CFI 방어망을 구축함.

---

## 2. 실세계 비유: 정문 신분증 확인대와 디지털 전자 인장

ARM64 BTI와 PAC의 상호 보완적 방어 메커니즘은 중요 시설의 출입 절차 및 기밀 문서 결재 시스템에 비유할 수 있음:

1. **BTI (전방향 착륙 게이트 신분증 확인대)**:
   - **전통적 커널 (비보호 상태)**: 방문자(간접 분기 `BLR`)가 가리키는 주소로 가면, 중간 문이든 창고 쪽문이든 구분 없이 바로 침입이 허용됨. 공격자가 가젯 중간으로 점프해도 CPU는 이를 정상 코드로 인식함.
   - **BTI 적용 커널 (보호 상태)**: 인가된 모든 공식 정문 입구 바닥에는 'BTI 랜딩 패드' 표식이 각인되어 있음. 간접 분기가 발생하면 CPU 파이프라인은 즉시 `PSTATE.BTYPE` 경계 모드로 전환됨. 착륙 지점의 첫 명령어가 인가된 표식(`bti c` 또는 `paciasp`)이 아닐 경우 즉시 침입 경보인 `Oops - BTI` 예외를 발생시키고 실행을 차단함.
2. **PAC (후방향 암호학적 인감도장)**:
   - **전통적 커널 (단일 스택 반환 주소)**: 출장을 떠난 직원의 복귀증(Return Address LR)이 스택이라는 개방된 탁자 위에 일반 텍스트로 보관됨. 공격자가 탁자 위 복귀증 주소를 위조하면 복귀 시 엉뚱한 가젯으로 이동함.
   - **PAC 적용 커널 (암호학적 서명)**: 직원이 외출할 때 CPU 내부 금고의 비밀 키(Key A)와 현재 스택 위치(SP)를 혼합하여 복귀증 상단 빈 공간에 위조 불가능한 '암호학적 인감(PAC)'을 날인함(`paciasp`). 복귀 시 인감을 재검증(`autiasp`)하여 1비트라도 훼손되었을 경우 즉시 `Oops - FPAC` 예외를 발생시키며 즉각 사살함.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 ARM64 BTI (Forward-Edge CFI) 아키텍처

```text
[ Indirect Branch: BLR Xn / BR Xn ]
                 │
                 ▼
     [ CPU Hardware PSTATE ]
     Set PSTATE.BTYPE = 0b10 (Call)
     Page Check: PTE_GP (Guarded Page)
                 │
         ┌───────┴───────┐
         ▼               ▼
   [ First Target Insn ]   [ First Target Insn ]
   == bti c (0xd503245f)   != BTI Landing Pad
   or paciasp (0xd503233f) (e.g. stp x29, x30...)
         │               │
         ▼               ▼
  [ BTYPE Cleared to 00 ] [ Branch Target Exception ]
  정상 실행 지속           ESR_EL1.EC = 0x0D
                          -> Kernel Oops - BTI
                          -> Process Terminated
```

1. **PSTATE.BTYPE 상태 전이**:
   - `0b00`: 기본 실행 상태 (간접 분기 대기 상태 아님).
   - `0b01`: 범용 레지스터 간접 점프(`BR Xn`, 단 X16/X17 제외) 직후 상태. `bti j` 또는 `bti jc` 허용.
   - `0b10`: 간접 함수 호출(`BLR Xn` 또는 `BR X16/X17`) 직후 상태. `bti c` 또는 `bti jc`, `paciasp`, `pacibsp` 허용.
   - `0b11`: 예약됨.
2. **Landing Pad 최적화 (paciasp)**:
   - `paciasp` 명령어(`0xd503233f`)는 PAC Key A 서명 기능과 동시에 암시적 `bti c` 랜딩 패드 역할을 동시 수행함.
   - 따라서 BTI와 PAC가 모두 활성화된 함수는 별도의 `bti c` 인스트럭션 추가 없이 `paciasp` 단일 명령어로 순방향과 역방향 검증을 원클릭 처리하여 코드 밀도를 극대화함.
3. **PTE Guarded Page (`PTE_GP`) 속성**:
   - ARMv8.5 BTI는 페이지 테이블의 비트 50(`GP` - Guarded Page)을 통해 활성화됨.
   - 커널 모듈 및 vmalloc/vmlinux 매핑 시 `PTE_MAYBE_GP`를 통해 BTI 지원 페이지로 마킹됨.

### 3.2 ARM64 PAC (Backward-Edge CFI) 아키텍처

```text
64-bit Virtual Address with PAC Layout (TBI enabled):
┌───────────┬─────────────┬───────────────────────────────────────────┐
│ Bits 63   │ Bits 62..48 │ Bits 47..0                                │
│ Sign Ext  │ PAC Tag     │ Canonical Virtual Memory Address          │
└───────────┴─────────────┴───────────────────────────────────────────┘
     ▲             ▲                            ▲
     │             │                            │
     └────── PACIASP computes tag ──────────────┘
            using Key A (128-bit secret) + SP (Modifier)
```

1. **포인터 서명 메커니즘 (`paciasp`)**:
   - 가상 메모리 주소 체계에서 상위 비트(bits 54:48 또는 VA 크기에 따라 가변)는 실제로 사용되지 않음.
   - `paciasp`는 하드웨어 암호화 유닛(QARMA-64 또는 PAC-GA)을 이용하여 `Key A` (128비트 내부 레지스터)와 `Modifier` (현재 스택 포인터 SP)를 입력으로 암호학적 다이제스트를 생성하고 상위 비트에 삽입함.
2. **포인터 인증 및 변조 탐지 (`autiasp`)**:
   - 함수 에필로그에서 `autiasp`는 동일한 `Key A`와 현재 `SP`로 서명을 재계산함.
   - **일치 시**: 상위 PAC 비트를 깨끗하게 제거하여 원래의 유효한 가상 주소로 복원 후 `ret` 실행.
   - **불일치 시**: 상위 비트에 오류 패턴(Bit 61/62 등)을 주입하여 비정규 주소(Non-canonical address)로 변환함. ARMv8.6-A / FPAC 지원 CPU에서는 주소 변조 즉시 하드웨어 예외(`ESR_EL1.EC=0x1C`, `Oops - FPAC`)를 일으켜 프로세스를 즉시 종료함.

---

## 4. 인터랙티브 아키텍처 다이어그램

다음 다이어그램은 ARM64 BTI 전방향 분기 착륙 검증, PAC 후방향 반환 주소 암호화 서명/인증, 베이스라인 취약점 대비, 그리고 x86 Intel CET와의 아키텍처 비교를 대화형으로 제공함:

<iframe src="../../assets/diagrams/bti-pac/architecture.html" width="100%" height="700px" style="border: 1px solid #334155; border-radius: 8px; margin: 16px 0;"></iframe>

---

## 5. 커널 설정 및 빌드 플래그

### 5.1 Kconfig 설정 (`configs/features/bti-pac.config`)

```ini
# Hardening Feature: ARM64 BTI & PAC
# 유저스페이스 및 커널 공간 Pointer Authentication 활성화
CONFIG_ARM64_PTR_AUTH=y
CONFIG_ARM64_PTR_AUTH_KERNEL=y

# 유저스페이스 및 커널 공간 Branch Target Identification 활성화
CONFIG_ARM64_BTI=y
CONFIG_ARM64_BTI_KERNEL=y

# 검증용 LKDTM 테스트 프레임워크
CONFIG_LKDTM=y
```

### 5.2 툴체인 요구사항 및 LLVM 빌드 제약

- **GCC 버그 106671 회피**: 업스트림 리눅스 6.12 커널의 `arch/arm64/Kconfig`는 `CONFIG_ARM64_BTI_KERNEL`에 대해 `depends on !CC_IS_GCC` 제약을 명시함. GCC의 BTI 인스트루먼테이션 관련 알려진 결함으로 인해, 본 실습 환경은 `scripts/build_kernel.sh`에서 ARM64 BTI/PAC 빌드 시 `LLVM=1` (Clang 18) 툴체인을 자동으로 활성화하도록 구성됨.
- **컴파일러 플래그**: Clang은 `-mbranch-protection=pac-ret+leaf+bti` 옵션을 전달받아 모든 함수 진입부에 `paciasp`(`0xd503233f`) 또는 `bti c`(`0xd503245f`)를 생성하고, 에필로그에 `autiasp`(`0xd50323bf`)를 자동 삽입함.

---

## 6. 실습 및 검증 결과

### 6.1 4개 시나리오 듀얼 아키텍처 실기 검증 매트릭스

본 실습은 ARM64와 x86_64 듀얼 아키텍처에 대해 각각 Hardened 및 Baseline 커널을 교차 빌드하고 QEMU 실기 부팅을 통해 무결성을 입증함.

| 시나리오 | 타깃 아키텍처 | 빌드 설정 | BTI 전방향 보호 (JOP 차단) | PAC 후방향 보호 (ROP 차단) | LKDTM CFI_BACKWARD 결과 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **시나리오 1** | **ARM64** | `bti-pac` (Hardened) | <span style="color:#22c55e">**차단 성공** (`Oops - BTI`)</span> | <span style="color:#22c55e">**차단 성공** (`Oops - FPAC`)</span> | <span style="color:#22c55e">**성공: FPAC 하드웨어 트랩**</span> |
| **시나리오 2** | **ARM64** | `bti-pac-disabled` | <span style="color:#ef4444">무방비 (`NOBTI_EXECUTED`)</span> | <span style="color:#ef4444">무방비 (서명 비활성)</span> | <span style="color:#ef4444">취약: `FAIL: redirected!`</span> |
| **시나리오 3** | **x86_64** | `bti-pac` (Hardened) | ARM64 전용 기술 안내 | ARM64 전용 기술 안내 | x86 CET (Lab 14) 대조 |
| **시나리오 4** | **x86_64** | `bti-pac-disabled` | ARM64 전용 기술 안내 | ARM64 전용 기술 안내 | 베이스라인 정상 복귀 |

### 6.2 시나리오 1: ARM64 Hardened 실기 로그 (`Image` 5.9MB)

```text
[Step 2A] Triggering legitimate indirect call (with BTI/PAC landing pad)...
[+] Result: LEGIT_SUCCESS (Total calls: 1)

[Step 2B] Triggering indirect call to target lacking BTI landing pad...
[    4.321017] Internal error: Oops - BTI: 0000000036000002 [#1] SMP
[    4.327997] CPU: 0 UID: 1000 PID: 48 Comm: exploit_bti_pac Not tainted 6.12.109 #1
[    4.331037] pstate: 61400805 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=-c)
[    4.341288] pc : bti_nobti_target+0x0/0x54
[    4.346606] lr : bti_dispatch_call+0x34/0x44
[    4.388245] Code: 9401b342 a8c17bfd d50323bf d65f03c0 (a9be7bfd)
[+] ARM64 BTI가 첫 인스트럭션 실행 전 파이프라인에서 분기를 강제 동결 및 종료함!

[Test 2/2] Triggering LKDTM CFI_BACKWARD Test
[    4.689924] lkdtm: Attempting unchecked stack return address redirection ...
[    4.690729] lkdtm: ok: redirected stack return address.
[    4.691675] lkdtm: Attempting checked stack return address redirection ...
[    4.692970] Internal error: Oops - FPAC: 0000000072000000 [#2] SMP
[    4.700042] pc : set_return_addr+0x28/0x44
[    4.761848] Code: eb00011f 540000a1 f90007a2 a8c17bfd (d50323bf)
[+] autiasp(0xd50323bf) 인스트럭션이 변조된 반환 주소를 감지하고 즉시 Oops - FPAC 트랩 발생!
```

### 6.3 시나리오 2: ARM64 Baseline 실기 로그 (`Image` 5.8MB)

```text
[Step 2B] Triggering indirect call to target lacking BTI landing pad...
[*] Result: NOBTI_EXECUTED (Total calls: 2)
[    1.855738] [vuln_bti_pac] [!] VULNERABLE: Function without BTI landing pad executed!
[    1.855765] [vuln_bti_pac] [!] Control flow redirected to non-BTI target: val=0xdeadbeef

[Test 2/2] Triggering LKDTM CFI_BACKWARD Test
[    2.004013] lkdtm: Attempting checked stack return address redirection ...
[    2.004097] lkdtm: FAIL: stack return address was redirected!
[    2.005578] lkdtm: This is probably expected, since this kernel was built *without* CONFIG_ARM64_PTR_AUTH_KERNEL=y
```

---

## 7. ARM64 BTI & PAC vs x86 Intel CET 비교 분석

| 항목 (Metric) | ARM64 (BTI + PAC) | x86_64 (Intel CET IBT + SHSTK) |
| :--- | :--- | :--- |
| **순방향 방어 기술** | Branch Target Identification (BTI) | Indirect Branch Tracking (IBT) |
| **순방향 랜딩 패드** | `bti c` (`0xd503245f`) 또는 `paciasp` (`0xd503233f`) | `endbr64` (`0xfa1e0ff3`) |
| **역방향 방어 기술** | Pointer Authentication Code (PAC) | Shadow Stack (SHSTK) |
| **역방향 구현 원리** | 가상 주소 상위 미사용 비트 암호학적 서명 | 별도 물리 메모리 페이지에 섀도 스택 할당 |
| **추가 메모리 소비** | **0% (추가 메모리 불필요)** | 스택 크기만큼 100% 추가 메모리 할당 필요 |
| **DRAM 버스 트래픽** | 추가 읽기/쓰기 없음 (CPU 레지스터 연산) | CALL/RET마다 섀도 스택 쓰기/읽기 발생 |
| **서명 대상 확장성** | 반환 주소, 함수 포인터, 데이터 포인터 모두 서명 가능 | 오직 스택 반환 주소(RIP)만 격리 가능 |
| **하드웨어 트랩** | `Oops - BTI (0x0D)` / `Oops - FPAC (0x1C)` | `#CP (Interrupt 21, Error Code 3)` |

---

## 8. 보안 효과 및 트레이드오프

### 8.1 보안 효과
1. **ROP / JOP 공격 체인 붕괴**: 함수 포인터 변조를 통한 JOP 가젯 체이닝과 스택 버퍼 오버플로우를 통한 ROP 체인이 하드웨어 단계에서 차단됨.
2. **제로 메모리 오버헤드**: Intel Shadow Stack과 달리 보조 스택 페이지 할당이 불필요하므로 메모리가 제한된 임베디드 및 모바일 기기에 최적임.
3. **포인터 무결성 전방위 보호**: PAC는 반환 주소뿐 아니라 커널 구조체 내부의 데이터 포인터 및 함수 포인터 서명(`pacia`, `pacda`)에도 유연하게 적용 가능함.

### 8.2 트레이드오프
1. **컴파일러 및 하드웨어 의존성**: ARMv8.3/v8.5 이상 하드웨어와 Clang 18+ 툴체인이 요구됨 (구형 프로세서에서는 NOP로 동작).
2. **미세한 CPU 사이클 비용**: 매 함수 진입/퇴출 시 서명 연산으로 인해 통상 1~2% 내외의 연산 오버헤드가 발생함.

---

## 9. 결론 및 향후 확장 로드맵 (MTE / AVF / CCA)

ARM64 BTI와 PAC는 소프트웨어 계층의 한계를 뛰어넘어 하드웨어 파이프라인에서 직접 제어 흐름 무결성을 강제하는 차세대 핵심 보안 기능임.

### 향후 확장 로드맵 (Roadmap)
1. **ARM64 MTE (Memory Tagging Extension - Phase 7 제안)**:
   - 하드웨어 비동기/동기 메모리 태깅(16바이트 청크당 4비트 컬러 태그)을 통해 힙 버퍼 오버플로우 및 UAF(Use-After-Free)를 즉각 탐지하는 실습 환경 구축 예정.
2. **AVF (Android Virtualization Framework)**:
   - pKVM(Protected KVM) 기반으로 격리된 마이크로 안드로이드 게스트 VM(pVM) 환경에서의 신뢰 실행 환경 검증.
3. **Arm CCA (Confidential Compute Architecture)**:
   - RMM(Realm Management Monitor) 및 하이퍼바이저로부터도 메모리가 암호학적으로 은닉되는 기밀 컴퓨팅(Realm) 데모 환경 확장 지원 예정.
