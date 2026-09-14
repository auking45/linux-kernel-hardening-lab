# FG-KASLR: 함수 단위 배치 무작위화 및 Monolithic KASLR 한계 극복 실습

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/fgkaslr/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="FG-KASLR Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: Monolithic KASLR의 단일 포인터 유출(Infoleak) 취약점

- **단일 슬라이드(Monolithic Slide) 방식의 구조적 결함**:
  - 기존 KASLR(`CONFIG_RANDOMIZE_BASE=y`)은 커널 `.text` 섹션 전체를 하나의 거대한 블록으로 취급하여 단일 난수 오프셋(`Slide`)을 일괄 적용함.
  - 이로 인해 커널 코드의 시작 주소(`_text`)는 무작위화되지만, 함수 간의 상대적 거리($\Delta$)는 컴파일 타임의 ELF 바이너리 구조와 100% 동일하게 고정됨:
    $$\Delta = \text{Addr}(\text{Target\_Func}) - \text{Addr}(\text{Leaked\_Func}) = \text{Constant}$$
  - 공격자가 스택 미소거(Uninitialized Stack)나 힙 객체 잔여물 등에서 임의의 커널 함수 포인터 단 1개만 유출시키면, 커널 슬라이드와 모든 가젯 주소를 즉각 역산해 낼 수 있음.
- **FG-KASLR (Function Granular KASLR)의 보안 목표**:
  - 함수 단위로 개별 섹션을 분리(`-ffunction-sections`)하고 부팅 시점 또는 로딩 시점에 함수들의 물리/가상 배치 순서를 무작위로 셔플링(Permutation)함.
  - 함수 간의 상대 거리($\Delta$)를 난수화함으로써, 단일 함수 포인터가 유출되더라도 인접 함수나 ROP 가젯 체인을 유추할 수 없도록 방어선을 구축함.

### 1.2 직관적 실전 비유: 레고 블록 셔플링 (The Shuffled LEGO Blocks Metaphor)

- **비유 설명**:
  - 커널 내의 함수들을 레고 블록 모형의 방들에 비유할 수 있음.
  - **Monolithic KASLR**: 통째로 완성된 레고 성(Castle) 전체를 들고 지도상의 임의의 좌표로 옮겨 놓은 상태임. 성의 절대 위치는 바뀌었지만, 1호실(유출 함수)에서 5호실(타깃 함수)까지의 복도 거리와 방향은 완벽히 동일함. 침입자가 1호실의 위치만 알아내면 벽을 뚫고 5호실로 직행할 수 있음.
  - **FG-KASLR**: 성을 구성하는 수만 개의 레고 블록(함수)을 전부 떼어내어 상자 속에 넣고 흔든 뒤 무작위 순서로 다시 조립한 상태임. 1호실의 위치를 알아냈더라도 5호실이 어디에 붙어 있는지 전혀 알 수 없으며, 기존 복도 설계도($\Delta$)를 믿고 전진하면 낭떠러지로 추락함.

---

## 2. 커널 내부 구현 원리 및 메인라인 쟁점 분석

### 2.1 FG-KASLR의 기술적 메커니즘 (Kristen Carlson Accardi RFC)

- **컴파일러 레벨 함수 섹션 분할**:
  - GCC의 `-ffunction-sections` 컴파일러 플래그를 사용하여 커널 소스의 모든 함수를 독립된 ELF 섹션(`.text.<function_name>`)으로 분할 생성함.
- **부팅 압축 해제기(Boot Decompressor)의 재배치**:
  - 커널 부팅 초기(`arch/x86/boot/compressed/`), 재배치 테이블을 파싱하여 함수 섹션들의 레이아웃을 무작위 순서로 재배열함.
  - 심볼 테이블 및 예외 테이블(`extable`), 버그 테이블(`bug_table`)의 오프셋을 동적으로 재계산하여 패치함.

### 2.2 리눅스 메인라인 미반영 사유 및 트레이드오프 심층 분석

- **CPU 마이크로아키텍처 성능 저하**:
  - **iTLB (Instruction TLB) 미스 급증**: 함수들이 흩어져 배치되면서 단일 대용량 페이지(2MB Huge Page) 매핑이 깨지고 4KB 소형 페이지 매핑이 강제되어 TLB 압박이 심화됨.
  - **분기 타깃 버퍼(BTB) 및 L1i 캐시 국소성(Locality) 훼손**: 인접 호출 빈도가 높은 핫(Hot) 함수들이 멀리 떨어져 배치되어 명령어 캐시 미스와 분기 예측 실패율이 대폭 증가 (벤치마크 기준 1~3% 이상의 성능 저하 관측).
- **커널 트레이싱 및 디버깅 인프라 파편화**:
  - `ftrace` 및 `livepatch`: 함수 프롤로그의 5바이트 패치(`fentry`) 및 정적 상대 호출(`call <rel32>`)에 의존하는 런타임 패칭 시스템과 충돌 발생.
  - `perf`, `BPF`, `objtool`: 선형적 주소 공간을 전제로 최적화된 도구 체계의 정합성 유지 곤란.
- **현대 보안의 대안 및 계보**:
  - 메인라인 커널은 배치 자체를 셔플하는 대신 간접 분기 타깃의 무결성을 하드웨어/컴파일러 수준에서 강제하는 **Clang kCFI**, **Intel FineIBT**, **ARM64 PAC/BTI**를 공식 채택함.

---

## 3. 실습 환경 및 취약 드라이버 구현 (Hands-on Lab Implementation)

### 3.1 취약 타깃 드라이버 (`vuln_fgkaslr.c`)

- `/proc/vuln_fgkaslr` (mode 0666) 인터페이스 구현:
  - **상대 오프셋 텔레메트리 제공**:
    - `LEAK_FUNC_ADDR`: 유출 대상 기준 함수(`fgkaslr_leak_source`) 주소.
    - `DEFAULT_TARGET_ADDR`: 컴파일 타임 순차 배치 기준 타깃 함수(`fgkaslr_target_slot0`) 주소.
    - `ACTIVE_TARGET_ADDR`: 현재 런타임 활성 타깃 함수 주소.
    - `STATIC_DELTA`: 기준 함수와 디폴트 타깃 간의 정적 상대 오프셋.
    - `ACTUAL_DELTA`: 기준 함수와 실제 활성 타깃 간의 런타임 상대 오프셋.
  - **모드 제어 및 공격 검증**:
    - 부팅 파라미터 `fgkaslr=1` (활성화) / `fgkaslr=0` (비활성화/Monolithic) 자동 인식.
    - 유저 공간에서 전송한 계산 주소가 실제 활성 함수 주소와 일치하는지 판별 후 실행.

### 3.2 상대 오프셋 기반 익스플로잇 PoC (`exploit.c`)

- 비특권 사용자(`lab`, UID 1000) 권한으로 단일 Infoleak 기반 상대 오프셋 공격 수행:
  - 1단계: `/proc/vuln_fgkaslr`에서 `LEAK_FUNC_ADDR`를 획득 (포인터 1개 유출 시뮬레이션).
  - 2단계: 오프라인 바이너리 분석으로 기확보된 `STATIC_DELTA` 가산 ($Target = Leaked + \Delta_{static}$).
  - 3단계: 계산된 주소로 커널 분기 실행 요청.
  - 결과 판정:
    - **Monolithic 모드**: 정적 델타와 실제 델타가 일치하여 100% 공격 성공 (`[!] VULNERABILITY CONFIRMED`).
    - **FG-KASLR 모드**: 함수 단위 무작위화로 델타 불일치 발생, 공격 차단 (`[+] DEFENSE ACTIVE`).

---

## 4. QEMU 실측 검증 및 분석 (Dual-Architecture Verification)

### 4.1 x86_64 아키텍처 실측 결과

#### Base / Monolithic KASLR (`fgkaslr-disabled`, `fgkaslr=0`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & FG-KASLR State Check
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=0
Boot Mode: FG-KASLR DISABLED via boot param (fgkaslr=0)

=========================================================
  [Test 2/3] Kernel Telemetry Analysis (/proc/vuln_fgkaslr)
=========================================================
FGKASLR_STATUS:        DISABLED
LEAK_FUNC_ADDR:        0xffffffff8f5ab440
DEFAULT_TARGET_ADDR:   0xffffffff8f5ab470
ACTIVE_TARGET_ADDR:    0xffffffff8f5ab470
STATIC_DELTA:          48
ACTUAL_DELTA:          48
DELTA_MISMATCH:        0
ACTIVE_SLOT:           0

=========================================================
  [Test 3/3] Real-World Relative Offset Exploit Demonstration
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Function Layout Telemetry:
    FG-KASLR Status:     DISABLED
    Leaked Function:     0xffffffff8f5ab440
    Default Target:      0xffffffff8f5ab470
    Active Target:       0xffffffff8f5ab470 (Slot 0)
    Static Delta:        +48 bytes
    Actual Delta:        +48 bytes
    Delta Mismatch:      +0 bytes

[*] Exploit Execution (Relative Offset Attack):
    Leaked Pointer:      0xffffffff8f5ab440
    Static Delta:        +48
    Calculated Target:   0xffffffff8f5ab470
[!] Target call returned success!
[!] VULNERABILITY CONFIRMED: Monolithic KASLR defeated via relative offset!
[!] Because function layout was NOT granularly randomized, static delta was valid.
[!] Attacker hijacked control flow with 100% accuracy from 1 infoleak.
```

#### Hardened / FG-KASLR (`fgkaslr`, `fgkaslr=1`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & FG-KASLR State Check
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=1
Boot Mode: FG-KASLR ENABLED via boot param (fgkaslr=1)

=========================================================
  [Test 2/3] Kernel Telemetry Analysis (/proc/vuln_fgkaslr)
=========================================================
FGKASLR_STATUS:        ENABLED
LEAK_FUNC_ADDR:        0xffffffffbb9ab440
DEFAULT_TARGET_ADDR:   0xffffffffbb9ab470
ACTIVE_TARGET_ADDR:    0xffffffffbb9ab4d0
STATIC_DELTA:          48
ACTUAL_DELTA:          144
DELTA_MISMATCH:        96
ACTIVE_SLOT:           3

=========================================================
  [Test 3/3] Real-World Relative Offset Exploit Demonstration
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Function Layout Telemetry:
    FG-KASLR Status:     ENABLED
    Leaked Function:     0xffffffffbb9ab440
    Default Target:      0xffffffffbb9ab470
    Active Target:       0xffffffffbb9ab4d0 (Slot 3)
    Static Delta:        +48 bytes
    Actual Delta:        +144 bytes
    Delta Mismatch:      +96 bytes

[*] Exploit Execution (Relative Offset Attack):
    Leaked Pointer:      0xffffffffbb9ab440
    Static Delta:        +48
    Calculated Target:   0xffffffffbb9ab470
[-] Write returned error: Invalid argument (errno = 22)
[+] Attack blocked or jumped to invalid location!
[+] DEFENSE ACTIVE: FG-KASLR prevented offset calculation!
[+] Function-level layout randomization broke compile-time relative offsets.
[+] Single-pointer infoleak failed to reveal adjacent function addresses.
```

---

### 4.2 ARM64 아키텍처 실측 결과

#### Base / Monolithic KASLR (`fgkaslr-disabled`)
```text
Kernel cmdline: console=ttyAMA0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=0
Boot Mode: FG-KASLR DISABLED via boot param (fgkaslr=0)
FGKASLR_STATUS:        DISABLED
LEAK_FUNC_ADDR:        0xffffa3be17b12b24
DEFAULT_TARGET_ADDR:   0xffffa3be17b12b50
ACTIVE_TARGET_ADDR:    0xffffa3be17b12b50
STATIC_DELTA:          44
ACTUAL_DELTA:          44
DELTA_MISMATCH:        0
[!] VULNERABILITY CONFIRMED: Monolithic KASLR defeated via relative offset!
```

#### Hardened / FG-KASLR (`fgkaslr`)
```text
Kernel cmdline: console=ttyAMA0 quiet panic=1 kaslr lab_test=test_fgkaslr fgkaslr=1
Boot Mode: FG-KASLR ENABLED via boot param (fgkaslr=1)
FGKASLR_STATUS:        ENABLED
LEAK_FUNC_ADDR:        0xffffd2fb3ed12b24
DEFAULT_TARGET_ADDR:   0xffffd2fb3ed12b50
ACTIVE_TARGET_ADDR:    0xffffd2fb3ed12b74
STATIC_DELTA:          44
ACTUAL_DELTA:          80
DELTA_MISMATCH:        36
ACTIVE_SLOT:           1
[-] Write returned error: Invalid argument (errno = 22)
[+] DEFENSE ACTIVE: FG-KASLR prevented offset calculation!
```

---

### 4.3 보안 메커니즘 비교 분석표

| 항목 | Monolithic KASLR (`nokaslr` 비교군 포함) | FG-KASLR (Function Granular KASLR) |
| :--- | :--- | :--- |
| **무작위화 단위** | 커널 `.text` 전체 단일 블록 | 개별 함수(Section) 단위 |
| **적용 슬라이드** | 단일 공통 오프셋 ($Slide$) | 함수별 독립 순서 셔플링 |
| **상대 거리 ($\Delta$)** | **상수(Constant)로 영구 고정** | **부팅마다 난수화되어 붕괴** |
| **단일 Infoleak 방어** | **완전 무력화** (1개 유출 시 전역 계산) | **완벽 방어** (다른 함수 주소 유추 불가) |
| **ROP 체이닝 방어** | 가젯 간 상대 거리가 유지되어 가젯 체이닝 용이 | 가젯들이 함수별로 분산되어 체이닝 파괴 |
| **성능 오버헤드** | 거의 0% (부팅 시 1회 오프셋 적용) | **약 1~3% 저하** (iTLB/BTB 캐시 미스) |
| **커널 인프라 영향** | 기존 툴체인/디버거 100% 호환 | `ftrace`, `livepatch`, `BPF` 충돌 |
| **메인라인 지위** | 공식 지원 (`CONFIG_RANDOMIZE_BASE`) | RFC 제안 $\rightarrow$ FineIBT / kCFI로 대체 발전 |

---

## 5. 성능 영향 및 보안 아키텍처 제언 (Trade-offs & Recommendations)

### 5.1 성능 및 엔지니어링 비용
- **iTLB 및 분기 타깃 버퍼(BTB) 스트레스**:
  - 함수 배치가 분산되면 CPU의 공간 지역성(Spatial Locality)이 파괴되어 명령어 페치 지연 증가.
- **바이너리 비대화**:
  - `-ffunction-sections` 빌드 시 ELF 섹션 헤더 및 재배치 테이블 엔트리가 수만 개 증가하여 빌드 시간 및 커널 크기 증가.

### 5.2 현대 보안 아키텍처에서의 시사점
- 단일 방어 기법에 의존하지 않는 **다층 방어(Defense in Depth)** 원칙의 중요성 입증:
  - KASLR의 단일 유출 취약점을 보완하기 위해 스택 소거(`STACKLEAK`), 메모리 다이렉트 매핑 무작위화(`CONFIG_RANDOMIZE_MEMORY`), 그리고 제어 흐름 무결성(kCFI/FineIBT)을 유기적으로 결합해야 함.

---

## 6. 부록 (Appendix)

### 6.1 영문 기술 발표 대본 (Technical Presentation Script)

> "Ladies and gentlemen, today we analyze FG-KASLR—Function Granular KASLR—and explore why modern security architectures evolved beyond monolithic randomization.
>
> Traditional KASLR shifts the entire kernel text using a single random slide. While this stops blind attacks using static addresses, it has a fatal flaw: the relative distance $\Delta$ between any two functions remains constant. If an attacker discovers a single memory leak, they can calculate the address of all ROP gadgets and critical functions with 100% precision.
>
> FG-KASLR was engineered to solve this by compiling functions into individual ELF sections and shuffling their order at boot time. As demonstrated in our lab, when an attacker attempts a relative offset jump after an infoleak, FG-KASLR breaks the expected delta, turning what would have been a successful exploit into an invalid branch or crash.
>
> While FG-KASLR was ultimately not merged into mainline Linux due to instruction TLB performance degradation and conflicts with ftrace and livepatching, its architectural principles laid the foundation for modern compiler-enforced Control Flow Integrity—such as Clang kCFI and hardware-assisted FineIBT."

### 6.2 보안 용어 사전 (Glossary)

- **FG-KASLR (Function Granular KASLR)**: 커널 함수 단위로 ELF 섹션을 나누어 부팅 시 배치 순서를 셔플링하는 세분화 무작위화 기술.
- **Monolithic KASLR**: 커널 텍스트 세그먼트 전체를 단 하나의 난수 슬라이드로 일괄 이동시키는 전통적인 KASLR 방식.
- **Relative Offset ($\Delta$)**: 두 함수 또는 가젯 사이의 메모리 거리 차이 ($Addr_B - Addr_A$).
- **iTLB (Instruction Translation Lookaside Buffer)**: 실행할 명령어의 가상 주소를 물리 주소로 초고속 변환하기 위한 CPU 내부 하드웨어 캐시.
- **BTB (Branch Target Buffer)**: 조건문 및 간접 분기 명령어의 분기 대상 주소를 예측하고 캐싱하는 CPU 마이크로아키텍처 구조.
- **kCFI (Kernel Control Flow Integrity)**: Clang 기반으로 간접 함수 호출 시 대상 함수의 타입 시그니처 해시를 런타임에 대조하여 분기 무결성을 강제하는 방어 기술.
