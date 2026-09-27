# Spectre v2: 간접 분기 예측 주입 및 Retpoline/IBPB 방어

## 1. 개요 및 배경

현대 프로세서는 함수 포인터 호출, 가상 함수 테이블(vtable), 인터페이스 디스패치 등 실행 시점에 목적지 주소가 결정되는 **간접 분기(Indirect Branch - `call *%rax`, `blr xN`)**의 파이프라인 지연을 없애기 위해 **분기 대상 버퍼(BTB: Branch Target Buffer)**를 운용함. BTB는 과거 간접 분기가 실행되었던 대상 주소를 캐싱하여, 다음 실행 시 실제 주소가 메모리나 레지스터로부터 로드되기 전에 목적지로 투기적(Speculative)으로 선행 점프함.

2018년 공개된 **Spectre Variant 2 (Branch Target Injection - CVE-2017-5715)**는 이러한 BTB의 하드웨어 공유 및 인덱싱 취약성을 악용함:
1. **BTB 엔트리 오염 (Branch Target Buffer Poisoning)**:
   - 다수의 프로세서에서 BTB는 가상 주소의 전체가 아닌 하위 비트(LSB)만을 해시하여 슬롯을 인덱싱함.
   - 비특권 공격자는 유저스페이스(EL0 / Ring 3)에서 커널의 간접 분기 주소와 동일한 하위 비트를 갖는 주소에서 간접 분기를 반복 실행하여, 커널 간접 분기 슬롯의 예측 대상을 공격자가 지정한 **희생자 가젯(Victim Gadget)**의 주소로 덮어씌움.
2. **간접 분기 대상 주입 (Branch Target Injection)**:
   - 공격자가 시스템 콜(예: `sys_write`, VFS 디스패치)을 호출하여 커널(EL1 / Ring 0)이 간접 분기문을 만나는 순간, CPU는 오염된 BTB를 참조하여 커널 내부의 희생자 가젯으로 투기적 분기를 감행함.
3. **부채널 캐시 상태 적재 및 비밀 탈취**:
   - 희생자 가젯은 커널 기밀 메모리를 로드하고 이를 인덱스로 삼아 2차 공유 배열(`probe_array[secret * 512]`)에 접근함.
   - 비투기적 실행 파이프라인이 실제 함수 포인터를 확인하여 분기를 롤백하더라도, 캐시 라인은 가열된 상태로 남아 공격자가 **Flush+Reload**를 통해 비밀 데이터를 복원함.

리눅스 커널은 컴파일러 기반의 **Retpoline(Return Trampoline)** 소프트웨어 트랩과 CPU 마이크로코드 기반의 **IBPB / STIBP**, 그리고 ARM64의 **CSV2 / BHB** 하드웨어 격리를 통해 이 공격을 완벽히 차단함.

---

## 2. 실세계 비유: 사기꾼의 고속도로 표지판 위조와 나들목 회전교차로

`Spectre v2`와 `Retpoline`의 원리는 **고속도로 갈림길의 사설 표지판 위조와 회전교차로 트랩**에 비유할 수 있음:

```
[ 취약한 방식 (Baseline: 오염 가능한 BTB 간접 분기) ]
  공격자: "고속도로 갈림길(간접 분기) 표지판을 몰래 '비밀 군사기지(가젯)'로 바꿔놓음!"
  커널 운전자: (내비게이션 확인이 지연되자 표지판만 믿고 급선회)
              ──► [비밀 군사기지로 투기 진입] ──► [타이어 자국(캐시 라인) 남김]
  내비게이션 확인 완료: "경로 이탈! 즉시 후진하여 본래 목적지로 복귀."
  공격자: "군사기지 진입로의 타이어 열기를 측정하여 군사 기밀 획득!"

[ 하드닝 방식 (Hardened: Retpoline 트램펄린) ]
  공격자: "갈림길 표지판을 위조해 둠!"
  커널 운전자: (위조 위험이 있는 표지판을 절대 보지 않고, 특수 회전교차로 나들목 진입)
              ──► [안전 트랩: 확인될 때까지 교차로 내부에서 헛돌기(pause; lfence)]
  내비게이션 확인 완료: "스택 봉투 개봉: 안전한 목적지로 비투기적 직진!"
  공격자: "군사기지 진입로는 아무도 밟지 않음 (0바이트 탈취 실패)!"
```

1. **전통적 커널 (위조 표지판 맹신)**:
   - 메모리로부터 목적지 함수 주소를 가져오는 데 수십~수백 사이클이 걸리므로, CPU는 유저 공간에서 사기꾼이 위조해 둔 BTB 표지판을 맹신하고 커널 비밀 가젯으로 투기 주행함.
   - 비록 나중에 잘못된 경로임을 깨닫고 차를 돌리더라도, 가젯 도로에 남겨진 열기(CPU 캐시 라인)는 지워지지 않아 비밀이 누출됨.
2. **Retpoline 적용 커널 (안전 회전교차로 트랩)**:
   - 위험한 BTB 표지판을 완전히 무시하고, `ret` 명령어 전용 안전 회전교차로(RSB 무한 루프)로 차를 몰아넣음.
   - 실제 주소가 확인될 때까지 투기적 엔진은 `pause; lfence` 루프에서 안전하게 공회전하며, 주소가 메모리 스택에 도달하는 즉시 정규 목적지로 안전하게 진출함.

---

## 3. 핵심 아키텍처 및 방어 메커니즘

### 3.1 Retpoline (Return Trampoline) 어셈블리 동작 원리

Google의 Paul Turner가 개발한 Retpoline은 분기 예측기가 `ret` 명령어를 예측할 때 BTB 대신 **리턴 스택 버퍼(RSB: Return Stack Buffer)**를 사용한다는 점을 역이용함:

```x86asm
/* x86_64 Retpoline Trampoline 구조 (__x86_indirect_thunk_rax) */
.global __x86_indirect_thunk_rax
__x86_indirect_thunk_rax:
    call 2f                 /* 1단계: RSB와 스택에 레이블 1의 주소를 푸시 */
1:
    pause                   /* 2단계: RSB를 참조한 투기적 엔진이 갇히는 무한 루프 */
    lfence
    jmp 1b
2:
    pushq %rax              /* 3단계: 스택 슬롯에 실제 목적지 주소(%rax)를 덮어씀 */
    ret                     /* 4단계: 비투기적으로 %rax 목적지로 점프 */
```

- **1단계 (`call 2f`)**: CPU는 `2f`로 분기하면서 리턴 주소(`1: pause; lfence; jmp 1b`)를 하드웨어 RSB와 메모리 스택에 동시에 푸시함.
- **2단계 & 3단계**: `2f`에서 실제 가고자 하는 함수 주소(`%rax`)를 스택 상단에 기록함.
- **4단계 (`ret`)**:
  - **투기적 실행(Speculative Path)**: CPU의 투기 파이프라인은 RSB에 들어있던 `1:`을 읽어와 `pause; lfence` 루프를 반복 실행하며 안전하게 멈춤(Stall/Trap).
  - **비투기적 실행(Architectural Path)**: 메모리 버스로부터 스택 상단의 진짜 타깃 주소(`%rax`)를 읽어와 안전하게 해당 목적지로 점프함.
  - **결과**: 공격자가 조작해 둔 악성 BTB 엔트리는 하드웨어적으로 **단 한 번도 참조되지 않음**.

### 3.2 하드웨어 기반 방어 기법 (IBPB, STIBP, eIBRS)

소프트웨어 트램펄린 외에도 현대 CPU와 커널은 다층 하드웨어 방어선을 구축함:

1. **IBPB (Indirect Branch Prediction Barrier)**:
   - 하드웨어 MSR(`IA32_PRED_CMD`, bit 0)에 1을 기록하여 BTB 내부의 모든 분기 예측 상태를 일괄 플러시함.
   - 리눅스 커널은 다른 유저 프로세스로 문맥 교환(Context Switch)이 일어날 때 IBPB를 발행하여, 이전 프로세스가 남겨둔 BTB 오염이 다음 프로세스에 영향을 주지 못하도록 격리함.
2. **STIBP (Single Thread Indirect Branch Predictors)**:
   - MSR(`IA32_SPEC_CTRL`, bit 1)을 설정하여, 동일한 물리 코어에서 하이퍼스레딩(SMT)으로 실행되는 형제 논리 코어 간의 BTB 교차 오염을 방지함.
3. **eIBRS (Enhanced Indirect Branch Restricted Speculation)**:
   - Intel 9세대 및 AMD Zen 3 이후 프로세서에서 지원되며, Ring 0(커널 모드) 진입 시 자동으로 유저 공간(Ring 3)에서 훈련된 BTB 예측을 완전히 배제함.

### 3.3 ARM64 아키텍처 특화 완화책

- **CSV2 (ID_AA64PFR0_EL1.CSV2)**: 하드웨어적으로 예외 레벨(EL) 간의 BTB 공유를 격리하여 EL0가 EL1 간접 분기를 오염시키지 못하도록 보장함.
- **SMCCC_ARCH_WORKAROUND_1**: EL1 커널 진입 시 PSCI 펌웨어 호출을 통해 하드웨어 분기 예측기를 클리어함.
- **Spectre-BHB (Branch History Buffer 완화)**: 분기 이력 레지스터를 루프로 순환 소거하여 이력 조작 공격을 원천 무력화함.

---

## 4. 인터랙티브 아키텍처 시뮬레이터

Spectre v2 간접 분기 예측 주입 공격과 Retpoline 트램펄린에 의한 RSB 무한 루프 격리 과정을 시뮬레이션한 대화형 다이어그램임:

<iframe src="../../assets/diagrams/spectrev2/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. 실습 및 공격/방어 시연

### 5.1 취약점 실습 드라이버 (`vuln_spectrev2.c`)

`/proc/vuln_spectrev2` (모드 0666) 인터페이스를 통해 다음 실습 기능을 제공함:
- **상태 및 하드웨어 취약점 보고 (`cat /proc/vuln_spectrev2`)**:
  - 타깃 CPU 아키텍처 및 Retpoline 어셈블리 트랩 구조 정보 출력.
  - 현재 활성 모드: `[0] Baseline (Vulnerable Raw Indirect Call)` vs `[1] Hardened (Retpoline / IBPB)`.
  - 간접 분기 총 호출 횟수, 가젯 탈취 탐지 횟수, 방어 차단 통계 출력.
- **모드 제어 명령**:
  - `echo 'mode baseline' > /proc/vuln_spectrev2`: 무방비 원시 간접 분기 활성화.
  - `echo 'mode hardened' > /proc/vuln_spectrev2`: Retpoline 트램펄린 방어 활성화.
- **간접 분기 실행 트리거**:
  - `echo 'dispatch <arg>' > /proc/vuln_spectrev2`: 커널 내부 간접 함수 포인터 디스패치 수행.
- **유저스페이스 캐시 프로브 매핑 (`mmap`)**:
  - 128KB 프로브 배열을 유저 가상 주소에 매핑하여, 비특권 프로세스가 직접 희생자 가젯 실행 여부를 계측할 수 있도록 지원함.

### 5.2 비특권 사용자 BTI 익스플로잇 PoC (`exploit.c`)

비특권 일반 사용자 `lab` (UID 1000) 권한으로 구동됨:
1. **BTB 오염 및 간접 분기 트리거**:
   - 커널 내부 간접 분기 호출 시점을 노려 가젯 오프셋 주입.
2. **결과 분석 및 판정**:
   - **Baseline 모드**:
     - 원시 간접 분기가 BTB 오염으로 인해 희생자 가젯(`victim_spectre_gadget`)으로 투기 분기함.
     - 기밀 문자열(`FLAG`)의 바이트가 프로브 배열에 기록되어 유출 성공 판정 (`[FAIL/VULNERABLE]`).
   - **Hardened 모드**:
     - Retpoline 트램펄린이 투기적 실행을 RSB 루프에 가두고, 오직 합법적 안전 핸들러(`safe_target_function`)만 비투기적으로 실행됨.
     - 희생자 가젯은 단 한 번도 실행되지 않고 0바이트 누출 달성 (`[PASS/PROTECTED]`).

---

## 6. 검증 및 결과 분석

### 6.1 인게스트 자동화 테스트 실행

```bash
# Spectre v2 자동화 테스트 실행
/bin/test_spectre_v2
```

### 6.2 sysfs 취약점 진단 인터페이스 확인

```bash
cat /sys/devices/system/cpu/vulnerabilities/spectre_v2
# x86_64: Mitigation: Retpolines, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling
# arm64 : Mitigation: CSV2, BHB
```

### 6.3 듀얼 아키텍처 QEMU 4개 시나리오 검증 매트릭스

| 시나리오 | 아키텍처 | 동작 모드 | 가젯 투기 탈취 여부 | 최종 판정 |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | ARM64 | Mode 1 (Hardened) | 0건 (CSV2/BHB 배리어 차단) | **PASS (Protected)** |
| **Scenario 2** | ARM64 | Mode 0 (Baseline) | 가젯 탈취 및 비밀 유출 확인 | **VULNERABLE (Demonstrated)** |
| **Scenario 3** | x86_64 | Mode 1 (Hardened) | 0건 (Retpoline RSB 루프 트랩) | **PASS (Protected)** |
| **Scenario 4** | x86_64 | Mode 0 (Baseline) | 가젯 탈취 및 비밀 유출 확인 | **VULNERABLE (Demonstrated)** |

