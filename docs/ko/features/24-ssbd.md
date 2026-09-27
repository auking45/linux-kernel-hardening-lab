# Spectre v4: 투기적 스토어 바이패스 방어 (SSBD - Speculative Store Bypass Disable)

## 1. 개요 및 배경

현대 고성능 슈퍼스칼라 CPU는 메모리 접근 지연시간을 은폐하기 위해 명령어를 순서대로 실행하지 않고 준비된 명령어부터 먼저 처리하는 **비순차적 명령어 처리(Out-of-Order Execution)**와 **메모리 비모호화(Memory Disambiguation)** 기법을 채택함.

2018년 공개된 **Spectre Variant 4 (Speculative Store Bypass - CVE-2018-3639)**는 이러한 메모리 비모호화 예측 엔진의 투기적(Speculative) 순서 역전 현상을 악용하여 메모리의 기밀 데이터를 유출하는 하드웨어 취약점임:
1. **스토어 버퍼 지연(Store Buffer Delay)**:
   - 선행 Store 명령어(`*ptr_x = safe_val`)가 발행되었으나 복잡한 포인터 연산이나 TLB/L1D 캐시 미스로 인해 목적지 주소(`ptr_x`) 계산이 지연될 경우, Store 데이터는 CPU 내부의 스토어 버퍼(Store Buffer)에서 대기함.
2. **투기적 스토어 바이패스(Speculative Store Bypass)**:
   - 파이프라인의 후행 Load 명령어(`val = *ptr_y`)가 대기 중일 때, CPU의 **메모리 비모호화 예측기(Memory Disambiguator)**는 과거 패턴에 기반하여 `ptr_x`와 `ptr_y`가 서로 다른 메모리 주소(No Aliasing)일 것으로 추측함.
   - 이에 따라 Store 완료를 기다리지 않고 Load 명령어를 선행 Store보다 앞서 투기적으로 먼저 실행(Bypass)함.
3. **이전 비밀 데이터(Stale Data) 투기 적재 및 부채널 누출**:
   - 만약 실제 런타임에 두 포인터가 동일한 메모리(`ptr_x == ptr_y`)를 가리키고 있었다면, Load 명령어는 새로 갱신될 `safe_val` 대신 메모리 슬롯에 남아있던 **이전의 비밀 데이터(Stale Secret Data)**를 읽어들임.
   - 이 투기적 값(`val`)은 캐시 프로브 배열(`probe_array[val * 512]`)의 특정 라인을 캐시에 적재하는 데 사용됨.
   - 이후 Store 주소가 확정되어 별칭 충돌(Hazard)이 감지되면 CPU는 투기적 레지스터 상태를 롤백하지만, **L1D 캐시에 워밍업된 태그 상태는 그대로 유지**되어 공격자가 **Flush+Reload** 시간차 측정으로 기밀 바이트를 완벽히 복원함.

리눅스 커널은 CPU 벤더의 하드웨어 레지스터(x86 MSR `IA32_SPEC_CTRL`, ARM64 `PSTATE.SSBS`), 시스템 콜 인터페이스(`prctl`), 그리고 메모리 직렬화 배리어(`lfence`, `dsb sy; isb`)를 결합하여 이 공격을 차단함.

---

## 2. 실세계 비유: 우편함 주소 확인 전의 성급한 옛 편지 낭독

`Spectre v4 (SSBD)`의 메커니즘은 **우편함 덮어쓰기와 성급한 비서의 이전 편지 낭독**에 비유할 수 있음:

```
[ 취약한 방식 (Baseline: 메모리 비모호화 투기적 바이패스 허용) ]
  보안 관리자: "우편함 번호 계산이 끝나는 대로 새 안전 안내문(safe_val)을 넣으시오! (Store 대기)"
  성급한 비서: "우편함 번호 계산을 기다리기 귀찮으니, 저쪽 우편함과 이 우편함은 서로 다른 번호일 거야! (No Alias 예측)"
              ──► [새 편지가 들어가기 전에 우편함을 열어 이전 비밀 편지(Stale Secret)를 꺼내 읽음]
              ──► [비밀 편지 내용에 따라 벽에 형광 표시(캐시 라인 워밍업)를 남김]
  보안 관리자: "계산 완료! 같은 우편함이었잖아! 당장 비서의 기억을 지우고 새 안내문을 넣어라! (파이프라인 롤백)"
  공격자: "비서의 기억은 지워졌지만 벽에 남은 형광 자국(캐시)을 보고 비밀 편지 내용 완벽 복원!"

[ 하드닝 방식 (Hardened: SSBD 비활성화 레지스터 및 메모리 배리어) ]
  보안 관리자: "SSBD 규칙 발효! 우편함 번호가 확정될 때까지 비서는 절대 우편함을 열지 마라!"
  신중한 비서: (비모호화 투기를 멈추고 우편함 주소 계산이 끝날 때까지 얌전히 대기 - Forced Stall)
              ──► [새 안전 안내문(safe_val)이 우편함에 완벽히 투입된 후 꺼냄]
              ──► [벽에 남는 표시는 오직 안전 안내문 번호뿐 (비밀 편지는 접근조차 못 함)]
  공격자: "형광 표시는 100% 안전 안내문뿐 (비밀 유출 0바이트 실패)!"
```

1. **전통적 커널 (성급한 바이패스)**:
   - 메모리 접근 처리량을 극대화하기 위해 선행 Store 주소 계산이 지연되면 후행 Load를 무조건 먼저 실행함.
   - 동일 주소 충돌 시 아키텍처 상태는 롤백되지만, 마이크로아키텍처 캐시 변조로 인해 기밀이 노출됨.
2. **SSBD 적용 커널 (안전 직렬화 강제)**:
   - Store 주소가 확정되어 스토어 버퍼가 안전하게 커밋되거나 별칭 여부가 명백해질 때까지 Load 파이프라인을 강제로 대기(Stall)시킴.
   - 따라서 Load는 반드시 최신의 안전한 데이터만을 읽게 되며, 이전 기밀 바이트에 대한 어떠한 투기적 접근도 발생하지 않음.

---

## 3. 핵심 아키텍처 및 방어 메커니즘

### 3.1 Store Buffer와 Memory Disambiguation의 하드웨어 동작

```
+--------------------------------------------------------------------------------+
|                         CPU Execution Pipeline                                 |
|                                                                                |
|  [ Store: *ptr_x = safe_val ]               [ Load: val = *ptr_y ]             |
|                |                                       |                       |
|                v                                       v                       |
|     +---------------------+               +-------------------------+          |
|     |    Store Buffer     |               |  Memory Disambiguator   |          |
|     |  Address: PENDING.. |               |  Prediction: NO ALIAS   |          |
|     |  Data:    0x55      |               +-------------------------+          |
|     +---------------------+                            |                       |
|                | (Delayed)                             v (Speculative Bypass)  |
|                |                           +------------------------+          |
|                |                           | Speculative Load Exec  |          |
|                |                           | Reads STALE Secret!    |          |
|                |                           +------------------------+          |
|                |                                       |                       |
|                v                                       v                       |
|     +---------------------------------------------------------------+          |
|     |              L1 Data Cache / Main Memory Slot                 |          |
|     |  [Physical Slot]: 0x46 ('F') =====> 0x55 (Safe)               |          |
|     +---------------------------------------------------------------+          |
+--------------------------------------------------------------------------------+
```

1. **Store Buffer (스토어 버퍼)**:
   - CPU가 메모리에 데이터를 기록할 때, 버스 대기시간 동안 파이프라인이 멈추지 않도록 기록 대기 큐(Store Buffer)에 값을 임시 보관함.
2. **Store-to-Load Forwarding (스토어-투-로드 포워딩)**:
   - Load 명령어의 주소가 Store Buffer에 대기 중인 엔트리의 주소와 일치하면, L1D 캐시까지 가지 않고 스토어 버퍼에서 즉시 데이터를 전달받음.
3. **Memory Disambiguation 예측기**:
   - Store Buffer 엔트리의 목적지 주소가 아직 계산되지 않았을 때(예: 이전 계산 명령어가 지연 중), Load가 Store Buffer를 기다릴지 통과할지를 예측함.
   - 예측기가 통과(Bypass)를 결정하면 투기적 스토어 바이패스가 발생하여 구버전의 메모리 값이 로드됨.

---

### 3.2 x86_64 하드웨어 SSBD 완화 메커니즘

Intel 및 AMD x86_64 프로세서는 마이크로코드 업데이트를 통해 하드웨어 제어 MSR을 추가함:

1. **MSR `IA32_SPEC_CTRL` (0x48)**:
   - **Bit 2 (`SPEC_CTRL_SSBD`)**:
     - `0`: Speculative Store Bypass 허용 (기본 고속 모드).
     - `1`: Speculative Store Bypass 금지 (SSBD 활성화).
     - Bit 2가 1로 설정되면 CPU 코어의 메모리 비모호화 예측기가 완전히 꺼지며, Store 주소가 확인될 때까지 의존 가능성이 있는 모든 Load가 대기함.
2. **MSR `IA32_ARCH_CAPABILITIES` (0x10A)**:
   - **Bit 4 (`SSB_NO`)**: CPU가 하드웨어적으로 Speculative Store Bypass에 취약하지 않음을 나타냄 (신형 프로세서).
3. **CPU 부팅 커맨드라인**:
   - `spec_store_bypass_disable=on`: 커널 및 유저 공간 전체에 SSBD 상시 활성화.
   - `spec_store_bypass_disable=prctl`: 기본적으로 해제하되 프로세스가 `prctl`로 활성화 가능 (리눅스 기본값).
   - `spec_store_bypass_disable=seccomp`: 샌드박싱된 seccomp 스레드에 한해 자동으로 SSBD 활성화.
   - `spec_store_bypass_disable=off`: 모든 완화 비활성화.

---

### 3.3 ARM64 하드웨어 SSBD 및 PSTATE.SSBS

ARMv8.5-A 및 ARMv8.0 완화 확장에서는 PSTATE와 시스템 레지스터를 통해 SSBD를 통제함:

1. **`PSTATE.SSBS` (Speculative Store Bypass Safe) 비트**:
   - `PSTATE.SSBS == 0`: Speculative Store Bypass 비활성화 (보안 모드).
   - `PSTATE.SSBS == 1`: Speculative Store Bypass 활성화 (성능 모드).
   - ARM64 명령어 `msr ssbs, #0` 또는 `msr ssbs, #1`을 통해 각 스레드가 직접 제어 가능.
2. **SMCCC v1.1 펌웨어 워크어라운드 (`ARM_SMCCC_ARCH_WORKAROUND_2`)**:
   - 하드웨어 SSBS 비트가 없는 ARMv8 코어의 경우, EL3 Secure Monitor 또는 EL2 하이퍼바이저 펌웨어 호출(SMC/HVC)을 통해 코어별 비모호화 우회 동작을 비활성화함.
3. **ARM64 부팅 커맨드라인**:
   - `ssbd=force-on`: 모든 EL0/EL1에서 SSBD 강제 활성화.
   - `ssbd=kernel`: 커널 공간(EL1) 진입 시에만 SSBD 활성화.
   - `ssbd=force-off`: SSBD 완화 비활성화.

---

### 3.4 소프트웨어 직렬화 배리어 (LFENCE / DSB)

하드웨어 MSR/SSBS 제어가 지원되지 않거나 국소적인 핫스팟 코드에서 투기 우회를 방지해야 할 경우, 파이프라인 직렬화 명령어를 직접 삽입함:

```c
// x86_64 소프트웨어 완화:
*slot = safe_value;
asm volatile("lfence" ::: "memory"); // 후행 Load가 Store 완료 전에 실행되는 것 차단
val = *slot;

// ARM64 소프트웨어 완화:
*slot = safe_value;
asm volatile("dsb sy\n\tisb" ::: "memory"); // 데이터 동기화 및 명령어 동기화 배리어
val = *slot;
```

---

### 3.5 리눅스 커널 유저 공간 통제 인터페이스 (`prctl`)

리눅스 커널은 비특권 프로세스가 자기 자신 또는 자식 스레드의 투기 실행 방어를 통제할 수 있도록 `prctl(2)` 인터페이스를 제공함:

```c
#include <sys/prctl.h>

// 1. 현재 프로세스의 SSBD 상태 조회
int status = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

// 2. 현재 스레드의 투기적 스토어 바이패스 비활성화 (보안 강화)
prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);

// 3. 비활성화 영구 고정 (이후 다시 활성화 불가, seccomp 샌드박스에서 필수)
prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE, 0, 0);
```

---

## 4. 인터랙티브 아키텍처 시뮬레이터

Spectre v4 투기적 스토어 바이패스와 하드웨어 SSBD 레지스터 및 메모리 직렬화 배리어에 의한 방어 과정을 시각화한 대화형 다이어그램임:

<iframe src="../../assets/diagrams/ssbd/architecture.html" width="100%" height="700px" style="border: 1px solid var(--card-border); border-radius: 8px; margin: 16px 0; background: #0b132b;"></iframe>

---

## 5. 실습 환경 및 검증 시나리오

본 실습 모듈(`labs/24-ssbd`)은 커널 드라이버와 비특권 PoC 익스플로잇을 통해 투기적 스토어 바이패스의 취약성과 SSBD 방어를 실증함.

### 5.1 타깃 드라이버 (`/proc/vuln_ssbd`)

- **파일 위치**: `labs/24-ssbd/vuln_ssbd.c`
- **인터페이스**:
  - `echo 'mode baseline' > /proc/vuln_ssbd`: Mode 0 (SSB 허용 / 취약 모드) 전환.
  - `echo 'mode hardened' > /proc/vuln_ssbd`: Mode 1 (SSBD 활성화 / 직렬화 모드) 전환.
  - `echo 'trigger <offset>' > /proc/vuln_ssbd`: 특정 비밀 오프셋에 대해 스토어 바이패스 사이클 실행.
  - `echo 'run_bench' > /proc/vuln_ssbd`: 인커널 자체 벤치마크 및 검증 루틴 수행.
  - `mmap()`: 128KB 2차 프로브 배열을 유저 공간에 매핑하여 Flush+Reload 캐시 관측 허용.

### 5.2 비특권 익스플로잇 PoC (`labs/24-ssbd/exploit.c`)

비특권 계정 `lab` (UID 1000)에서 실행되며, 두 단계에 걸쳐 방어 유효성을 검증함:

```bash
# QEMU 가상머신 내 자동화 검증 스크립트 실행
/bin/test_ssbd
```

1. **Phase 1: Baseline 모드 (Mode 0 - SSB 허용)**:
   - 메모리 슬롯에 이전 비밀 데이터(`FLAG{...}`)가 남아있는 상태에서 새 안전 데이터(`0x55`)를 기록하는 Store 발행.
   - 비모호화 예측기가 후행 Load를 투기적으로 선행 실행하여 Stale Secret 바이트를 취득.
   - 프로브 캐시 라인 가열을 확인하여 `[FAIL/VULNERABLE] In Baseline mode, Speculative Store Bypass leaked stale data!` 진단.
2. **Phase 2: Hardened 모드 (Mode 1 - SSBD 활성화)**:
   - SSBD 하드웨어 제어 및 메모리 직렬화 배리어가 활성화됨.
   - Store가 메모리에 안전하게 커밋될 때까지 Load가 대기함.
   - 오직 갱신된 안전 데이터(`0x55`)만이 적재되며 비밀 바이트는 단 1바이트도 캐시에 남지 않음.
   - `[PASS/PROTECTED] SSBD successfully prevented speculative store bypass!` 판정.

---

## 6. 방어 기법 및 아키텍처 비교 매트릭스

| 비교 항목 | Baseline (취약) | x86_64 SSBD (MSR) | ARM64 SSBD (PSTATE.SSBS) | Software Barrier (LFENCE) |
| :--- | :--- | :--- | :--- | :--- |
| **방어 메커니즘** | 투기적 바이패스 허용 | MSR 0x48 bit 2 강제 세팅 | PSTATE.SSBS=0 레지스터 제어 | Store-Load 사이 직렬화 배리어 |
| **하드웨어 요구** | 기존 하드웨어 | 마이크로코드 업데이트 필요 | ARMv8.5-A 또는 SMCCC 펌웨어 | 표준 명령어 지원 전 기종 |
| **유저 공간 제어** | `PR_SPEC_ENABLE` | `prctl(PR_SPEC_STORE_BYPASS)` | `prctl(PR_SPEC_STORE_BYPASS)` | 소스코드 재컴파일 필요 |
| **성능 영향** | 0% (최대 성능) | 약 2% ~ 8% 저하 | 약 1% ~ 5% 저하 | 해당 루프 국소적 수십 사이클 지연 |
| **sysfs 표기** | `Vulnerable` | `Mitigation: Speculative Store Bypass...` | `Mitigation: Speculative Store Bypass...` | 하드웨어 미지원 시 취약 표기 |

---

## 7. 참고 문헌

- [Kernel Documentation: Speculative Store Bypass](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/speculative-store-bypass.html)
- [Intel Analysis of Speculative Store Bypass (CVE-2018-3639)](https://software.intel.com/security-software-guidance/insights/deep-dive-speculative-store-bypass)
- [Arm Speculative Processor Vulnerability: Speculative Store Bypass](https://developer.arm.com/Arm%20Security%20Center/Speculative%20Processor%20Vulnerability)
- [Linux prctl(2) Speculation Control Interface](https://man7.org/linux/man-pages/man2/prctl.2.html)

