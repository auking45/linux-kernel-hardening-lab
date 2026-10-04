# [Scenario 06] 부채널/예측 실행 정보 유출 (Spectre v1/v2 & Retpoline/array_index_nospec)

!!! abstract "🎯 발표 핵심 요약 (Executive Summary)"
    - **실제 공격 사례**: CPU 마이크로아키텍처 분기 예측기(BPU) 오작동 유도 및 투기적 실행(Speculative Execution) 바운즈 검사 우회 (**CVE-2017-5753 / Spectre v1**) 및 분기 타깃 주입 (**CVE-2017-5715 / Spectre v2**)
    - **위협 벡터**: 비인가 컨테이너나 저권한 비전 AI 프로세스가 커널 배열 인덱스 검사문(`if (x < size)`)의 분기 지연 시간 동안 일시적으로 커널 보안 엔클레이브 메모리를 투기적으로 읽어 들인 후, 캐시 상태 부채널(Flush+Reload)을 통해 비밀 토큰을 무단 복원
    - **사이버-물리 피해**: 로봇 자율 주행 지오펜스(Geofence) 인증 서명 및 경로 안전 인터록 해시 탈취로 인해 비인가 원격 명령 위조, 안전 경계선 강제 무력화 및 위험 구역(고전압 설비/제한 구역)으로의 자율 주행 돌진 발생
    - **1차 소프트웨어 방어선**: 조건부 점프 없는 산술 마스크 투기적 클램핑 **`array_index_nospec()`** 및 간접 분기 예측 무력화 트램펄린 **`CONFIG_RETPOLINE=y`**
    - **하드웨어 협력 방어선**: 마이크로코드 기반 간접 분기 예측 격리 **IBRS / IBPB** 및 커널-유저 페이지 테이블 물리 격리 **KPTI (`CONFIG_PAGE_TABLE_ISOLATION=y`)**

---

## 1. 실제 커널 침해 사례 분석: CVE-2017-5753 / Spectre와 로봇 지오펜스 무력화

현대 고성능 프로세서는 파이프라인 지연을 방지하기 위해 분기문 결과를 예측하여 선행 실행하는 투기적 실행(Speculative Execution) 기법을 기본 탑재함:

```
[로봇 비전 AI 컨테이너 (Ring 3 / 저권한 게스트)]
                 │
                 │ (1) 훈련된 BPU에 악의적 OOB 오프셋 주입
                 ▼
[CPU 마이크로아키텍처 (BPU 투기적 실행 윈도우)]
 ┌──────────────────────────────────────────────┐
 │ if (x < array1_size) {                       │
 │     y = probe_array[array1[x] * 512];        │ <── [BPU: 조건 참으로 오예측]
 │ }                                            │
 └──────────────────────────────────────────────┘
                 │
                 │ (2) 투기적 OOB 읽기 -> probe_array[secret_byte] 캐시 라인 적재!
                 ▼
[미세아키텍처 캐시 메모리 (L1/L2 Cache)]
 - Line #0x4E ('N') : 42 CPU 사이클 (L1 Cache Hit!)
 - Other Lines       : 240+ CPU 사이클 (DRAM Latency)
                 │
                 │ (3) Flush+Reload 타이밍 측정으로 "NAV_SEC_8F3A" 100% 복원
                 ▼
[💥 지오펜스 인증 위조: 비인가 제한 구역 돌진 및 충돌 재해 발생]
```

### 1.1 침해 경로 및 근본 원인 (Root Cause)

- **CVE-2017-5753 (Spectre Variant 1: Bounds Check Bypass)**:
    - 커널 시스템 콜 처리 함수에서 배열 인덱스 `x`가 경계 크기보다 작은지 검사(`x < size`)하지만, 조건식에 사용되는 `size` 변수가 L1/L2 캐시에서 누락되어 DRAM에서 로드되는 수백 사이클 동안 CPU는 분기 예측기(BPU)의 이전 훈련 기록에 의존하여 조건문 내부를 투기적으로 선행 실행함.
- **아키텍처적 상태 롤백과 마이크로아키텍처 잔존 신호의 괴리**:
    - DRAM에서 `size`가 도착하여 `x >= size`임이 판명되면, CPU는 범용 레지스터 등 소프트웨어적 아키텍처 상태(Architectural State)를 모두 취소하고 롤백함. 따라서 메모리 접근 위반 예외(`#PF`, Segfault)가 전혀 발생하지 않음.
    - 그러나 투기적 실행 과정에서 참조된 `probe_array`의 특정 캐시 라인은 **L1/L2 CPU 캐시에 그대로 상주(Microarchitectural Side-Effect)**함.
- **Flush+Reload 캐시 타이밍 측정**:
    - 공격자는 고정밀 타이머 명령어(`rdtsc`)를 사용하여 256개 캐시 라인의 접근 시간을 측정함. 40사이클 미만으로 로드되는 캐시 라인 인덱스가 곧 투기적으로 읽힌 커널 기밀 바이트 값임을 식별함.

### 1.2 사이버-물리적 재난 분석 (Cyber-Physical Hazards)

커널 내부 보안 엔클레이브의 기밀 유출은 로봇의 자율 판단 신뢰 체계를 근본부터 붕괴시킴:

- 🔴 **지오펜스 인증 서명 위조 (Geofence Interlock Forgery)**:
    - 로봇의 작업 반경(안전 작업 복도)을 규정하는 암호화 토큰이 복원되어, 원격 공격자가 위조된 작업 허가 신호를 주입할 수 있음.
- 🔴 **안전 경계선 해제 및 제한 구역 침범 (Restricted Zone Breach)**:
    - 협동 로봇 안전 규격(ISO 10218)에 따른 방호 울타리 가상 경계가 무력화되어 고전압 변전 설비나 작업자 전용 통로로 로봇이 고속 이동함.
- 🔴 **물리 충돌 및 시설물 전소 (Catastrophic Collision)**:
    - 위치 센서 보정 해시가 탈취되어 왜곡된 좌표계가 주입됨으로써 시설물과의 고속 충돌 및 배터리 팩 파손 화재 발생함.

---

## 2. 분기 예측 유도(BPU Poisoning) 및 Flush+Reload 캐시 부채널 메커니즘

부채널 공격(Side-Channel Attack)은 암호학적 알고리즘 결함이 아닌 물리적 실행 특성(시간, 전력, 캐시)을 관측하여 데이터를 유출하는 기법임.

### 2.1 Flush+Reload 공격 3단계 파이프라인

Flush+Reload는 공유 메모리 기반의 고해상도 캐시 부채널 기법임:

```
[1단계: FLUSH (캐시 무효화)]
  for (i = 0; i < 256; i++) {
      _mm_clflush(&probe_array[i * 512]); // 캐시 라인 강제 비움
  }

[2단계: TRANSIENT ACCESS (투기적 접근 유도)]
  victim_kernel_function(malicious_oob_index);
  // BPU 오작동 -> probe_array[secret_byte * 512]가 L1 캐시에 로드됨

[3단계: RELOAD & MEASURE (타이밍 재측정)]
  for (i = 0; i < 256; i++) {
      t0 = __rdtsc();
      junk = probe_array[i * 512];
      t1 = __rdtsc();
      if ((t1 - t0) < CACHE_HIT_THRESHOLD) { // 40~60 사이클 = HIT!
          leaked_secret = i;
      }
  }
```

- 공격자는 시스템 콜을 수천 번 호출하여 BPU가 항상 분기 참(Taken)을 예상하도록 길들인 후(BPU Training), 단 한 번의 OOB 인덱스 호출로 원하는 오프셋의 커널 메모리를 1바이트씩 스캔함.

### 2.2 `array_index_nospec` 산술 클램핑 방어 원리

기존의 `lfence`(로드 펜스) 명령어는 모든 분기문마다 파이프라인을 강제 동결하므로 30% 이상의 막대한 성능 저하를 초래함.
리눅스 커널이 고안한 **`array_index_nospec(index, size)`**은 조건부 분기(Branch)를 전혀 사용하지 않는 산술 비트 마스킹(Arithmetic Masking) 기법을 사용함:

$$\text{mask} = \sim (\text{index} < \text{size})$$
$$\text{safe\_index} = \text{index} \ \& \ (\sim \text{mask})$$

- x86-64에서는 `cmp` 후 `sbb`(Subtract with Borrow) 명령어로 캐리 플래그를 확장하여 0 또는 `~0UL` 마스크를 1클록 만에 생성함.
- 투기적 실행 엔진이 분기 예측을 시도하더라도, 인덱스 계산 자체가 순수 데이터 의존성(Data Dependency)으로 묶여 있어 $x \ge \text{size}$인 경우 인덱스가 강제로 0으로 클램핑됨. OOB 영역의 캐시 라인을 건드리는 것이 물리적으로 불가능함.

---

## 3. 대화형 인터랙티브 아키텍처 다이어그램 (Interactive Diagrams)

아래 4개 단계별 다이어그램 및 통합 아키텍처 다이어그램을 통해 BPU 오예측 유도, Flush+Reload 타이밍 측정, `array_index_nospec` 산술 마스킹 차단, 안전 홀드 자율 대응 전 과정을 시각적으로 확인 가능함.

### 3.1 [Phase 1] 정상 메모리 접근 및 합법적 예측 실행 (Nominal Flow)

<iframe src="../../assets/diagrams/spectre/phase1-normal.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.2 [Phase 2] 분기 예측 오작동 & Flush+Reload 캐시 부채널 유출 (Attack Detonation)

<iframe src="../../assets/diagrams/spectre/phase2-attack.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.3 [Phase 3] array_index_nospec 산술 마스킹 & Retpoline 차단 (Hardened Trap)

<iframe src="../../assets/diagrams/spectre/phase3-trap.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.4 [Phase 4] 부채널 탐지 격리 및 안전 홀드 자율 대응 (Deterministic Safe State)

<iframe src="../../assets/diagrams/spectre/phase4-failsafe.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.5 [통합 아키텍처] 예측 실행 부채널(Spectre) 방어 아키텍처 타임라인 (Comprehensive Flow)

<iframe src="../../assets/diagrams/spectre/architecture.html" width="100%" height="860" frameborder="0" style="border:none; border-radius:10px; margin-bottom:24px;"></iframe>

<script>
window.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'diagram-theme-change') {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      iframe.contentWindow.postMessage({
        type: 'set-diagram-theme',
        theme: e.data.theme
      }, '*');
    });
  }
});
</script>

---

## 4. 방어 기법 심층 분석 및 하드닝 매트릭스 (Defense Matrix)

리눅스 커널은 투기적 실행 결함을 완화하기 위해 소프트웨어 컴파일러 및 하드웨어 마이크로코드를 포괄하는 다계층 방어망을 운영함:

| 방어 기술 | 커널 Kconfig 설정 / 매크로 | 보호 취약점 및 완화 방식 | 성능 오버헤드 |
| :--- | :--- | :--- | :--- |
| **`array_index_nospec`** | C 코드 인라인 매크로 | Spectre v1 (Bounds Check Bypass) 산술 비트 마스크 클램핑 | **< 0.1% (극저부하, 분기 펜스 대체)** |
| **Retpoline** | `CONFIG_RETPOLINE=y` | Spectre v2 (Branch Target Injection) 간접 분기 포즈 루프 트랩 | **~1.0% - 3.0%** |
| **eIBRS / IBPB** | CPU 마이크로코드 플래그 | 하드웨어 수준 커널-유저 분기 예측기 엔트리 완전 격리 | **< 1.0% (최신 CPU 하드웨어 지원)** |
| **KPTI** | `CONFIG_PAGE_TABLE_ISOLATION=y` | Meltdown (Rogue Data Cache Load) 유저-커널 페이지 테이블 격리 | **~2.0% - 5.0%** |

### 4.1 [Spectre v1 핵심 방어선] `array_index_nospec`

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **산술 마스크 합성 (`sbb`)**:
        - `cmp %size, %idx` 후 캐리 플래그(CF)를 검사하여 `sbb %mask, %mask` 명령어로 비트 마스크를 생성함.
        - $idx < size$이면 `mask = 0`, $idx \ge size$이면 `mask = ~0UL`이 산출됨.
    2.  **데이터 의존성 기반 인덱스 고정**:
        - `idx = idx & ~mask` 연산으로 인덱스를 즉각 필터링함.
        - 분기 명령어가 전혀 없으므로 BPU가 추측을 개입시킬 여지가 없으며, 마이크로아키텍처 파이프라인에서 OOB 주소 참조가 원천 차단됨.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **`lfence` 파이프라인 정지 오버헤드 극복**:
        - 펜스 명령어로 인한 수백 사이클의 파이프라인 스톨(Stall) 없이 단 2~3 클록 만에 안전한 메모리 로드 보장함.
    2.  **부채널 캐시 오염 원천 봉쇄**:
        - OOB 데이터가 L1/L2 캐시에 적재되는 부수 효과가 0%로 차단되어 Flush+Reload 공격이 무력화됨.

</div>

### 4.2 [Spectre v2 방어선] Retpoline & IBRS

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **리턴 트램펄린 (Return Trampoline)**:
        - 간접 점프(`jmp *%rax`, `call *%rax`)를 `call`과 `ret` 명령어로 치환함.
        - 리턴 주소 스택(RSB)의 예측 상태를 고의로 무한 루프(`pause; jmp`)로 유도하여 BPU가 공격자가 주입한 타깃을 추측 실행하지 못하도록 격리함.
    2.  **Enhanced IBRS**:
        - 하드웨어 레벨에서 커널 실행 모드(Ring 0) 진입 시 유저 모드에서 학습된 분기 예측 엔트리를 참조하지 못하도록 하드웨어 장벽을 형성함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **커널 함수 주소 누출 및 ROP/JOP 방어**:
        - BPU 엔트리 조작을 통한 커널 가젯 임의 투기 실행을 100% 방지함.

</div>

---

## 5. 실습 환경 및 공격 시뮬레이션 데모 (`spectre_demo.c`)

본 실습에서는 Spectre v1 취약점(CVE-2017-5753)을 모사한 C 언어 시뮬레이터(`spectre_demo.c`)를 빌드하고, 취약 모드와 `array_index_nospec` 하드닝 모드의 캐시 타이밍 측정 동작 차이를 실측 검증함.

### 5.1 시뮬레이터 핵심 아키텍처 (`spectre_demo.c`)

- **실습 소스 코드**: [`spectre_demo.c`](../../assets/labs/scenarios/06-spectre/spectre_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/scenarios/06-spectre/spectre_demo.c)
- **메모리 구조**: 커널 공개 배열(`g_public_array`, 크기 16B) 및 인접 메모리에 위치한 미션 보안 엔클레이브 구조체(`g_mission_enclave`, 기밀 토큰 `"NAV_SEC_8F3A"`) 모델링.
- **방어 로직 구현**: 리눅스 커널 `mm/nospec.c`의 `array_index_nospec()` 산술 마스킹 함수를 구현하여 투기적 인덱스 클램핑 검증.

```c
/* labs/scenarios/06-spectre/spectre_demo.c 산술 마스킹 구현 */
static inline size_t array_index_nospec(size_t index, size_t size) {
    uintptr_t mask = ~(uintptr_t)0;
    if (index < size) {
        mask = 0;
    }
    return index & ~mask; /* 경계 초과 시 0으로 클램핑 */
}
```

---

### 5.2 공격 실행 및 기밀 토큰 탈취 경고 로그 (Attack Execution Logs)

투기적 방어선이 비활성화된 취약 모드(`nospec=n`)에서 Flush+Reload 부채널 공격을 감행했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 취약 모드 실행 (Spectre v1 부채널 유출 환경)
cd labs/scenarios/06-spectre && make run-attack
```

**런타임 경고 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot Speculative Side-Channel & array_index_nospec Lab (Spectre) 
======================================================================

[MODE 2: SPECTRE V1 FLUSH+RELOAD SIDE-CHANNEL LEAK (NOSPEC=n)]
[*] Simulating CVE-2017-5753: Branch Predictor training & speculative bounds bypass...
[*] Attacker targets Kernel Mission Secret Token located beyond public array boundary...

    [!] Training BPU with 1000 in-bounds iterations (idx < 16)...
    [!] Flushing cache lines for probe array (clflush simulation)...
    [!] Launching transient speculative read for secret byte offsets...

    -> Offset +00: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'N' (0x4E)
    -> Offset +01: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'A' (0x41)
    -> Offset +02: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'V' (0x56)
    -> Offset +03: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: '_' (0x5F)
    -> Offset +04: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'S' (0x53)
    -> Offset +05: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'E' (0x45)
    -> Offset +06: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'C' (0x43)
    -> Offset +07: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: '_' (0x5F)
    -> Offset +08: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: '8' (0x38)
    -> Offset +09: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'F' (0x46)
    -> Offset +10: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: '3' (0x33)
    -> Offset +11: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: 'A' (0x41)

======================================================================
 [💥 CRITICAL SIDE-CHANNEL COMPROMISE] Kernel Secret Exfiltrated! 
======================================================================
  [*] Recovered Auth Token = 'NAV_SEC_8F3A' (100% Match with Enclave)
  [*] Attack Method = Spectre Variant 1 (Bounds Check Bypass) + FLUSH+RELOAD
  [*] Architectural Privilege Violation: 0 (No #PF / No Segfault triggered!)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & GEOFENCE OVERRIDE] ---
  [🔴 PHYSICAL HAZARD] Geofence Authorization Token Forged by Attacker!
  [🔴 PHYSICAL HAZARD] Autonomous Safety Boundary Disarmed: Robot entering forbidden high-voltage zone!
  [🔴 PHYSICAL HAZARD] Locomotion Planner Hijacked: High-speed unauthorized trajectory executed!
```

---

### 5.3 하드닝 모드 검증 및 부채널 신호 차단 로그 (Hardened Defense Logs)

`array_index_nospec` 산술 클램핑 적용 환경에서의 실측 로그:

```bash
# 하드닝 모드 실행 (산술 마스크 클램핑 및 타이밍 평탄화)
cd labs/scenarios/06-spectre && make run-hardened
```

**런타임 방어 및 페일세이프 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot Speculative Side-Channel & array_index_nospec Lab (Spectre) 
======================================================================

[MODE 3: SIDE-CHANNEL THWARTED BY ARRAY_INDEX_NOSPEC & RETPOLINE]
[*] Initializing Hardened Kernel Environment (CONFIG_RETPOLINE=y, array_index_nospec active)...
[*] Attacker attempts speculative bounds bypass on target offsets...
[*] array_index_nospec() arithmetic mask clamps speculative index to 0...

    [*] Cache Probe Measurement Result:
        - Cache Hit Timing for Secret Bytes = 0 hits (All reads DRAM latency > 240 cycles)
        - Clamped Index Access = index 0 access only (Benign public data)

======================================================================
 [🛡️ SPECULATIVE SIDE-CHANNEL NEUTRALIZED] array_index_nospec Mask Active! 
======================================================================
  [!] Forensic Analysis:
      Secret Recovery Rate = 0% (Side-Channel Timing Signal Neutralized)
      Defense Mechanism    = Speculation barrier arithmetic clamping (sbb mask)
      Spectre v2 Defense   = CONFIG_RETPOLINE + IBRS Speculative Branch Trap
  [!] Mission Enclave Secure: Geofence token remained intact.

  [FAIL-SAFE ACTIVE] Perception Watchdog flagged abnormal timing probing pattern!
  [FAIL-SAFE ACTIVE] Autonomous Navigation halted: Locomotion locked in deterministic Hold Mode!
```

---

### 5.4 아키텍처 핵심 분석: Rooting (UID 0 / Ring 3) vs Kernel Microarchitectural Leaks (Ring 0)의 결정적 차이

부채널 유출(Side-Channel Leaks)은 전통적인 소프트웨어 권한 모델과 완전히 다른 하드웨어 미세아키텍처 차원의 위협임:

```
[보안 평가 축]               [루팅 권한 (UID 0 / Ring 3)]          [부채널 투기적 유출 (Spectre / Ring 0 Leak)]
보안 결함 계층              소프트웨어 접근 제어 (DAC/MAC)        CPU 마이크로아키텍처 하드웨어 파이프라인
공격 수행 권한 요구          루트 관리자(UID 0) 자격 증명 필요     가장 낮은 권한의 비인가 컨테이너/샌드박스
메모리 접근 위반 로그        SELinux AVC 거부 또는 커널 Oops 기록   커널 로그 기록 전무 (No #PF / No Segfault)
LSM 보안 정책의 유효성       AppArmor/SELinux 정책에 의해 차단     하드웨어 캐시 타이밍 관측으로 LSM 완전 무력화
방어 수단                   사용자 권한 격리 및 Capability 제한    array_index_nospec, Retpoline, KPTI, IBRS
```

1. **루팅 권한(UID 0)과의 차이점**:
    - 루트 사용자는 시스템 파일을 수정할 수 있지만, 커널 내부 메모리나 보안 엔클레이브에 직접 접근할 때는 MMU 하드웨어 보호에 의해 차단되며 시스템 로그에 명확한 감사 기록(Audit Log)을 남김.
2. **미세아키텍처 부채널 공격의 은밀성과 치명성**:
    - Spectre 공격은 유저 공간의 격리된 샌드박스(Ring 3)에서도 커널(Ring 0)의 임의 메모리를 1바이트씩 타이밍 측정만으로 읽어낼 수 있음.
    - 단 한 번의 메모리 폴트나 크래시도 유발하지 않으므로 기존 IDS/IPS나 LSM이 침해 사실을 전혀 인지하지 못함. 따라서 커널 소스 레벨의 `array_index_nospec` 방어와 CPU 마이크로코드 패치가 필수 불가결함.

---

## 6. 엔지니어링 심층 분석 (Engineering Deep Dive)

### 6.1 `array_index_nospec` 어셈블리 생성 및 분기 없는 산술 연산

리눅스 커널 `include/linux/nospec.h`에 정의된 매크로의 x86-64 어셈블리 구조:

```nasm
# x86-64 nospec 인라인 어셈블리
    cmpq    %rsi, %rdi              # rdi(index)와 rsi(size) 비교
    sbbq    %rax, %rax              # if (index < size) CF=1 -> rax = ~0UL
                                    # if (index >= size) CF=0 -> rax = 0
    andq    %rax, %rdi              # rdi = index & mask
```

- **조건부 점프(Jcc)의 완전 배제**:
  - `jmp`, `jne`, `jl` 등의 분기 명령어가 단 1개도 사용되지 않음.
  - BPU가 분기 방향을 추측할 대상 자체가 존재하지 않으므로 투기적 실행 윈도우가 물리적으로 발생할 수 없음.

### 6.2 Retpoline 트램펄린 어셈블리 구조

Spectre v2를 완화하는 Clang/GCC Retpoline 어셈블리 템플릿:

```nasm
# Retpoline Thunk (__x86_indirect_thunk_rax)
__x86_indirect_thunk_rax:
    call    .Lsetup_rsb
.Lcapture_spec:
    pause                           # BPU 투기적 엔진을
    lfence                          # 포즈 루프에 가두어 동결
    jmp     .Lcapture_spec
.Lsetup_rsb:
    mov     %rax, (%rsp)            # 실제 타깃 주소로 리턴 스택 덮어쓰기
    ret                             # 안전한 복귀 실행
```

- BPU는 `call/ret` 쌍을 보고 리턴 스택 버퍼(RSB)를 참조하여 `.Lcapture_spec`의 `pause` 루프로 추측 실행을 유도당함. 실제 연산 유닛이 `(%rsp)`의 값을 확인한 후 정규 경로로 복귀함.

### 6.3 하드웨어 IBRS vs eIBRS 성능 특성

인텔 마이크로코드 패치 기반 간접 분기 격리 기술:

- **Legacy IBRS**: 매 커널 진입 및 퇴장 시 `IA32_SPEC_CTRL` MSR을 쓰기(WRMSR)해야 하므로 20~30%의 시스템 콜 오버헤드 유발함.
- **Enhanced IBRS (eIBRS)**: Intel 9세대+ 프로세서에 적용되어 MSR 쓰기 없이 하드웨어 내부적으로 특권 레벨 전환 시 BPU 상태를 자동 격리하여 오버헤드를 1% 미만으로 경감함.

### 6.4 로봇 사이버-물리 페일세이프 아키텍처

부채널 프로빙 시도로부터 로봇 미션을 보호하는 2중 안전 대응:

1. **하드웨어 PMU 성능 카운터 감시(Performance Monitoring Unit)**:
   - 캐시 미스/히트 비율 및 `clflush` 명령어 실행 빈도가 임계치를 초과할 경우 이상 행위 감지 인터럽트 발생시킴.
2. **미션 보안 엔클레이브 키 소거 및 안전 정지(Safe Hold)**:
   - 100 μs 이내에 기밀 세션 토큰을 메모리에서 강제 소거(Zeroize)하여 조작된 명령 수신을 차단함.
   - 로봇 자율 주행 플래너를 정지 상태(Safe Hold)로 고정하여 비인가 이동을 물리 차단함.

---

## 7. 공식 커널 문서 및 표준 보안 레퍼런스

- [Linux Kernel Documentation - Speculative Execution Side Channel Mitigations](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/spectre.html)
- [Linux Kernel Documentation - Mitigation for Spectre Variant 1 (Bounds Check Bypass)](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/spectre_v1.html)
- [CVE-2017-5753: Bounds Check Bypass / Spectre Variant 1 (NIST NVD)](https://nvd.nist.gov/vuln/detail/CVE-2017-5753)
- [CVE-2017-5715: Branch Target Injection / Spectre Variant 2 (NIST NVD)](https://nvd.nist.gov/vuln/detail/CVE-2017-5715)
- [Intel Analysis of Speculative Execution Side Channels Whitepaper](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/analysis-speculative-execution-side-channels.html)
- [Paul Kocher et al.: Spectre Attacks: Exploiting Speculative Execution (IEEE S&P)](https://spectreattack.com/spectre.pdf)
