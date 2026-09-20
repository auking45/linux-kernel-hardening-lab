# Spectre v1: 경계 검사 우회 및 array_index_nospec 방어

## 1. 개요 및 배경

현대 고성능 마이크로프로세서는 메모리 접근 지연으로 인한 파이프라인 정체(Stall)를 최소화하기 위해 **분기 예측(Branch Prediction)** 및 **비순차적 투기적 실행(Out-of-Order Speculative Execution)** 기술을 채택함. CPU는 조건문(`if (index < size)`)의 분기 조건이 확정되기 전, 분기 예측기(Branch Target Buffer / Pattern History Table)의 과거 이력을 참조하여 분기 방향을 사전에 추측하고 후속 명령어를 선행 실행함.

2018년 공개된 **Spectre Variant 1 (Bounds Check Bypass - CVE-2017-5753)**은 이러한 하드웨어 투기적 실행 엔진의 설계 특성을 악용하는 마이크로아키텍처 부채널 공격(Side-Channel Attack)임:
1. **분기 오훈련 (Branch Predictor Mistraining)**:
   - 비특권 공격자는 합법적인 인덱스(`index < size`)를 반복적으로 전달하여 분기 예측기가 해당 조건 분기를 항상 "Taken(참)"으로 판정하도록 학습시킴.
2. **투기적 경계 밖 접근 (Transient Out-of-Bounds Load)**:
   - 이후 경계를 벗어난 악의적 오프셋(`index >= size`, 즉 커널 비밀 메모리 주소)을 전달하고, 경계 크기 변수를 캐시에서 비워 조건 판정 지연(Memory Latency Stall)을 유도함.
   - CPU는 메모리 판정이 완료될 때까지 조건문 내부의 메모리 로드 명령어를 투기적으로 실행하여, 커널 비밀 바이트(`secret = array1[index]`)를 읽고 이를 기반으로 2차 공유 배열(`probe_array[secret * 512]`)에 접근함.
3. **부채널 캐시 상태 잔류 및 비밀 복원 (Flush+Reload Extraction)**:
   - 뒤늦게 조건문이 "거짓(False)"으로 판정되면 CPU는 명령어 결과를 폐기하고 레지스터 상태를 롤백(Rollback)하지만, **마이크로아키텍처(CPU 캐시 라인) 상태는 롤백되지 않고 그대로 잔류**함.
   - 공격자는 유저스페이스에서 **Flush+Reload** 캐시 타이밍 측정(`rdtsc` / `cntvct_el0`)을 수행하여, 가장 짧은 접근 시간(Cache Hit)을 기록한 인덱스를 찾아냄으로써 커널 비밀 데이터를 100% 역산함.

리눅스 커널은 이러한 투기적 경계 우회를 소프트웨어 및 하드웨어 연계 방식으로 차단하기 위해 **`<linux/nospec.h>`**의 **`array_index_nospec()`** 매크로를 표준 방어 수단으로 제공함.

---

## 2. 실세계 비유: 도서관 사서의 성급한 사전 대출과 책갈피 흔적

`Spectre v1`과 `array_index_nospec`의 동작 원리는 **보안 구역 열람실 사서의 성급한 사전 심사**에 비유할 수 있음:

```
[ 취약한 방식 (Baseline: 무방비 조건 분기) ]
  공격자: "열람증 번호 500번(미인가 보안구역) 신청합니다!"
  사서: (신분증 검증에 시간이 걸리자 과거 경험만 믿고 성급하게 보안 서고로 달려감)
        ──► [1급 기밀문서 열람] ──► [책장에 흔적(캐시 라인) 남김]
  신분증 검증 완료: "자격 미달! 책을 도로 꽂아놓으세요." (대출 취소)
  공격자: "서가 책들의 온도를 측정해보니 기밀문서 위치만 따뜻하네! 기밀 내용 획득!"

[ 하드닝 방식 (Hardened: array_index_nospec) ]
  공격자: "열람증 번호 500번 신청합니다!"
  사서: (신분증 검증과 동시에 산술 마스크 적용: 500 & 0 = 0번으로 강제 고정)
        ──► [0번 공개 게시판만 확인] ──► [기밀 서고 근처 접근 자체를 차단]
  신분증 검증 완료: "자격 미달! 거절합니다."
  공격자: "서가 온도를 재봐도 기밀 서고는 전혀 따뜻해지지 않음 (0바이트 탈취 실패)!"
```

1. **전통적 커널 (성급한 사서의 흔적 잔류)**:
   - 신분증 유효성 판정(조건 분기)에 시간이 걸리는 동안, 사서(CPU)는 과거 경험에 따라 합법적일 것으로 예단하고 서고 안쪽 기밀 문서(OOB 커널 메모리)를 꺼내와 책상에 올려놓음.
   - 뒤늦게 불법 대출임이 밝혀져 책은 제자리에 돌려놓지만, 책이 놓였던 책상 자리의 온기(CPU 캐시 히트)는 그대로 남아 공격자가 기밀을 알아냄.
2. **array_index_nospec 활성화 커널 (산술 마스크 강제 고정)**:
   - 사서가 서고로 발을 떼기 전, 열람 번호에 하드웨어 산술 마스크를 강제로 곱함. 유효 범위를 벗어난 번호는 계산 즉시 0번(공개 구역)으로 수렴됨.
   - 사서가 성급하게 선행 작업을 하더라도 0번 일반 게시판만 확인하므로, 기밀 서고 쪽 캐시 라인은 전혀 가열되지 않아 정보 유출이 원천 차단됨.

---

## 3. 핵심 아키텍처 및 방어 메커니즘

### 3.1 취약한 코드 가젯 패턴 (Vulnerable Gadget Pattern)

Spectre v1 취약점은 커널 내에 다음과 같은 전형적인 배열 참조 패턴이 존재할 때 발생함:

```c
// 취약한 커널 코드 패턴
if (user_index < array1_size) {
    // 1단계: 경계 검사 지연 시 투기적으로 경계 밖 커널 메모리 로드
    uint8_t secret = array1[user_index];
    // 2단계: 비밀 데이터를 인덱스로 사용하여 2차 배열 캐시 라인 가열
    uint8_t val = probe_array[secret * 512];
}
```

- 공격자가 전달한 `user_index`가 `array1_size`보다 클 때, 분기 예측기는 분기문 내부로 진입하도록 투기 실행을 유도함.
- `probe_array`의 스트라이드가 512바이트(또는 페이지 단위)인 이유는 CPU의 하드웨어 공간 프리페처(Spatial Prefetcher)가 인접 캐시 라인을 미리 당겨오는 것을 방지하고, 정확히 `secret` 바이트에 해당하는 캐시 라인 1개만 L1/L2 캐시에 적재되도록 격리하기 위함임.

### 3.2 array_index_nospec() 매크로의 동작 원리

리눅스 커널의 `<linux/nospec.h>`는 분기문 직후 인덱스를 소독(Sanitize)하는 매크로를 정의함:

```c
#define array_index_nospec(index, size)					\
({									\
	typeof(index) _i = (index);					\
	typeof(size) _s = (size);					\
	unsigned long _mask = array_index_mask_nospec(_i, _s);		\
									\
	(typeof(_i)) (_i & _mask);					\
})
```

- `array_index_mask_nospec(index, size)`는 조건 분기문 대신 **CPU 산술 플래그 의존성(Arithmetic Data Dependency)**을 활용하여 마스크를 산출함:
  - `index < size` (합법적 인덱스): `mask = ~0UL` (`0xFFFFFFFFFFFFFFFF`), 따라서 `index & mask == index`.
  - `index >= size` (경계 초과 인덱스): `mask = 0UL` (`0x0000000000000000`), 따라서 `index & mask == 0`.

### 3.3 아키텍처별 하드웨어 명령어 구현

| 아키텍처 | 어셈블리 구현 (`asm volatile`) | 투기 제어 배리어 | 특징 및 성능 영향 |
| :--- | :--- | :--- | :--- |
| **x86_64** | `cmp %1, %2; sbb %0, %0` | `barrier_nospec()` (`lfence`) | `sbb`(Subtract with Borrow)를 통해 플래그 레지스터 상태를 즉각 마스크 레지스터로 복사 (오버헤드 < 1%) |
| **ARM64 (aarch64)** | `cmp %1, %2; sbc %0, xzr, xzr` | **`csdb` (hint #20)** | `sbc`로 마스크 산출 후, 제어 투기 데이터 배리어(`csdb`)로 후속 메모리 로드 동기화 보장 |

- **x86의 `sbb` 기법**: `cmp idx, sz` 수행 시 `idx < sz`이면 캐리 플래그(CF)가 1이 되어 `sbb dst, dst`는 `0 - 0 - 1 = -1` (`~0UL`)이 되고, `idx >= sz`이면 CF가 0이 되어 `0 - 0 - 0 = 0`이 됨. CPU 투기적 실행 파이프라인은 이 산술 연산 결과가 나오기 전까지 `array1[safe_idx]`의 주소를 결정할 수 없어, 자동으로 OOB 주소 생성이 차단됨.
- **ARM64의 `csdb` 기법**: ARMv8-A 명세에 추가된 **Control Speculation Data Barrier**(`hint #20`)는 조건 플래그 판정 결과가 레지스터에 기록되기 전에 투기적 로드 파이프라인이 데이터 버스를 점유하는 것을 완벽히 동기화 차단함.

---

## 4. 인터랙티브 아키텍처 시뮬레이터

Spectre v1 경계 검사 우회 과정과 `array_index_nospec`에 의한 산술 마스킹 차단 메커니즘을 시각화한 대화형 아키텍처 다이어그램임:

<iframe src="../../assets/diagrams/spectrev1/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. 실습 및 공격/방어 시연

### 5.1 취약점 실습 드라이버 (`vuln_spectrev1.c`)

`/proc/vuln_spectrev1` (모드 0666) 인터페이스를 통해 다음 실습 기능을 제공함:
- **상태 및 하드웨어 취약점 보고 (`cat /proc/vuln_spectrev1`)**:
  - 현재 CPU 아키텍처 및 산술 마스킹 명령어 정보(`sbb` vs `sbc+csdb`).
  - 활성 동작 모드: `[0] Baseline (Vulnerable)` vs `[1] Hardened (array_index_nospec)`.
  - 공개 배열 크기(16B), 비밀 문자열 오프셋 거리(+16B), 2차 프로브 배열 물리 주소 및 스트라이드(512B).
  - 총 누출 탐지 횟수 및 방어 차단 횟수 통계.
- **모드 전환 제어**:
  - `echo 'mode baseline' > /proc/vuln_spectrev1`: 무방비 상태의 표준 조건 분기 활성화.
  - `echo 'mode hardened' > /proc/vuln_spectrev1`: `array_index_nospec()` 보호 활성화.
- **유저스페이스 직접 Flush+Reload 지원 (`mmap`)**:
  - 드라이버의 128KB 2차 프로브 배열을 유저 공간 가상 메모리에 매핑하여, 비특권 프로세스가 직접 하드웨어 캐시 타이밍을 계측할 수 있도록 지원함.
- **자체 인커널 벤치마크 (`echo run_bench > /proc/vuln_spectrev1`)**:
  - 커널 드라이버 내부에서 30라운드의 분기 오훈련과 OOB 투기 실행을 수행하고, 타이밍 측정을 통해 누출 여부를 진단함.

### 5.2 비특권 사용자 Flush+Reload 익스플로잇 PoC (`exploit.c`)

일반 비특권 사용자 `lab` (UID 1000) 권한으로 실행되며, 다음과 같은 정밀 부채널 공격을 수행함:
1. **듀얼 아키텍처 고해상도 사이클 타이머**:
   - x86_64: `rdtscp` 명령어로 직렬화된 CPU 사이클 측정.
   - ARM64: `cntvct_el0` (Virtual Count Register) 및 `isb` 배리어 동기화 측정.
2. **분기 예측기 오훈련 루프**:
   - 유효 인덱스(0..15)로 5회 반복 호출하여 분기 예측기를 "Taken" 상태로 오훈련.
   - 6번째 호출에서 비밀 데이터 오프셋(+16)을 주입.
3. **결과 분석 및 판정**:
   - **Baseline 모드**:
     - `FLAG` 비밀 문자열의 바이트('F', 'L', 'A', 'G')가 52~70 사이클 내의 짧은 캐시 히트 타이밍으로 복원됨 (`[FAIL/VULNERABLE]`).
   - **Hardened 모드**:
     - OOB 인덱스가 `safe_idx = 0`으로 강제 마스킹되어 비밀 데이터 접근 차단.
     - 모든 프로브 라인이 200사이클 이상의 캐시 미스(Cold)를 기록하여 0바이트 누출 달성 (`[PASS/PROTECTED]`).

---

## 6. 검증 및 결과 분석

### 6.1 인게스트 자동화 테스트 실행

QEMU 게스트 환경에서 배포된 테스트 스크립트를 실행하여 완화 상태를 검증함:

```bash
# Spectre v1 자동화 테스트 실행
/bin/test_spectre_v1
```

### 6.2 sysfs 취약점 진단 인터페이스 확인

리눅스 커널의 표준 마이크로아키텍처 취약점 인터페이스를 통해 시스템 수준의 완화책 상태를 확인함:

```bash
cat /sys/devices/system/cpu/vulnerabilities/spectre_v1
# 출력: Mitigation: __user pointer sanitization
```

### 6.3 아키텍처별 QEMU 4개 시나리오 검증 매트릭스

| 시나리오 | 아키텍처 | 동작 모드 | 비밀 데이터 복원 여부 | 최종 판정 |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | ARM64 | Mode 1 (Hardened) | 0바이트 (전 라인 캐시 미스) | **PASS (Protected)** |
| **Scenario 2** | ARM64 | Mode 0 (Baseline) | 'F', 'L', 'A', 'G' 누출 확인 | **VULNERABLE (Demonstrated)** |
| **Scenario 3** | x86_64 | Mode 1 (Hardened) | 0바이트 (`sbb` 클램핑 차단) | **PASS (Protected)** |
| **Scenario 4** | x86_64 | Mode 0 (Baseline) | 'F', 'L', 'A', 'G' 누출 확인 | **VULNERABLE (Demonstrated)** |

