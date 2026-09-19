# KFENCE (Kernel Electric Fence: 힙 결함 샘플링 탐지)

## 1. 개요 및 배경

리눅스 커널 힙 메모리(SLUB 할당자)는 Use-After-Free(UAF, CWE-416) 및 힙 버퍼 오버플로우/언더플로우(Out-of-Bounds, CWE-125/CWE-787) 등 가장 빈번하고 치명적인 메모리 오염 취약점이 발생하는 핵심 공격 표면임.

이러한 메모리 결함을 탐지하기 위한 대표적인 도구로 **KASAN(Kernel Address Sanitizer)**이 존재하지만, 프로덕션 환경에 적용하기에는 치명적인 제약이 존재함:
- **KASAN의 한계**: 전체 메모리의 1/8을 섀도 메모리(Shadow Memory)로 할당하고 모든 메모리 접근마다 컴파일러 계측(Instrumentation) 인스트럭션을 삽입함. 이로 인해 **메모리 사용량이 100% 이상 증가**하고 **CPU 실행 오버헤드가 2~3배(200~300%) 증가**하여 개발 및 테스트 팜 이외의 실제 서비스 환경(Android 양산 단말, 대규모 클라우드 서버 등)에서는 상시 가동이 불가능함.

리눅스 커널 5.12에서 최초 도입되어 6.12 LTS에서 표준으로 자리 잡은 **KFENCE (Kernel Electric Fence, `CONFIG_KFENCE=y`)**는 이러한 딜레마를 해결하기 위해 설계된 **프로덕션 맞춤형 샘플링 메모리 안전성 탐지기**임:
1. **확률적 샘플링(Probabilistic Sampling)**: 모든 할당을 전수 검사하는 대신, 설정된 주기(기본 100ms, 본 실습 10ms)마다 발생하는 힙 할당 중 단 1건만 표본 추출하여 전용 가드 풀로 라우팅함.
2. **하드웨어 MMU 가드 페이지(Guard Pages)**: 표본 할당된 객체의 전후에 페이지 테이블 상에서 존재하지 않는(Non-present, `PROT_NONE`) 가드 페이지를 배치하여, 경계를 단 1바이트라도 침범하는 즉시 CPU 하드웨어 페이지 폴트(Page Fault)를 유발함.
3. **UAF 페이지 보호**: 객체가 `kfree()`로 반환되면 해당 객체 페이지 전체를 즉시 보호 상태로 전환하여, 해제된 메모리에 접근하려는 댕글링 포인터를 하드웨어 인터럽트로 즉각 감전(Zap) 차단함.
4. **극도로 낮은 오버헤드**: 프로덕션 실측 기준 **CPU 오버헤드 1% 미만**, 메모리 사용량 수 MB 수준으로 실서비스에 24/7 상시 활성화 가능함.

---

## 2. 실세계 비유: 놀이공원 롤러코스터 표본 정밀점검과 안전 가드레일

KFENCE의 동작 원리는 대형 테마파크의 **롤러코스터 안전 점검 시스템**에 비유할 수 있음:

```
[ 일반 손님 열차 (일반 SLUB 할당) ] ─────(초고속 통과: 노 딜레이)─────► [ 정상 운행 ]
                                                      
[ 100ms 주기 알람: 샘플 열차 선정 ]
                 │
                 ▼
[ KFENCE 전용 시험 트랙 (가드 페이지 풀) ]
  ┌───────────────────────────────────────────────────────────┐
  │ [⚡ 고전압 철조망] │ [ 점검 열차 (객체) ] │ [⚡ 고전압 철조망] │
  └─────────┬───────────────────┬───────────────────┬─────────┘
            │                   │                   │
            ▼                   ▼                   ▼
     (좌측 탈선 시)       (탑승 중 손 내밀면)    (우측 탈선 시)
     💥 감전 비상 정지!     ⚡ 즉시 경보 작동!     💥 감전 비상 정지!
```

1. **전통적 커널 (경비 없는 트랙)**:
   - 모든 열차를 검사 없이 고속 통과시킴. 열차가 트랙을 이탈하여 옆 레일을 침범하거나(OOB), 이미 승강장을 떠난 빈 열차에 탑승을 시도해도(UAF) 센서가 없어 대형 충돌 사고(커널 패닉/보안 침해)가 터질 때까지 결함을 인지하지 못함.
2. **KASAN (모든 열차마다 전수 분해 검사)**:
   - 탑승하는 모든 승객마다 가방을 다 털고 레일 나사를 하나하나 풀어서 확인함. 완벽하게 안전하지만 대기 시간이 3배로 늘어나 놀이공원 운영이 마비됨(프로덕션 배포 불가).
3. **KFENCE (주기적 표본 추출 & 고전압 가드레일 트랙)**:
   - 100ms마다 한 대씩만 특별히 설계된 '고전압 가드레일 트랙'으로 유도함. 나머지 99.9% 열차는 원래 속도대로 주행하므로 파크 운영(CPU 성능)에 영향이 전무함.
   - 가드레일 트랙에 들어간 표본 열차가 조금이라도 레일을 벗어나면 고전압 철조망(MMU 가드 페이지)에 닿아 즉시 비상 경보(`BUG: KFENCE: out-of-bounds`)가 울리고 정밀 위치가 블랙박스에 기록됨.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 KFENCE 메모리 풀 레이아웃 (`__kfence_pool`)

KFENCE는 부팅 시 연속된 물리 메모리를 예약하여 전용 풀을 구성함 (`mm/kfence/core.c`):

```text
[ Guard Page 0 ] (PROT_NONE, Non-present)
[ Object Page 0] (Guarded Object Slot) ──► Left/Right 정렬 배치 + Redzone Canary
[ Guard Page 1 ] (PROT_NONE, Non-present)
[ Object Page 1] (Guarded Object Slot)
[ Guard Page 2 ] (PROT_NONE, Non-present)
...
[ Guard Page N ] (PROT_NONE, Non-present)
```

- 총 페이지 수: `(CONFIG_KFENCE_NUM_OBJECTS * 2) + 1` 페이지. 기본값 255개 객체 설정 시 총 511페이지(약 2MB)의 극소 메모리만 소비함.
- 가드 페이지는 페이지 테이블에서 유효 비트가 해제되어 있어 읽기/쓰기 시도 시 즉시 MMU Fault 발생.

### 3.2 샘플링 게이트 메커니즘 (`kfence_allocation_gate`)

```text
타이머 인터럽트 (kfence_sample_interval 주기)
       │
       ▼
atomic_set(&kfence_allocation_gate, 1);
       │
       ▼
SLUB 슬랩 할당 요청 (kmalloc / kmem_cache_alloc)
       │
       ▼
kfence_alloc()
       │
       ├─► allocation_gate == 0: 일반 SLUB 빠른 경로(Fastpath)로 반환
       │
       └─► allocation_gate == 1 (원자적 게이트 선점 성공):
             atomic_set(&kfence_allocation_gate, 0); // 게이트 즉시 폐쇄
             kfence_guarded_alloc() 호출 -> __kfence_pool에서 객체 할당
```

### 3.3 좌/우 무작위 정렬 및 OOB 탐지 원리

객체 크기(예: 32바이트)는 페이지 크기(4096바이트)보다 작으므로, 객체를 페이지 내 어느 쪽에 배치하느냐에 따라 탐지 방향이 결정됨:
- **우측 정렬 (`!PAGE_ALIGNED`, 50% 확률)**: 객체를 페이지의 가장 마지막 바이트에 붙여 할당 (`PAGE_SIZE - size`). 객체 범위를 1바이트라도 초과하는 오버플로우(`buf + size`) 발생 시 즉각 우측 가드 페이지 침범 -> Fault.
- **좌측 정렬 (`PAGE_ALIGNED`, 50% 확률)**: 객체를 페이지 시작 주소에 배치. 언더플로우(`buf - 1`) 발생 시 즉각 좌측 가드 페이지 침범 -> Fault.
- **카나리 패턴 검증**: 객체가 배치되지 않은 나머지 페이지 공간에는 특수 매직 바이트(`0xAA` / `0xBB`)가 기록되어, 객체 해제 시 카나리 변조(`KFENCE_ERROR_CORRUPTION`)를 추가 검증함.

### 3.4 UAF 탐지 및 격리 메커니즘

1. 객체가 `kfree(ptr)`로 반환되면 `kfence_guarded_free()` 실행.
2. 해제된 객체가 위치한 페이지 자체를 `kfence_protect()`를 호출하여 `PROT_NONE`으로 전환.
3. 이후 공격자가 댕글링 포인터를 통해 해당 주소를 읽거나 쓰려고 하면 즉시 MMU 페이지 폴트 발생.
4. `kfence_handle_page_fault()`가 이를 가로채 `BUG: KFENCE: use-after-free` 리포트를 발행하고, 할당 시점 및 해제 시점의 콜스택을 완벽하게 교차 출력함.

---

## 4. 인터랙티브 아키텍처 다이어그램

아래 시뮬레이터는 일반 SLUB과 KFENCE 가드 풀의 메모리 레이아웃 차이 및 OOB/UAF 발생 시 하드웨어 트랩 동작을 동적으로 시연함.

<iframe src="../../assets/diagrams/kfence/architecture.html" width="100%" height="750px" style="border:none; border-radius:8px; overflow:hidden;"></iframe>

---

## 5. 실습 환경 구성 및 빌드 가이드

### 5.1 커널 설정 구성

```ini
# configs/features/kfence.config
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=10
CONFIG_KFENCE_NUM_OBJECTS=255
CONFIG_LKDTM=y
```

### 5.2 빌드 및 부팅 명령어

#### ARM64 (aarch64) 실습
```bash
# KFENCE 활성화 커널 부팅 및 자동 테스트
./scripts/run_lab.sh --arch arm64 --feature kfence --test test_kfence

# 베이스라인 취약 커널 비교 부팅
./scripts/run_lab.sh --arch arm64 --feature kfence-disabled --test test_kfence
```

#### x86_64 실습
```bash
# KFENCE 활성화 커널 부팅 및 자동 테스트
./scripts/run_lab.sh --arch x86_64 --feature kfence --test test_kfence

# 베이스라인 취약 커널 비교 부팅
./scripts/run_lab.sh --arch x86_64 --feature kfence-disabled --test test_kfence
```

---

## 6. 취약점 공격 및 방어 검증 실습

### 6.1 비특권 익스플로잇 PoC 검증 (`/bin/exploit_kfence`)

비특권 계정 `lab` (UID 1000)에서 실행하여 OOB 및 UAF 결함을 유발하고 KFENCE의 탐지 통계를 실시간 조회함.

#### 하드닝 커널 (`CONFIG_KFENCE=y`) 결과
```text
=========================================================
  KFENCE (Kernel Electric Fence) Verification PoC
  UID: 1000 | GID: 1000 | PID: 50
=========================================================
=========================================================
  KFENCE Verification Driver (/proc/vuln_kfence)
=========================================================
Kernel Configuration : CONFIG_KFENCE=y [ENABLED]
Sample Interval      : 10 ms (configurable via kfence.sample_interval)
Protection Status    : ACTIVE (Sampling guard pages & UAF page protection)
Debugfs Interface    : /sys/kernel/debug/kfence/stats
=========================================================

[*] Initial KFENCE bug counter: 0
    [Stats] Current KFENCE Debugfs Counters:
            currently allocated: 2
            total allocations: 14
            total frees: 12
            zombie allocations: 0
            total bugs: 0

[*] Step 1: Triggering Out-of-Bounds (OOB) Probe via Driver
[+] Triggered OOB probe against kernel heap buffer.
    [Stats] Current KFENCE Debugfs Counters:
            total bugs: 1

[*] Step 2: Triggering Use-After-Free (UAF) Probe via Driver
[+] Triggered UAF probe against freed kernel heap object.

[*] Final KFENCE bug counter: 2
    [Stats] Current KFENCE Debugfs Counters:
            total bugs: 2

=========================================================
  Verification Assessment:
  [+] PASS: KFENCE successfully trapped heap errors!
  [+] Total Bugs Caught: 2 (New bugs: +2)
  [+] Memory Protection: ACTIVE (Electric Guard Pages Enforced)
=========================================================
```

#### 커널 로그 (`dmesg`) 확인
```text
[   14.238120] ==================================================================
[   14.238240] BUG: KFENCE: out-of-bounds read in trigger_oob_test+0x54/0x9c
[   14.238380] Out-of-bounds read at 0xffff800082f53000 (1B right of kfence-#14):
[   14.238510]  trigger_oob_test+0x54/0x9c
[   14.238620]  vuln_kfence_write+0x68/0xb0
[   14.238710] kfence-#14: 0xffff800082f52fe0-0xffff800082f52fff (size 32, cache kmalloc-32)
[   14.238800] allocated by task 50 on cpu 1 at 14.237890s:
[   14.238910]  alloc_guarded_object+0x44/0xa8
[   14.239020]  trigger_oob_test+0x20/0x9c
[   14.239130] ==================================================================
[   14.258900] ==================================================================
[   14.259010] BUG: KFENCE: use-after-free read in trigger_uaf_test+0x88/0xbc
[   14.259120] Use-after-free read at 0xffff800082f56fe0 (in kfence-#15):
[   14.259230]  trigger_uaf_test+0x88/0xbc
[   14.259340] freed by task 50 on cpu 1 at 14.258710s:
[   14.259450]  kfree+0x78/0x120
[   14.259560]  trigger_uaf_test+0x70/0xbc
[   14.259670] allocated by task 50 on cpu 1 at 14.258410s:
[   14.259780]  alloc_guarded_object+0x44/0xa8
[   14.259890]  trigger_uaf_test+0x20/0xbc
[   14.260000] ==================================================================
```

#### 베이스라인 커널 (`CONFIG_KFENCE` 미적용) 결과
```text
=========================================================
  Verification Assessment:
  [-] BASELINE: KFENCE is disabled. Heap OOB/UAF executed silently!
  [-] Memory Protection: NONE (Unchecked SLUB operation)
=========================================================
```

---

## 7. 성능 오버헤드 및 실무 적용 고려사항

1. **프로덕션 런타임 오버헤드**:
   - 샘플링 주기를 100ms로 설정할 경우, 초당 최대 10개의 객체만 가드 풀로 할당됨.
   - 수십만 번의 일반 슬랩 할당 중 99.99%는 단일 원자적 정수 비교(`kfence_allocation_gate`)만 거치므로 **CPU 오버헤드는 0.5% 미만**에 불과함.
2. **풀 메모리 소비량**:
   - 기본 255개 객체 기준 약 2MB(511페이지)의 고정 메모리만 점유하므로 RAM 제약이 심한 모바일 기기 및 IoT 게이트웨이에서도 부담 없이 상시 활성화 가능함.
3. **프로덕션 채택 현황**:
   - **Google Android Common Kernel (ACK)**: Android 12 이후 전 세계 수십억 대의 안드로이드 기기에 KFENCE가 기본 탑재되어 매일 수백 건의 제로데이 커널 힙 버그를 원격 텔레메트리로 수집함.
   - **Google Cloud & Meta**: 대규모 하이퍼스케일 서버 인프라에서 커널 무결성 모니터링을 위해 상시 운용 중임.

---

## 8. FAQ 및 트러블슈팅

**Q1: KFENCE가 발생시키는 결함으로 인해 시스템이 패닉에 빠지는가?**
- 기본적으로 KFENCE는 시스템을 즉시 패닉시키지 않고 상세한 버그 리포트를 커널 로그에 기록한 후 해당 페이지의 보호를 일시 해제하여 시스템 생존성을 유지함. 보안 크리티컬 환경에서는 `panic_on_warn=1` 부팅 매개변수를 통해 공격 발생 즉시 안전한 재부팅을 유도할 수 있음.

**Q2: 런타임에 샘플링 빈도를 변경할 수 있는가?**
- 변경 가능함. `/sys/module/kfence/parameters/sample_interval` 노드에 밀리초 단위 값을 쓰면 재부팅 없이 실시간으로 샘플링 주기를 조정할 수 있음 (`echo 50 > /sys/module/kfence/parameters/sample_interval`).

