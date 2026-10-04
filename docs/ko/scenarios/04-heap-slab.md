# [Scenario 04] 힙 UAF & 슬랩 메모리 오염 (SLAB Freelist Hardening & KFENCE)

!!! abstract "🎯 발표 핵심 요약 (Executive Summary)"
    - **실제 공격 사례**: 리눅스 커널 파일시스템 컨텍스트 힙 버퍼 오버플로우 (**CVE-2022-0185**) 및 넷필터 힙 오염 익스플로잇 (**CVE-2021-22555**)
    - **위협 벡터**: SLUB 할당자(`kmalloc-128`)의 미할당 청크(Free Slot) 내 평문 `freelist_ptr`를 조작하여 차기 `kmalloc` 시 임의의 커널 중요 데이터 구조체(로봇 자세 제어 PID 구조체 등)를 공격자 할당 객체로 반환받아 무단 덮어쓰기 수행 (Freelist Poisoning)
    - **사이버-물리 피해**: 2족 보행 균형 제어 PID 게인 폭주(Pitch Kp: 150.0 -> 9500.0), 감쇠 계수 무력화(Kd: 12.0 -> 0.0), 요 회전 발산(Yaw: 32.5 rad/s)으로 인한 관절 공진 발산 및 지면 전도 파괴 발생
    - **1차 방어선**: 커널 슬랩 포인터 난독화 암호화 기술 **`CONFIG_SLAB_FREELIST_HARDENED`** (XOR 쿠키 + 바이트 스왑 검증)
    - **보완 방어선**: 저오버헤드 프로덕션 힙 가드 메모리 **KFENCE (`CONFIG_KFENCE`)** 및 슬랩 프리리스트 무작위화 **`CONFIG_SLAB_FREELIST_RANDOM`**

---

## 1. 실제 커널 침해 사례 분석: CVE-2022-0185 / CVE-2021-22555와 휴머노이드 제어 구조체 파괴

리눅스 커널 메모리 취약점 중 가장 치명적인 유형은 동적 힙 할당자(SLAB/SLUB)에서 발생하는 버퍼 오버플로우 및 Use-After-Free(UAF) 결함임:

```
[로봇 사용자 공간 (Locomotion Planner / C2: Ring 3)]
                 │
                 │ (1) fs_context / netfilter 취약점 시스템 콜 호출
                 ▼
[커널 힙 공간 (SLUB kmalloc-128 Cache)]
 ┌──────────────────────┐      ┌──────────────────────┐
 │ Chunk 0 (Vulnerable) │ ───> │ Chunk 1 (Free Slot)  │ ───> Chunk 2 ...
 └──────────────────────┘  OOB └──────────────────────┘
            │          초과 쓰기       │ (평문 freelist_ptr 변조)
            └─────────────────────────┘
                                       ▼
                       [오염된 주소: &victim_gait]
                                       │
                 │ (2) 차기 kmalloc() 호출 -> victim_gait 할당 반환!
                 ▼
[로봇 2족 보행 균형 제어기 (robot_gait_config_t)]
 - Kp_pitch : 150.0  ──[변조]──> 9500.0 (공진 발산 폭주)
 - Kd_pitch : 12.0   ──[변조]──> 0.0    (감쇠 완전 무력화)
 - Yaw_rate : 1.2    ──[변조]──> 32.5   (고속 회전 슬립)
                 │
                 ▼
[💥 물리적 전도 파괴: 2족 보행 관절 기어비 파단 및 지면 충돌 파손]
```

### 1.1 침해 경로 및 근본 원인 (Root Cause)

- **CVE-2022-0185 (fs_context 힙 버퍼 오버플로우)**:
    - 리눅스 레거시 파일시스템 파라미터 처리 모듈(`fs/fs_context.c`)의 `legacy_parse_param()` 함수에서 정수 언더플로우/경계 검증 미비로 인해 4KB 페이지 크기를 초과하여 힙 슬랩 인접 청크로 1바이트 이상 임의 바이트를 덮어쓰는 힙 OOB(Out-of-Bounds) 쓰기 발생함.
- **CVE-2021-22555 (Netfilter 힙 메모리 손상)**:
    - 넷필터 서브시스템(`net/netfilter/x_tables.c`)의 32비트 호환 레이어 메모리 복사 과정에서 인덱스 계산 착오로 인해 8바이트 메모리 오염 발생함.
- **평문 Freelist 포인터(Plaintext Freepointer) 악용**:
    - 하드닝이 적용되지 않은 기본 SLUB 캐시에서는 가용 청크 내부에 다음 가용 청크의 가상 메모리 주소가 그대로 평문(Plaintext)으로 노출되어 저장됨.
    - 공격자가 힙 오버플로우를 통해 이 포인터를 원하는 타깃 주소(`&victim_gait` 또는 `struct cred`)로 덮어쓰면, 할당자는 다음 `kmalloc()` 호출 시 해당 타깃 메모리를 새로운 슬랩 청크로 잘못 인식하여 공격자에게 제어권을 넘겨줌.

### 1.2 사이버-물리적 재난 분석 (Cyber-Physical Hazards)

커널 힙 객체 오염은 로봇의 폐루프(Closed-loop) 키네마틱스 제어기를 즉각 교란하여 심각한 하드웨어 파손을 유발함:

- 🔴 **피치 축 비례 게인(Kp) 폭주 (Resonance Runaway)**:
    - 공칭 150.0인 비례 게인이 9500.0으로 63배 이상 폭증하여 관절 모터가 한계 각속도로 급격히 좌우 진동함. 고유 진동수와 결합되어 시스템 공진 발산 유도함.
- 🔴 **미분 감쇠 게인(Kd) 제로화 (Zero Damping Undamped Oscillation)**:
    - 공칭 12.0인 댐핑 팩터가 0.0으로 지워져 진동을 억제하지 못하고 무한 증폭 상태로 전이됨.
- 🔴 **요(Yaw) 축 고속 회전 슬립 (Violent Spin & Tip-Over)**:
    - 최대 요 각속도 제한이 1.2 rad/s에서 32.5 rad/s로 해제되어 2족 지지면을 이탈하고 지면에 전속력으로 전도 전복되어 12개 관절 모터 감속기 파손을 초래함.

---

## 2. SLUB 할당자 아키텍처 및 Freelist Poisoning 공격 메커니즘

리눅스 커널은 메모리 단편화를 방지하고 고속 객체 할당을 지원하기 위해 SLUB(Unqueued Slab Allocator)을 채택함.

### 2.1 SLUB 가용 객체 관리 구조

SLUB 할당자는 각 CPU 코어마다 `kmem_cache_cpu` 구조체를 유지하며, 가용 청크들을 단방향 연결 리스트(Freelist)로 연결함:

```
[ kmem_cache_cpu ]
  freelist ──────┐
                 ▼
        ┌──────────────────┐      ┌──────────────────┐
        │ Object 0 (Free)  │      │ Object 1 (Free)  │
        ├──────────────────┤      ├──────────────────┤
        │ [freelist_ptr] ──┼─────>│ [freelist_ptr] ──┼───> NULL
        │  (Payload Data)  │      │  (Payload Data)  │
        └──────────────────┘      └──────────────────┘
```

1. **인라인 프리포인터(Inline Freepointer)**:
    - 객체가 미할당(Free) 상태일 때 별도의 메타데이터 영역을 할당하지 않고, **객체 자신의 데이터 영역 시작 부분(Offset 0) 또는 중간에 다음 가용 객체의 포인터를 직접 저장**함.
2. **할당 및 반환 메커니즘**:
    - `kmem_cache_alloc()`: `freelist` 헤드가 가리키는 객체를 pop하고, 해당 객체의 `freelist_ptr`를 새로운 헤드로 갱신함.
    - `kmem_cache_free()`: 해제된 객체의 `freelist_ptr`를 현재 `freelist` 헤드로 설정하고, 해제 객체를 새 헤드로 push함.

### 2.2 Freelist Poisoning 익스플로잇 흐름

하드닝 부재 환경(`CONFIG_SLAB_FREELIST_HARDENED=n`)에서의 익스플로잇 단계:

```
[단계 1: 인접 힙 배치]
 힙 풍수(Heap Feng-Shui)를 통해 활성 청크(Chunk 0) 바로 뒤에 미할당 청크(Slot 1)를 배치함.

[단계 2: 경계 초과 쓰기]
 CVE-2022-0185 1바이트 힙 오버플로우로 Slot 1의 freelist_ptr를 victim_gait 주소(0xFFFF...01B0)로 덮어씀.

[단계 3: 힙 포인터 추출]
 차기 kmalloc(128) 호출:
   - Chunk 0 추출 완료 후 캐시 헤드가 변조된 Slot 1 주소를 가리킴.
 차차기 kmalloc(128) 호출:
   - 할당자가 Slot 1의 freelist_ptr를 읽어 victim_gait 주소를 새로운 청크로 반환함!

[단계 4: 임의 커널 구조체 덮어쓰기]
 공격자가 할당된 포인터에 데이터를 쓰면, 실제로는 커널 내부의 중요한 구조체 메모리가 변조됨!
```

---

## 3. 대화형 인터랙티브 아키텍처 다이어그램 (Interactive Diagrams)

아래 4개 단계별 다이어그램 및 통합 아키텍처 다이어그램을 통해 SLUB 할당 메커니즘, 공격자의 힙 오염 공격, 커널 방어 트랩, 하드웨어 페일세이프 E-Stop 전 과정을 시각적으로 확인 가능함.

### 3.1 [Phase 1] 정상 SLUB 메모리 할당 및 Freelist 순회 (Normal Allocation)

<iframe src="../../assets/diagrams/heap-slab/phase1-normal.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.2 [Phase 2] 힙 버퍼 오버플로우 & 평문 Freelist 오염 공격 (Attack Detonation)

<iframe src="../../assets/diagrams/heap-slab/phase2-attack.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.3 [Phase 3] Freelist Hardening XOR 쿠키 검증 & KFENCE 트랩 (Hardened Defense)

<iframe src="../../assets/diagrams/heap-slab/phase3-trap.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.4 [Phase 4] 사이버-물리 페일세이프 E-Stop 및 관절 락 (Deterministic Safe State)

<iframe src="../../assets/diagrams/heap-slab/phase4-failsafe.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.5 [통합 아키텍처] 커널 슬랩 힙 방어 체계 타임라인 (Comprehensive Architecture Flow)

<iframe src="../../assets/diagrams/heap-slab/architecture.html" width="100%" height="860" frameborder="0" style="border:none; border-radius:10px; margin-bottom:24px;"></iframe>

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

## 4. 다층 방어 기법 심층 분석 (Defense-in-Depth Layered Protection)

리눅스 커널은 힙 익스플로잇 체인을 무력화하기 위해 단계별 방어선을 구축함:

| 방어 기술 | 커널 Kconfig 설정 | 방어 기법 및 포획 시점 | 성능 오버헤드 |
| :--- | :--- | :--- | :--- |
| **SLAB Freelist Hardening** | `CONFIG_SLAB_FREELIST_HARDENED=y` | XOR 난수 쿠키 및 바이트 스왑 기반 포인터 암호화 (`kmem_cache_alloc` 시점) | **< 0.5% (무시 가능)** |
| **KFENCE (Kernel Electric-Fence)** | `CONFIG_KFENCE=y` | 샘플링 기반 가드 페이지(Guard Page) 할당 및 `#PF` 하드웨어 예외 포획 | **< 1.0% (프로덕션 특화)** |
| **SLAB Freelist Randomization** | `CONFIG_SLAB_FREELIST_RANDOM=y` | Fisher-Yates 셔플 알고리즘으로 프리리스트 순서 무작위화 | **초기화 시점 단 1회 (< 0.1%)** |
| **Zero Memory Sanitization** | `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` | 객체 해제 시 0으로 즉각 소거하여 잔존 포인터 및 UAF 누출 방지 | **~1.5% - 2.5%** |

### 4.1 [1차 핵심 방어선] `CONFIG_SLAB_FREELIST_HARDENED`

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **쿠키 생성 및 인코딩**:
        - 각 `kmem_cache` 생성 시 CSPRNG 난수 쿠키(`s->random`)를 발급받음.
        - `freelist_ptr`를 저장할 때 `ptr ^ s->random ^ swab64(ptr_addr)` 공식으로 연산하여 평문 노출을 방지함.
    2.  **디코딩 및 무결성 검증**:
        - 할당 시 역연산을 수행하여 유효한 커널 슬랩 가상 주소 범위 및 8바이트 정렬 상태를 엄격히 대조함.
        - 공격자가 평문 주소를 덮어쓴 경우 역연산 결과가 유효하지 않은 엔트로피 쓰레기 값(`0x756acb91f00cb3ce`)으로 붕괴하여 즉각 감지됨.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **Freelist Poisoning 원천 무력화**:
        - 공격자가 `s->random` 쿠키와 청크의 주소를 사전에 탈취하지 못하는 한, 원하는 특정 구조체 주소를 정상 포인터로 위장할 수 없음.
    2.  **커널 패닉/웁스 트리거**:
        - 조작된 주소를 통한 임의 쓰기가 발생하기 전 할당 루틴에서 `[🛡️ SLUB FREELIST CORRUPTION DETECTED]` 예외를 즉각 발생시킴.

</div>

### 4.2 [2차 상시 감시선] `CONFIG_KFENCE` (Kernel Electric-Fence)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **샘플링 기반 가드 페이지 배치**:
        - 시스템 부팅 시 전용 KFENCE 풀을 할당하고, 객체마다 앞뒤로 접근 불가(`PROT_NONE`) 가드 페이지를 배치함.
        - 기본 주기(예: 100ms마다 1건)로 무작위 객체를 KFENCE 풀에 할당하여 모니터링함.
    2.  **하드웨어 MMU 페이지 폴트(`#PF`) 유발**:
        - 인접 청크를 넘어서는 1바이트 오버플로우나 해제 후 접근(UAF) 발생 시 가드 페이지를 건드려 CPU 하드웨어 `#PF` 예외를 즉각 포획함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **프로덕션 환경 상시 배치 가능**:
        - 기존 KASAN의 200~300% 오버헤드와 달리 1% 미만의 극저부하로 운용 가능함.
    2.  **Zero-day 힙 취약점 조기 탐지**:
        - 실제 익스플로잇 체인이 완성되기 전 힙 침범 단계를 정확한 콜스택과 함께 커널 로그(`dmesg`)에 기록함.

</div>

---

## 5. 실습 환경 및 공격 시뮬레이션 데모 (`slab_demo.c`)

본 실습에서는 CVE-2022-0185 / CVE-2021-22555 취약점을 모사한 C 언어 시뮬레이터(`slab_demo.c`)를 빌드하고, 취약 모드와 하드닝 모드의 동작 차이를 실측 검증함.

### 5.1 시뮬레이터 핵심 아키텍처 (`slab_demo.c`)

- **실습 소스 코드**: [`slab_demo.c`](../../assets/labs/scenarios/04-heap-slab/slab_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/scenarios/04-heap-slab/slab_demo.c)
- **메모리 구조**: SLUB `kmalloc-128` 캐시 풀(청크 4개)과 인접 배치된 로봇 보행 제어기(`robot_gait_config_t`) 구조체 모델링.
- **방어 로직 구현**: `mm/slub.c` 커널 소스의 `freelist_ptr_encode()` 및 `freelist_ptr_decode()` 함수를 충실히 구현하여 XOR 쿠키 난독화 검증 시뮬레이션.

```c
/* labs/scenarios/04-heap-slab/slab_demo.c 포인터 난독화 루틴 */
static inline uint64_t encode_freepointer(mock_kmem_cache_t *cache, uint64_t next_obj_addr, uint64_t slot_addr) {
    if (!cache->hardened_enabled) {
        return next_obj_addr; /* 평문 프리포인터 (취약 모드) */
    }
    return next_obj_addr ^ cache->random_cookie ^ swab64(slot_addr);
}

static inline uint64_t decode_freepointer(mock_kmem_cache_t *cache, uint64_t stored_val, uint64_t slot_addr) {
    if (!cache->hardened_enabled) {
        return stored_val; /* 평문 반환 */
    }
    return stored_val ^ cache->random_cookie ^ swab64(slot_addr);
}
```

---

### 5.2 공격 실행 및 물리적 재난 경고 로그 (Attack Execution Logs)

취약 모드(`SLAB_HARDENED=n`)에서 힙 오염을 감행했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 취약 모드 실행 (SLAB Freelist Hardening 부재 환경)
cd labs/scenarios/04-heap-slab && make run-attack
```

**런타임 경고 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot Kernel Heap Overflow & SLAB Hardening Lab (CVE-2022-0185) 
======================================================================

[MODE 2: HEAP OVERFLOW & FREELIST POISONING WITHOUT HARDENING (SLAB_HARDENED=n)]
[*] Initializing baseline SLUB cache: Plaintext freelist pointers...
[*] Attacker triggers CVE-2022-0185 1-byte heap out-of-bounds write on Chunk 0...
    [!] Vulnerable write overflows Chunk 0 boundary into Free Slot 1's freelist pointer!
    [!] Freelist poisoned: Slot 1 -> freelist_ptr overwritten to 0x7ffd26e601b0 (Victim Gait Config)
[*] Attacker requests kmalloc-128: Allocator returns hijacked address: 0x7ffd26e601b0!
[*] Attacker writes malicious kinematics configuration directly into kernel heap memory...

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Kernel Heap Arbitrary Overwrite! 
======================================================================
  [*] SLUB Freelist Hijacked: Target object allocated into arbitrary kernel struct!
  [*] Current Memory: Kernel Heap Space (SLUB kmalloc-128)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & BIPEDAL BALANCE COLLAPSE] ---
  [🔴 PHYSICAL HAZARD] Pitch Axis Proportional Gain: 150.0 -> 9500.0 (RESONANCE RUNAWAY)
  [🔴 PHYSICAL HAZARD] Damping Factor (Kd): 12.0 -> 0.0 (ZERO DAMPING: UNDAMPED OSCILLATION)
  [🔴 PHYSICAL HAZARD] Yaw Spin Oscillation: 1.2 -> 32.5 rad/s (HIGH-SPEED DISORIENTING TIP-OVER)
  [🔴 ROBOT COLLAPSE] Bipedal balance loop failed: Violent ground impact & gear breakage!
```

---

### 5.3 하드닝 모드 검증 및 커널 트랩 로그 (Hardened Defense & Safe E-Stop Logs)

`CONFIG_SLAB_FREELIST_HARDENED=y` 환경에서 동일 공격을 감행했을 때의 실측 로그:

```bash
# 하드닝 모드 실행 (XOR 쿠키 검증 및 안전 차단)
cd labs/scenarios/04-heap-slab && make run-hardened
```

**런타임 방어 및 페일세이프 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot Kernel Heap Overflow & SLAB Hardening Lab (CVE-2022-0185) 
======================================================================

[MODE 3: HEAP ATTACK INTERCEPTED BY SLAB FREELIST HARDENING & KFENCE]
[*] Initializing Hardened SLUB cache (CONFIG_SLAB_FREELIST_HARDENED=y)...
[*] Attacker triggers CVE-2022-0185 heap overflow: Attempts to poison Slot 1's freelist pointer...
    [!] Slot 1 poisoned with plaintext address: 0xffff888012345678
[*] Kernel executes kmalloc-128: Attempting to de-obfuscate Slot 1 freelist pointer...
    [*] Decoded address using XOR cookie & byte-swap: 0x756acb91f00cb3ce

======================================================================
 [🛡️ SLUB FREELIST CORRUPTION DETECTED] kmem_cache_alloc Trap! 
======================================================================
  [!] SLUB INTEGRITY TRAP: Freelist pointer corrupt detected in cache 'kmalloc-128'!
  [!] Forensic Analysis:
      Expected Pointer Pattern = Valid decoded slab offset within page
      Found Pointer = 0x756acb91f00cb3ce (Non-canonical / Corrupted Entropy Garbage)
      Defense Mechanism = CONFIG_SLAB_FREELIST_HARDENED XOR Cookie Validation
  [!] Allocation aborted: Arbitrary write hijacked: 0%. Kernel Panic / Oops triggered.

  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Spring-loaded parking brakes LOCKED. Robotic joints secured safely!
```

---

### 5.4 아키텍처 핵심 분석: Rooting (UID 0 / Ring 3) vs Kernel Heap Control (Ring 0)의 결정적 차이

시스템 보안에서 단순 루트 획득(Rooting)과 커널 힙 메모리 제어(Ring 0 Control)는 본질적으로 격리 수준이 완전히 다름:

```
[비교 영역]                  [루팅 상태 (UID 0 / Ring 3)]          [커널 힙 제어 (Ring 0 SLUB Hijack)]
실행 권한 레벨              CPU Ring 3 (유저 공간 모드)           CPU Ring 0 (슈퍼바이저 커널 모드)
하드웨어 메모리 매핑        가상 메모리 MMU 격리 하에 통제됨      전체 물리 메모리 및 커널 데이터 직통 쓰기
하드웨어 I/O 및 MMIO 제어    /dev 장치 드라이버 API 규약 준수      모터 버스 컨트롤러 MMIO 레지스터 직통 변조
SELinux / AppArmor 정책     MAC 보안 정책에 의해 차단 가능        커널 보안 검증 함수 포인터 자체를 패치/무력화
페일세이프 인터록 우회      소프트웨어 인터록 우회 불가           하드웨어 감시 워치독 카운터 강제 정지 가능
```

1. **루팅 권한(UID 0)의 한계**:
    - 루트 사용자는 시스템 파일 읽기/쓰기 및 프로세스 종료가 가능하지만, CPU 실행 레벨은 여전히 **Ring 3(유저 모드)**에 머무름.
    - 커널 메모리 직접 쓰기, 미등록 인터럽트 핸들러 등록, 하드웨어 타이머 레지스터 직접 조작은 MMU 및 CPU 링 아키텍처에 의해 물리 차단됨.
2. **커널 힙 제어(Ring 0 SLUB Hijack)의 전권 장악**:
    - 공격자가 슬랩 힙 오염을 통해 커널 내부 객체를 장악하면 CPU는 **Ring 0(슈퍼바이저 모드)**에서 공격자의 의도대로 코드를 수행하거나 데이터를 변조함.
    - SELinux 검증 훅(`security_hook_heads`), 커널 크레덴셜(`commit_creds`), 하드웨어 제어 레지스터를 실시간 무력화하여 완벽한 영구 침투(Rootkit) 및 물리 기구 파괴를 자행할 수 있음.

---

## 6. 엔지니어링 심층 분석 (Engineering Deep Dive)

### 6.1 Freepointer 암호화/복호화 공식의 수학적 안전성 증명

리눅스 커널 `mm/slub.c`에 정의된 포인터 난독화 공식:

$$\text{Encoded} = \text{ptr} \oplus s\text{->random} \oplus \text{swab64}(\text{ptr\_addr})$$

- **XOR 연산의 대칭성**:
  $$\text{Decoded} = \text{Encoded} \oplus s\text{->random} \oplus \text{swab64}(\text{ptr\_addr}) = \text{ptr}$$
- **엔트로피 확산 효과 (Byte Swapping)**:
  - 단순 $s\text{->random}$ XOR만 적용할 경우, 인접 슬롯들이 동일한 쿠키를 공유하므로 힙 주소 릭(Leak) 공격에 취약해짐.
  - 슬롯 자신의 주소에 64비트 엔디안 반전(`swab64`)을 적용함으로써, 하위 12비트(페이지 내 오프셋)의 변화가 상위 비트로 확산되어 슬롯마다 완전히 독립적인 마스킹 키가 동적 생성됨.

### 6.2 KFENCE 가드 페이지 매핑과 `#PF` 하드웨어 예외 트랩

KFENCE는 가상 메모리 페이징 기법을 결합하여 무오버헤드 경계 검증을 달성함:

```
[KFENCE 가상 메모리 풀 배치]
┌──────────────────┬──────────────────┬──────────────────┐
│  Guard Page 0    │  Sampled Object  │  Guard Page 1    │
│  (PROT_NONE)     │  (Allocated)     │  (PROT_NONE)     │
└──────────────────┴──────────────────┴──────────────────┘
         ▲                                     ▲
         │ (Underflow 시 즉각 #PF)             │ (Overflow 시 즉각 #PF)
```

1. **PTE `Present` 비트 클리어**: 가드 페이지의 페이지 테이블 엔트리(PTE)에서 `_PAGE_PRESENT` 비트를 0으로 설정하여 접근 권한을 제거함.
2. **하드웨어 인터셉트**: CPU가 경계를 벗어난 주소에 접근하는 즉시 MMU가 예외 벡터 14번(Page Fault `#PF`)을 발생시킴.
3. **폴트 핸들러 분기**: 커널 `do_page_fault()`가 KFENCE 주소 영역임을 확인하고, 커널 힙 손상이 발생하기 전에 호출 스택과 손상 위치를 출력하고 할당을 거절함.

### 6.3 SLUB Redzones 및 Object Poisoning

프로덕션 디버깅 커널 파라미터(`slub_debug=FZP`) 적용 시의 추가 방어 기법:

- **Redzone (`CONFIG_SLUB_DEBUG`)**:
  - 각 슬랩 객체의 앞뒤에 `0xcc` 또는 `0xbb` 바이트 패턴의 안전 완충 지대를 16바이트 추가 배치함.
  - 객체 해제 시 레드존 바이트가 변경되었는지 전수 조사하여 힙 오버플로우를 사후 포획함.
- **Poisoning**:
  - 미할당 객체의 데이터 영역을 `0x6b` 바이트로 채우고, 해제 시 `0xa5` 패턴을 기록하여 Use-After-Free 시 비정상 주소 역참조로 즉각 크래시를 유도함.

### 6.4 로봇 사이버-물리 페일세이프 아키텍처

사이버 위협이 물리적 기구 파손으로 전이되는 것을 방지하기 위한 이중 안전 계통:

1. **하드웨어 안전 워치독(Hardware Safety Watchdog)**:
   - 커널 내부 타이머 틱과 독립된 물리 MCU로 주기적 펄스(Heartbeat)를 송신함.
   - 커널 패닉 또는 SLUB 무결성 트랩 발생 시 100 μs 이내에 펄스가 중단되어 비상 인터럽트를 발령함.
2. **전원 차단 및 기계식 전자 브레이크 (Depower & Clamp)**:
   - 48V DC 서보 모터 전원 릴레이 코일의 전원을 강제 소자(De-energize)하여 모터 출력을 0W로 강등함.
   - 무여자 작동형(Power-off Engaged) 스프링 파킹 브레이크가 물리적으로 작동하여 5ms 이내 전 관절을 기계 고정함.

---

## 7. 공식 커널 문서 및 표준 보안 레퍼런스

- [Linux Kernel Documentation - SLUB Allocator](https://www.kernel.org/doc/html/latest/mm/slub.html)
- [Linux Kernel Documentation - Kernel Electric-Fence (KFENCE)](https://www.kernel.org/doc/html/latest/dev-tools/kfence.html)
- [CVE-2022-0185: Heap Overflow in Linux Kernel fs_context (NIST NVD)](https://nvd.nist.gov/vuln/detail/CVE-2022-0185)
- [CVE-2021-22555: 15 Years Old Linux Kernel Privilege Escalation in Netfilter](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
- [Alexander Popov: Linux Kernel Defense-in-Depth - Slab Freelist Hardening](https://a13xp0p0v.github.io/2020/02/15/slab-freelist-hardened.html)
