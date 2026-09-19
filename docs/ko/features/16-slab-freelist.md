# SLAB Freelist Hardening & Randomization (슬랩 프리리스트 무작위화 및 포인터 난독화)

## 1. 개요 및 배경

리눅스 커널의 핵심 메모리 관리 계층인 SLUB(Slab Allocator with Queues) 할당자는 커널 객체(`struct task_struct`, `struct cred`, 네트워크 버퍼, `file` 구조체 등)의 고속 빈번 할당 및 해제를 전담함. 그러나 전통적인 슬랩 할당 메커니즘은 공격자에게 매우 치명적인 악용 표면을 제공해 왔음:

1. **결정론적 선형 할당 (Deterministic Linear Allocation)**:
   - 새 슬랩 페이지가 생성될 때 가용 객체(Free Object)들이 메모리 주소 순서(`[0] -> [1] -> [2] -> [3]...`)대로 순차 연결됨.
   - 공격자는 취약한 객체 A를 할당받은 직후 희생자 객체 B(함수 포인터나 자격 증명 구조체)를 할당받아, A의 힙 버퍼를 선형 오버플로우시켜 B를 100% 확정적으로 변조하는 힙 그루밍(Heap Grooming/Spraying)을 수행함.
2. **평문 프리리스트 포인터 (Plaintext Free Pointer)**:
   - 해제된 객체 내부의 첫 8바이트에는 다음 가용 객체의 커널 가상 주소가 암호화 없이 평문으로 저장됨.
   - 힙 오버플로우나 UAF(Use-After-Free)를 통해 이 포인터를 공격자가 제어하는 임의의 커널 주소로 덮어쓰면, 다음 `kmem_cache_alloc()` 호출 시 해당 주소가 새 객체로 반환되는 **프리리스트 하이재킹(Freelist Hijacking / Arbitrary Write)**이 발생함.

리눅스 커널 6.12 LTS는 이 두 가지 구조적 결함을 차단하기 위해 다음 두 가지 하드닝 기능을 제공함:
- **`CONFIG_SLAB_FREELIST_RANDOM=y`**: 슬랩 페이지 초기화 시 프리리스트 순서를 무작위로 셔플하여 순차 할당 예측성을 제거함.
- **`CONFIG_SLAB_FREELIST_HARDENED=y`**: 프리리스트 포인터를 캐시별 난수 쿠키 및 주소 바이트 스왑과 XOR 연산하여 난독화하고, 포인터 오염 및 더블 프리(`BUG_ON`)를 즉시 탐지함.

---

## 2. 실세계 비유: 뒤섞인 물품 보관함과 암호화된 교환 열쇠

SLAB 프리리스트 하드닝의 방어 원리는 은행 대여금고와 암호화된 보관함 키 시스템에 비유할 수 있음:

1. **프리리스트 무작위화 (CONFIG_SLAB_FREELIST_RANDOM)**:
   - **전통적 커널 (순차 번호표 배부)**: 보관함 열쇠를 순서대로(1번, 2번, 3번, 4번...) 나누어 줌. 악당이 1번 보관함을 대여한 뒤 바로 다음 사람에게 2번 보관함이 배정될 것을 100% 확신하고 1번 보관함 벽을 뚫어 2번 보관함을 털어버림(힙 그루밍 오버플로우).
   - **무작위화 적용 커널 (추첨식 셔플 배부)**: 보관함 열쇠를 번호 순서가 아닌 무작위 추첨통(Fisher-Yates 셔플)에 넣고 섞어서 배부함(예: 4번, 1번, 7번, 0번...). 악당 옆 칸에 어떤 대상이 배정될지 예측할 수 없어 인접 공격이 원천 실패함.
2. **프리리스트 포인터 난독화 (CONFIG_SLAB_FREELIST_HARDENED)**:
   - **전통적 커널 (평문 다음 번호표)**: 보관함 안에 다음 가용 보관함의 번호가 "다음 칸: 0x1040"이라고 종이에 적혀 있음. 악당이 종이를 "다음 칸: VIP 금고 0xDEAD"로 위조하면 직원이 VIP 금고를 악당에게 열어줌(임의 쓰기).
   - **난독화 적용 커널 (일회용 암호화 직인)**: 종이의 번호표는 지점장만의 비밀 난수 쿠키(`s->random`)와 보관함 위치(`swab(addr)`)로 암호화되어 있음. 악당이 1글자라도 위조한 번호표를 제출하면 해독 시 엉뚱한 쓰레기 주소로 판명되어 즉시 비상벨(`kmem_cache: Free pointer corrupt`)이 울리고 직원이 체포됨.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 프리리스트 순서 무작위화 (`CONFIG_SLAB_FREELIST_RANDOM`)

```text
[ Slab Page Allocation ]
         │
         ▼
[ Determine Object Count N ] (e.g. N = 8)
         │
         ▼
[ Fisher-Yates Random Shuffle ]
  Pre-computed random_seq: [3, 0, 6, 1, 4, 7, 2, 5]
         │
         ▼
[ Construct Freelist Links ]
  Head -> Slot 3 -> Slot 0 -> Slot 6 -> Slot 1 -> Slot 4 -> Slot 7 -> Slot 2 -> Slot 5 -> NULL
```

1. **초기화 시점 셔플**:
   - `mm/slab_common.c`의 `cache_random_seq_create()`에서 Fisher-Yates 셔플 알고리즘을 수행하여 캐시 객체 수 크기의 순열 배열(`s->random_seq`)을 사전 생성함.
   - 새 슬랩 페이지가 버디 할당자로부터 공급될 때, `init_cache_random_seq()`와 `next_freelist_entry()`에 의해 미리 섞인 무작위 순서대로 프리리스트가 연결됨.
2. **힙 그루밍 무력화**:
   - 연속된 `kmem_cache_alloc()` 호출이 인접한 메모리 오프셋에 떨어지지 않고 물리적 슬랩 슬롯 사이를 불규칙하게 도약함.
   - 공격자가 단일 객체 버퍼 오버플로우를 통해 특정 목표 구조체를 변조할 확률을 대폭 감소시킴.

### 3.2 프리리스트 포인터 암호화 및 검증 (`CONFIG_SLAB_FREELIST_HARDENED`)

```text
인코딩 (객체 해제 시):
  encoded_ptr = ptr ^ s->random ^ swab(ptr_addr)

디코딩 (객체 할당 시):
  decoded_ptr = encoded_ptr ^ s->random ^ swab(ptr_addr)
```

1. **암호화 구성 요소**:
   - `ptr`: 연결할 다음 가용 슬랩 객체의 실제 가상 주소.
   - `s->random`: `kmem_cache_create()` 시점 커널 CSPRNG로부터 생성된 캐시 고유의 64비트 비밀 난수 쿠키.
   - `swab(ptr_addr)`: 포인터가 저장된 현재 메모리 주소(`ptr_addr`)의 바이트 스왑(Endian Swap) 값. 주소 의존성을 추가하여 다른 위치로 복사된 메타데이터 재사용을 방지함.
2. **변조 감지 메커니즘**:
   - 공격자가 힙 오버플로우로 `encoded_ptr`를 조작할 경우, `s->random`을 알지 못하므로 디코딩 결과는 완전히 무작위화된 비정규 가상 주소가 됨.
   - 비정규 주소 역참조 시 커널 Page Fault가 발생하거나, SLUB 내부의 프리리스트 정합성 검사에서 `kmem_cache: Free pointer corrupt` 오류 메시지와 함께 즉각 안전하게 종료됨.
3. **더블 프리(Double Free) 즉시 탐지**:
   - `set_freepointer()` 내부에서 `BUG_ON(object == fp)` 검사를 수행함. 동일한 객체를 연속 해제하여 자기 자신을 가리키는 순환 루프가 형성되는 즉시 `Oops - BUG`를 트리거함.

---

## 4. 인터랙티브 아키텍처 다이어그램

다음 다이어그램은 프리리스트 무작위 순열 할당, 포인터 인코딩/디코딩 수학적 연산, 힙 오버플로우 변조 시 트랩 발생 메커니즘을 대화형으로 제공함:

<iframe src="../../assets/diagrams/slab-freelist/architecture.html" width="100%" height="700px" style="border: 1px solid #334155; border-radius: 8px; margin: 16px 0;"></iframe>

---

## 5. 커널 설정 및 빌드 플래그

### 5.1 Kconfig 설정 (`configs/features/slab-freelist.config`)

```ini
# Hardening Feature: SLAB Freelist Hardening & Randomization
# 프리리스트 포인터 난독화 및 변조 탐지 활성화
CONFIG_SLAB_FREELIST_HARDENED=y

# 슬랩 페이지 초기화 시 프리리스트 순서 무작위 셔플 활성화
CONFIG_SLAB_FREELIST_RANDOM=y

# SLUB 할당자 및 디버깅 지원
CONFIG_SLUB=y
CONFIG_SLUB_DEBUG=y

# 검증용 LKDTM 테스트 프레임워크
CONFIG_LKDTM=y
```

---

## 6. 실습 및 검증 결과

### 6.1 4개 시나리오 듀얼 아키텍처 실기 검증 매트릭스

본 실습은 x86_64 및 ARM64 환경에서 각각 Hardened 및 Baseline 커널을 교차 검증함.

| 시나리오 | 타깃 아키텍처 | 빌드 설정 | 연속 할당 인접률 (Adjacency) | 프리 포인터 난독화 | LKDTM SLAB_FREE_DOUBLE 결과 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **시나리오 1** | **ARM64** | `slab-freelist` (Hardened) | <span style="color:#22c55e">**0% (완전 비선형)**</span> | <span style="color:#22c55e">**적용 (XOR 암호화)**</span> | <span style="color:#22c55e">**차단 성공 (`BUG at mm/slub.c:547`)**</span> |
| **시나리오 2** | **ARM64** | `slab-freelist-disabled` | <span style="color:#ef4444">선형 순차 (결정론적)</span> | <span style="color:#ef4444">미적용 (평문 주소)</span> | <span style="color:#ef4444">미탐지 (비정상 통과)</span> |
| **시나리오 3** | **x86_64** | `slab-freelist` (Hardened) | <span style="color:#22c55e">**0% (완전 비선형)**</span> | <span style="color:#22c55e">**적용 (XOR 암호화)**</span> | <span style="color:#22c55e">**차단 성공 (`BUG at mm/slub.c:547`)**</span> |
| **시나리오 4** | **x86_64** | `slab-freelist-disabled` | <span style="color:#ef4444">선형 순차 (결정론적)</span> | <span style="color:#ef4444">미적용 (평문 주소)</span> | <span style="color:#ef4444">미탐지 (비정상 통과)</span> |

### 6.2 Hardened 실기 로그 (더블 프리 즉시 차단)

```text
[Test 1/2] Real-World SLUB Freelist Hardening PoC
[*] CONFIG_SLAB_FREELIST_RANDOM: ENABLED
[*] Sequential Adjacency Rate:   0% (0/7 matches)
[*] Allocation Sample Offsets:
    [0] 0xffff000000d9a300
    [1] 0xffff000000d9a1c0
    [2] 0xffff000000d9afc0
    [3] 0xffff000000d9adc0
[+] DEFENSE ACTIVE: Freelist layout is randomized via Fisher-Yates shuffle.

[*] CONFIG_SLAB_FREELIST_HARDENED: ENABLED
[*] Pointer Obfuscated:            YES
[+] DEFENSE ACTIVE: Free pointer is obfuscated: ptr ^ cookie ^ swab(addr)

[Test 2/2] Triggering LKDTM SLAB_FREE_DOUBLE Test
[    4.520918] kernel BUG at mm/slub.c:547!
[    4.535371] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP
[    4.538302] pc : kmem_cache_free+0x280/0x2d8
[    4.552237] lr : lkdtm_SLAB_FREE_DOUBLE+0x5c/0x7c
[+] CONFIG_SLAB_FREELIST_HARDENED의 BUG_ON(object == fp) 검사가 더블 프리를 즉각 격추함!
```

---

## 7. 보안 효과 및 트레이드오프

### 7.1 보안 효과
1. **힙 그루밍(Heap Grooming) 원천 차단**: 객체 할당 순서가 비결정론적으로 분산되어, 취약 객체 바로 뒤에 희생자 객체를 배치하려는 스프레이 공격의 성공률이 극단적으로 낮아짐.
2. **프리리스트 하이재킹 무력화**: 오버플로우로 다음 포인터를 임의 변조하더라도, 디코딩 단계에서 쿠키 불일치로 무효 주소가 생성되어 공격자가 원하는 주소에 객체를 할당받는 공격이 불가능함.
3. **단순 더블 프리 신속 탐지**: 동일 포인터가 2회 연속 해제될 때 지연 없이 `BUG_ON`으로 즉각 커널 패닉을 유도하여 힙 오염 확산을 차단함.

### 7.2 트레이드오프
1. **극히 미미한 CPU 오버헤드**: 페이지 생성 시 1회 셔플 및 포인터 읽기/쓰기 시 단순 XOR + 바이트 스왑 연산만 수행하므로 성능 영향은 0.5% 미만임.
2. **슬랩 내부 객체 재배치 한정**: 무작위화는 동일 슬랩 페이지 내부 슬롯 간 순서에 한정되며, 페이지 간의 배치 무작위화는 페이지 할당자 레벨에서 보완되어야 함.

---

## 8. 결론

`CONFIG_SLAB_FREELIST_RANDOM`과 `CONFIG_SLAB_FREELIST_HARDENED`는 별도의 추가 메모리 오버헤드 없이도 리눅스 커널 슬랩 할당자의 예측 가능성을 제거하고 힙 기반 공격 체인을 효과적으로 무력화하는 필수 기초 방어선임.

