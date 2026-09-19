# Heap Memory Zeroing on Alloc & Free (힙 메모리 자동 0 초기화)

## 1. 개요 및 배경

리눅스 커널에서 동적으로 할당되는 힙 메모리(SLUB 슬랩 할당자 객체 및 버디 페이지 할당자 페이지)는 전통적으로 성능 극대화를 위해 할당 및 해제 시 메모리를 별도로 초기화하지 않고 그대로 반환함. 개발자가 명시적으로 `kzalloc()`이나 `__GFP_ZERO` 플래그를 지정하지 않고 `kmalloc()`을 호출할 경우, 해당 메모리 영역에는 이전에 같은 크기의 슬랩 슬롯을 사용하던 프로세스나 커널 서브시스템이 남겨둔 잔류 데이터가 고스란히 남아있게 됨.

이러한 미초기화 힙 메모리는 커널 보안에 두 가지 중대한 위협을 초래함:

1. **초기화되지 않은 커널 메모리 정보 누출 (Uninitialized Memory Disclosure, CWE-457)**:
   - 구조체 할당 후 특정 필드만 초기화하거나, 컴파일러가 필드 정렬을 위해 삽입한 구조체 패딩(Padding) 바이트를 채우지 않은 상태로 `copy_to_user()`를 호출하면, 이전 객체가 사용하던 암호화 키, 커널 포인터, 민감 토큰이 유저 공간으로 여과 없이 유출됨.
2. **Use-After-Free(UAF, CWE-416) 익스플로잇 악용 표면 제공**:
   - 객체가 `kfree()`로 반환된 이후에도 민감한 함수 포인터나 상태 정보가 메모리에 계속 유지됨. 공격자가 댕글링 포인터를 보유하고 있을 경우 해제된 메모리의 잔존 데이터를 읽어 KASLR 주소를 유출하거나 악성 데이터를 주입하는 발판으로 악용함.
   - 또한, 전원 차단 직후 메모리를 덤프하는 콜드 부트(Cold Boot) 공격이나 라이브 포렌식 분석 시 해제된 객체 내부의 비밀 데이터가 손쉽게 복원될 위험이 존재함.

리눅스 커널 6.12 LTS는 이러한 구조적 정보 누출 및 잔류 데이터 위협을 원천 완화하기 위해 다음 두 가지 Kconfig 하드닝 옵션을 제공함:
- **`CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`**: 메모리 할당 시(`slab_post_alloc_hook`) 자동으로 전체 객체 및 페이지를 `0x00`으로 초기화함.
- **`CONFIG_INIT_ON_FREE_DEFAULT_ON=y`**: 메모리 해제 시(`slab_free_hook`) 즉시 객체 및 페이지를 `0x00`으로 덮어써 잔류 데이터 수명(Lifetime)을 0으로 단축시킴.

---

## 2. 실세계 비유: 체크인 시 방역하는 렌터카와 퇴실 즉시 청소하는 호텔

힙 메모리 자동 0 초기화의 두 가지 메커니즘은 일상생활의 위생 관리 프로세스에 비유할 수 있음:

1. **할당 시 0 초기화 (`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`) - 렌터카 불스원샷 방역**:
   - **전통적 커널 (청소 없는 렌터카)**: 이전 운전자가 차를 반납한 뒤 세차나 청소 없이 다음 운전자에게 그대로 차를 인도함. 차 안에 이전 사람이 흘리고 간 지갑, 영수증, 비밀 서류(암호화 키, 커널 포인터)가 그대로 남아있어 새 탑승자가 손쉽게 이를 훔쳐봄.
   - **초기화 적용 커널 (인도 직전 실내 세차)**: 새 운전자에게 차를 넘겨주기 직전 직원이 실내를 완벽하게 청소하고 소독함. 이전 운전자가 무엇을 남겼든 새 운전자는 먼지 하나 없는 깨끗한 상태(모두 `0x00`)의 차만 인수받음.
2. **해제 시 0 소거 (`CONFIG_INIT_ON_FREE_DEFAULT_ON`) - 퇴실 즉시 침구 교체 호텔**:
   - **전통적 커널 (다음 손님 올 때까지 방치)**: 손님이 체크아웃하고 나가도 다음 손님이 예약할 때까지 방을 어지럽혀진 채로 방치함. 청소되지 않은 빈방에 도둑(댕글링 포인터)이 몰래 들어가 침대 밑에 남겨진 귀중품을 훔쳐감(UAF 정보 유출).
   - **소거 적용 커널 (체크아웃 즉시 침구 수거 및 락스 소독)**: 손님이 방 키를 반납(`kfree()`)하는 1초 즉시 청소팀이 들어가 모든 침구를 수거하고 금고와 서랍을 비움. 도둑이 뒤늦게 빈방에 침입하더라도 텅 빈 방(모두 `0x00`)만 마주하여 아무것도 건질 수 없음.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 할당 시 0 초기화 메커니즘 (`slab_post_alloc_hook`)

```text
[ kmalloc(256) / kmem_cache_alloc() ]
                │
                ▼
      [ __slab_alloc_node() ]
   (프리리스트에서 객체 슬롯 획득)
                │
                ▼
   [ slab_want_init_on_alloc() ]
 (static_branch: init_on_alloc 확인)
                │
         ┌──────┴──────┐
      true           false
         │             │
         ▼             ▼
[ memset(p, 0, size) ] [ 미초기화 유지 ]
(전체 객체 0x00 클리어)
                │
                ▼
   [ Caller에게 안전한 버퍼 반환 ]
```

1. **정적 브랜치 검사**:
   - `include/linux/mm.h`의 `want_init_on_alloc(flags)` 및 `mm/slab.h`의 `slab_want_init_on_alloc(flags, c)`가 `init_on_alloc` 정적 키를 평가함.
   - 커널 생성자(`c->ctor`)가 등록된 캐시나 RCU 지연 해제(`SLAB_TYPESAFE_BY_RCU`) 객체를 제외한 일반 슬랩 할당에 대해 초기화 플래그를 `true`로 설정함.
2. **슬랩 사후 처리 훅 (`slab_post_alloc_hook`)**:
   - `mm/slub.c`의 `slab_post_alloc_hook()`에서 `memset(p[i], 0, zero_size)`를 호출하여 방금 할당된 메모리 블록을 0으로 덮어씀.
   - 버디 할당자(`mm/page_alloc.c`)의 경우 페이지 할당 시 `kernel_init_pages()`를 통해 페이지 전체를 0으로 소거함.

### 3.2 해제 시 0 소거 메커니즘 (`slab_free_hook`)

```text
[ kfree(ptr) / kmem_cache_free() ]
                │
                ▼
      [ slab_free_hook() ]
                │
                ▼
   [ slab_want_init_on_free() ]
  (static_branch: init_on_free 확인)
                │
         ┌──────┴──────┐
      true           false
         │             │
         ▼             ▼
[ memset(x, 0, orig_size) ] [ 메모리 방치 ]
(슬랩 레드존/메타데이터 제외 소거)
                │
                ▼
     [ set_freepointer() ]
   (프리리스트 체인에 반환)
```

1. **즉각적인 메모리 와이프**:
   - `mm/slub.c`의 `slab_free_hook()`에서 객체 해제 즉시 `memset(kasan_reset_tag(x), 0, orig_size)`를 수행함.
   - 슬랩 할당자의 무결성을 유지하기 위해 SLAB 레드존 및 객체 외부 프리 포인터 영역을 제외한 순수 페이로드 및 메타데이터 영역만 정밀하게 소거함.
2. **UAF 및 포렌식 차단**:
   - 해제된 직후 메모리 내용이 소거되므로, 취약한 커널 모듈이 해제된 포인터를 역참조하여 비밀 토큰을 읽더라도 `0`만 읽히게 됨.
   - 콜드 부트 공격이나 하이퍼바이저 수준 메모리 스캔 시에도 해제된 이전 데이터가 복원되지 않음.

---

## 4. 성능 영향도 및 트레이드오프 분석

| 비교 항목 | `init_on_alloc` | `init_on_free` | KASAN (참고) |
| :--- | :--- | :--- | :--- |
| **초기화 시점** | 할당 시 (`slab_post_alloc_hook`) | 해제 시 (`slab_free_hook`) | 섀도 메모리 마킹 |
| **CPU 캐시 영향** | **핫 캐시(Hot Cache)**: 직후 쓸 메모리 터치 | **콜드 캐시(Cold Cache)**: 곧 안 쓸 메모리 터치 | 섀도 메모리 추가 캐시 라인 소비 |
| **런타임 오버헤드** | **< 1.0%** (대부분 워크로드) | **3% ~ 5%** (일부 워크로드 최대 8%) | **~200%** (디버깅 전용) |
| **미초기화 누출 방어** | **완벽 방어 (100% Zeroed)** | **완벽 방어 (100% Zeroed)** | 탐지만 수행 (방어 불가) |
| **UAF 댕글링 읽기 방어** | 재할당 전까지 잔류 데이터 노출 | **해제 즉시 소거 (완전 방어)** | 탐지 및 크래시 유도 |
| **프로덕션 적합성** | **강력 권장 (기본 하드닝)** | 고보안 환경 권장 | 프로덕션 부적합 (개발/테스트용) |

---

## 5. 인터랙티브 아키텍처 다이어그램

본 랩에서 제공하는 인터랙티브 시뮬레이터는 SVG 동적 스트림, 할당 파이프라인 파티클 펄스 및 메모리 소거 파동(Wipe Wave)을 실시간으로 시각화함:

- **다이어그램 파일**: `docs/assets/diagrams/heap-init/architecture.html`
- **주요 시뮬레이션 탭**:
  1. `할당 시 자동 0 초기화`: `kmalloc` 파이프라인에서 0x00 클리어 파동이 버퍼를 소거하는 흐름.
  2. `해제 시 즉시 0 소거`: `kfree` 즉시 슬랩 내부의 구조체 필드가 모두 0으로 덮어써지는 흐름.
  3. `베이스라인 잔류 누출`: 미초기화 슬랩을 재할당받아 유저 공간으로 유출되는 취약점 시나리오.
  4. `비교 매트릭스`: Alloc vs Free vs KASAN 간의 오버헤드 및 방어 스펙트럼 비교.

---

## 6. 취약점 실습 및 검증 가이드

### 6.1 테스트 드라이버 및 유저스페이스 PoC

- **드라이버**: `/proc/vuln_heap_init` (권한 0666)
- **PoC 바이너리**: `/bin/exploit_heap_init` (비특권 사용자 `lab` 실행)
- **테스트 러너**: `/bin/test_heap_init`

```bash
# 비특권 사용자로 PoC 실행
/bin/exploit_heap_init
```

### 6.2 LKDTM 커널 테스트 트리거

커널 내장 LKDTM 모듈을 통해 슬랩 및 버디 페이지의 초기화 상태를 직접 검증함:

```bash
# 디버그 파일시스템 마운트
mount -t debugfs none /sys/kernel/debug

# 1. 슬랩 할당 초기화 검증
echo SLAB_INIT_ON_ALLOC > /sys/kernel/debug/provoke-crash/DIRECT

# 2. 버디 페이지 할당 초기화 검증
echo BUDDY_INIT_ON_ALLOC > /sys/kernel/debug/provoke-crash/DIRECT

# 3. 슬랩 해제 즉시 소거 검증
echo READ_AFTER_FREE > /sys/kernel/debug/provoke-crash/DIRECT

# 4. 버디 페이지 해제 즉시 소거 검증
echo READ_BUDDY_AFTER_FREE > /sys/kernel/debug/provoke-crash/DIRECT

# 커널 로그 확인
dmesg | grep -E "lkdtm:.*(initialized|poisoned|FAIL)"
```

- **하드닝 커널 기대 출력**:
  ```text
  lkdtm: Memory appears initialized (0, no earlier values)
  lkdtm: Memory correctly poisoned (0)
  ```
- **취약 베이스라인 기대 출력**:
  ```text
  lkdtm: FAIL: Slab was not initialized
  lkdtm: FAIL: Memory was not poisoned!
  ```

---

## 7. 커널 설정 가이드

### 7.1 Kconfig 설정 (`configs/features/heap-init.config`)

```ini
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_LKDTM=y
```

### 7.2 런타임 부팅 파라미터 제어

Kconfig 컴파일 설정을 커널 부팅 명령줄 인수를 통해 런타임에 오버라이드할 수 있음:
- `init_on_alloc=1` 또는 `init_on_alloc=0`
- `init_on_free=1` 또는 `init_on_free=0`

---

## 8. 결론

`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`과 `CONFIG_INIT_ON_FREE_DEFAULT_ON`은 커널 힙 메모리 라이프사이클의 양쪽 끝단(할당 및 해제)에서 잔류 비밀 데이터를 기계적으로 소거함으로써, 광범위한 미초기화 정보 누출(CWE-457)과 UAF(CWE-416) 익스플로잇 가능성을 근본적으로 잠식시키는 필수 하드닝 기법임.

