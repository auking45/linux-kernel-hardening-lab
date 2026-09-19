# Hardened Usercopy (유저 공간 복사 경계 검증)

## 1. 개요 및 배경

리눅스 커널에서 커널 공간(Ring 0 / EL1)과 유저 공간(Ring 3 / EL0) 사이의 데이터 교환은 주로 `copy_to_user()` 및 `copy_from_user()` 원시 함수를 통해 이루어짐. 시스템 콜 매개변수 복사, 파일 I/O, 디바이스 드라이버의 `read()` / `write()` / `ioctl()` 등 커널과 유저 간의 거의 모든 상호작용이 이 계층을 거침.

전통적인 리눅스 커널 구현에서는 성능 최적화를 위해 복사하려는 대상 객체(슬랩 할당 메모리, 커널 스택 버퍼 등)의 실제 유효 할당 크기를 런타임에 검증하지 않고 유저가 요청한 길이만큼 단순 메모리 복사를 수행함:

1. **힙 경계 초과 메모리 노출 (Heap Out-of-bounds Read / Information Leak, CWE-125)**:
   - 디바이스 드라이버나 네트워크 스택에서 64바이트 크기의 슬랩 객체를 할당한 후, 길이 검증 버그로 인해 128바이트를 유저 공간으로 복사(`copy_to_user`)하는 경우 발생.
   - 요청된 64바이트 이후의 인접 슬랩 객체 데이터, 잔류 암호화 키, 함수 포인터, 슬랩 할당자 메타데이터(`freelist` 포인터 등)가 유저 공간으로 무방비 유출됨. 이는 KASLR 우회 및 추가 공격 체인의 결정적 발판이 됨.
2. **힙 경계 초과 메모리 덮어쓰기 (Heap Out-of-bounds Write / Memory Corruption, CWE-787)**:
   - 반대로 `copy_from_user()`를 통해 64바이트 버퍼에 유저 공간의 128바이트 데이터를 검증 없이 덮어쓰면 인접 힙 객체와 메타데이터가 파괴되어 원격 코드 실행(RCE) 및 권한 상승으로 직결됨.
3. **커널 실행 코드 (.text) 직접 누출 및 KASLR 무력화**:
   - 커널 함수 포인터나 실행 코드 영역(`[_stext, _etext]`)의 주소가 유저 공간으로 직접 복사될 경우, 공격자는 커널의 실시간 기계어 바이너리를 추출하여 가젯(ROP/JOP) 오프셋을 역산함으로써 KASLR을 100% 무력화함.
4. **스택 프레임 초과 누출 (Stack Frame Escaping)**:
   - 현재 실행 중인 스택 프레임을 벗어나 이전 호출자의 로컬 변수나 스택 카나리, 리턴 주소를 유저 공간으로 유출하거나 조작함.

리눅스 커널 6.12 LTS의 `CONFIG_HARDENED_USERCOPY=y`는 `copy_to_user()` 및 `copy_from_user()`의 진입점에 강력한 런타임 인터셉터(`__check_object_size()`)를 삽입하여, 슬랩 할당자 크기, 스택 프레임 유효 범위, 커널 실행 코드 영역을 엄격히 검증하고 위반 감지 시 즉각 `usercopy_abort()` 및 커널 `BUG()`로 프로세스를 격리 차단함.

---

## 2. 실세계 비유: 은행 창구의 방탄 유리 서류 투입구

`CONFIG_HARDENED_USERCOPY`의 보호 메커니즘은 은행 창구의 **보안 서류 투입구**에 비유할 수 있음:

```
[ 은행 내부 (커널 힙/스택/코드) ]               [ 고객 대기석 (유저 공간) ]
  ┌────────────────────────┐                    ┌──────────────────────┐
  │ 64B 신청 서류 (Chunk A)│                    │                      │
  │ 64B 금고 열쇠 (Chunk B)│                    │ 고객 접수 바구니     │
  └───────────┬────────────┘                    └──────────▲───────────┘
              │                                            │
              ▼                                            │
    [ 방탄 투입구: __check_object_size ]                   │
    - 통과 규격: 정확히 64B 신청서만 허용                  │
    - 128B 초과 투입 시도? ───(⛔ 비상 셔터 폐쇄!)─────────┘
      (금고 열쇠 딸려나옴 감지 -> 경보 울리고 창구 폐쇄)
```

1. **전통적 커널 (경비 없는 뻥 뚫린 창구)**:
   - 은행 직원이 고객에게 64바이트짜리 양식을 건네주려다 실수로 책상 옆에 놓인 금고 비밀번호 메모지(인접 청크 B)까지 묶어서 128바이트 뭉치로 창구 너머로 밀어 넣음.
   - 고객은 자신이 요청하지 않은 은행 내부 기밀 메모까지 고스란히 손에 쥐게 됨(힙 오버리드 정보 누출).
2. **하드닝 커널 (규격 검사 센서가 장착된 방탄 투입구)**:
   - 투입구에 정밀 센서(`__check_object_size`)가 설치되어 서류의 크기와 출처를 실시간 계측함.
   - 64바이트 규격 양식 이외에 뒤따라오는 종이가 감지되거나, 은행 금고 벽면 타일(커널 실행 코드)을 뜯어서 넘기려는 시도가 감지되는 즉시 강철 방탄 셔터가 쾅 닫히고 비상 경보(`usercopy_abort` -> `BUG()`)를 울리며 위험을 원천 차단함.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 `copy_to_user` 인터셉트 파이프라인

`include/linux/uaccess.h`에서 유저 공간 복사 함수는 컴파일 타임 및 런타임 검사 계층을 거침:

```text
copy_to_user(to, from, n)
       │
       ▼
check_copy_size(from, n, is_source=true)
       │
       ▼
check_object_size(addr, bytes, is_source)
       │
       ▼ (CONFIG_HARDENED_USERCOPY=y 인 경우)
__check_object_size(ptr, n, to_user)
       │
       ├─► 1. check_bogus_address(): 널 포인터 및 랩어라운드 주소 검증
       ├─► 2. check_kernel_text_object(): 커널 코드 영역([_stext, _etext]) 유출 차단
       ├─► 3. check_stack_object(): 프로세스 스택 프레임 범위 초과 검증
       └─► 4. check_heap_object(): SLUB 슬랩 객체 유효 경계(__check_heap_object) 검증
```

### 3.2 슬랩 객체 경계 검증 (`__check_heap_object`)

SLUB 할당자(`mm/slub.c`) 내부에서 실행되는 슬랩 검증 로직은 다음과 같음:

```c
void __check_heap_object(const void *ptr, unsigned long n,
                         const struct slab *slab, bool to_user)
{
    struct kmem_cache *s = slab->slab_cache;
    unsigned int offset = (ptr - slab_address(slab)) % s->size;

    /* 화이트리스트 유저 복사 허용 범위 내에 완전히 포함되는지 확인 */
    if (offset >= s->useroffset &&
        offset - s->useroffset <= s->usersize &&
        n <= s->useroffset - offset + s->usersize)
        return; /* 정상 검증 통과 */

    /* 경계 초과 시 커널 버그 유발 */
    usercopy_abort("SLUB object", s->name, to_user, offset, n);
}
```

- 일반적인 `kmalloc` 캐시의 경우 `s->useroffset = 0`, `s->usersize = s->object_size`로 설정됨.
- 64바이트 객체(`kmalloc-64`)에서 오프셋 0부터 128바이트를 복사하려 하면 `n (128) > s->usersize (64)` 조건에 의해 즉각 `usercopy_abort()`가 호출됨.

### 3.3 커널 코드 및 스택 보호

1. **커널 텍스트 보호 (`check_kernel_text_object`)**:
   ```c
   static inline void check_kernel_text_object(const unsigned long ptr,
                                               unsigned long n, bool to_user)
   {
       unsigned long textlow = (unsigned long)_stext;
       unsigned long texthigh = (unsigned long)_etext;

       if (overlaps(ptr, n, textlow, texthigh))
           usercopy_abort("kernel text", NULL, to_user, ptr - textlow, n);
   }
   ```
   - 커널 시작 심볼 `_stext`부터 종료 심볼 `_etext` 사이의 메모리를 유저 공간으로 복사하려는 모든 시도를 차단함.
2. **비정상 중단 처리 (`usercopy_abort`)**:
   - `pr_emerg("Kernel memory %s attempt detected %s %s ... (offset %lu, size %lu)!\n", ...)` 커널 긴급 로그를 남긴 후 `BUG()`를 호출하여 Oops 및 악성 스레드 강제 종료를 유발함.

---

## 4. 인터랙티브 아키텍처 다이어그램

아래 시뮬레이터는 기본 베이스라인(경계 검사 없음)과 하드닝 활성화 상태의 유저 복사 제어 흐름 차이를 동적으로 비교 시연함.

<iframe src="../../assets/diagrams/hardened-usercopy/architecture.html" width="100%" height="750px" style="border:none; border-radius:8px; overflow:hidden;"></iframe>

---

## 5. 실습 환경 구성 및 빌드 가이드

### 5.1 커널 설정 구성

```ini
# configs/features/hardened-usercopy.config
CONFIG_HARDENED_USERCOPY=y
CONFIG_LKDTM=y
```

### 5.2 빌드 및 부팅 명령어

#### ARM64 (aarch64) 실습
```bash
# 하드닝 적용 커널 부팅 및 자동 테스트
./scripts/run_lab.sh --arch arm64 --feature hardened-usercopy --test test_hardened_usercopy

# 베이스라인 취약 커널 비교 부팅
./scripts/run_lab.sh --arch arm64 --feature hardened-usercopy-disabled --test test_hardened_usercopy
```

#### x86_64 실습
```bash
# 하드닝 적용 커널 부팅 및 자동 테스트
./scripts/run_lab.sh --arch x86_64 --feature hardened-usercopy --test test_hardened_usercopy

# 베이스라인 취약 커널 비교 부팅
./scripts/run_lab.sh --arch x86_64 --feature hardened-usercopy-disabled --test test_hardened_usercopy
```

---

## 6. 취약점 공격 및 방어 검증 실습

### 6.1 비특권 익스플로잇 PoC 검증 (`/bin/exploit_hardened_usercopy`)

비특권 계정 `lab` (UID 1000)에서 실행하여 슬랩 오버리드 및 커널 텍스트 누출 공격을 수행함.

#### 하드닝 커널 (`CONFIG_HARDENED_USERCOPY=y`) 결과
```text
=========================================================
  CONFIG_HARDENED_USERCOPY Proof of Concept Exploit
  UID: 1000 | GID: 1000 | PID: 106
=========================================================

[*] Test 1: Slab Heap Out-of-Bounds Memory Disclosure
[*] Attempting 128-byte copy_to_user from 64-byte SLUB allocation...
[+] [PASS] Child killed by signal 11 (Segmentation fault)!
[+] Protection ACTIVE: CONFIG_HARDENED_USERCOPY caught out-of-bounds copy.
[+] Kernel generated BUG() / usercopy_abort and aborted the exposure.

[*] Test 2: Kernel Code (.text) Disclosure
[*] Attempting copy_to_user directly from kernel function pointer...
[+] [PASS] Child killed by signal 11 (Segmentation fault)!
[+] Protection ACTIVE: Kernel text read blocked by check_kernel_text_object().

=========================================================
  PoC Summary:
  - Slab Heap Boundary Enforcement : PROTECTED
  - Kernel Text Read Enforcement   : PROTECTED
=========================================================
```

#### 커널 로그 (`dmesg`) 확인
```text
[   18.102145] vuln_usercopy: attempting copy_to_user(buf, chunk_a, 128) - exceeding 64-byte boundary!
[   18.102380] usercopy: Kernel memory exposure attempt detected from SLUB object 'kmalloc-64' (offset 0, size 128)!
[   18.102610] ------------[ cut here ]------------
[   18.102720] kernel BUG at mm/usercopy.c:102!
[   18.102850] Internal error: Oops - BUG: 00000000f2000800 [#1] PREEMPT SMP
```

#### 베이스라인 커널 (`CONFIG_HARDENED_USERCOPY` 미적용) 결과
```text
[*] Test 1: Slab Heap Out-of-Bounds Memory Disclosure
    [Child] read() succeeded! Received 128 bytes:
    [Child] Chunk A Header (0-63)   : PUBLIC_CHUNK_A_HEADER: Welcome to Hardened Usercopy Lab!...
    [Child] Chunk B Adjacent (64-127): LEAKED SECRET -> CONFIDENTIAL_KEY_IN_CHUNK_B_9999
[-] [FAIL] Child successfully extracted adjacent heap memory (exit code 42).
[-] Vulnerability CONFIRMED: CONFIG_HARDENED_USERCOPY is NOT active.
```

### 6.2 커널 LKDTM 공식 테스트 스위트 검증

커널 LKDTM 모듈을 통해 공식적인 슬랩 크기 및 텍스트 검증 루틴을 직접 유발함:

```bash
# 슬랩 객체 크기 초과 copy_to_user 테스트
echo USERCOPY_SLAB_SIZE_TO > /sys/kernel/debug/provoke-crash/DIRECT

# 커널 텍스트 copy_to_user 테스트
echo USERCOPY_KERNEL > /sys/kernel/debug/provoke-crash/DIRECT
```

- **하드닝 적용 시**: `usercopy: Kernel memory exposure attempt detected from SLUB object` 트리거 및 `kernel BUG` 방어 성공.
- **베이스라인 시**: `lkdtm: FAIL: bad usercopy not detected!` 실패 메시지 출력.

---

## 7. 성능 오버헤드 및 실무 적용 고려사항

1. **런타임 복사 오버헤드**:
   - `copy_to_user()` / `copy_from_user()` 호출마다 포인터와 크기 검증(`__check_object_size`)이 추가됨.
   - 전체 시스템 벤치마크 기준 CPU 오버헤드는 통상 **1% 미만**으로 측정되며 네트워크 및 디스크 대역폭 처리량에 미치는 영향은 극히 미미함.
2. **슬랩 화이트리스트 기능 (`kmem_cache_create_usercopy`)**:
   - 객체 전체가 아닌 특정 구조체 멤버만 유저 공간 복사를 허용해야 하는 보안 민감 객체의 경우 `kmem_cache_create_usercopy()`를 통해 화이트리스트 오프셋과 크기를 지정 가능함.
3. **프로덕션 적용 권고**:
   - Android Common Kernel (ACK), Ubuntu, Red Hat Enterprise Linux, ChromeOS 등 대다수의 현대 프로덕션 배포판에서 기본 활성화(`=y`)되어 출하되는 필수 보안 표준임.

---

## 8. FAQ 및 문제 해결

**Q1: `copy_to_user` 호출 시 크기가 상수(Constant)인 경우에도 검사가 작동하는가?**
- 컴파일러가 크기를 알 수 있는 경우 `__builtin_constant_p()`를 통해 컴파일 타임 검사가 수행되며, 할당 크기를 알 수 없는 런타임 포인터 복사의 경우 항상 `check_object_size()`가 호출되어 동적 슬랩 메타데이터를 검사함.

**Q2: 사용자 정의 슬랩 캐시(Custom kmem_cache)에서도 자동으로 보호되는가?**
- 보호됨. `kmem_cache_create()`로 생성된 모든 슬랩 캐시는 기본적으로 `s->usersize = s->object_size`로 초기화되어 할당 크기를 초과하는 유저 복사는 일괄 차단됨.

