# CONFIG_PAGE_TABLE_CHECK: 런타임 페이지 테이블 무결성 검증 및 불법 메모리 매핑 동기 탐지

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/page-table-check/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="CONFIG_PAGE_TABLE_CHECK Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: 불법 이중 매핑(Double Mapping) 및 지연된 메모리 오염(Delayed Corruption)

- **전통적인 메모리 관리자(Linux MM)의 한계와 지연된 결함 검출 문제**:
  - 기존 리눅스 커널의 가상 메모리 서브시스템은 성능 최적화를 위해 페이지 테이블 조작(PTE, PMD 설정) 시점에 광범위한 의미론적 유효성 검증을 매번 수행하지 않음.
  - 커널 내 레이스 컨디션, 드라이버의 결함 있는 `remap_pfn_range()` 호출, Use-After-Free(UAF) 페이지 재할당 버그가 발생할 경우:
    1. 동일한 물리 메모리 프레임(PFN)이 두 개 이상의 서로 다른 프로세스에 Read/Write 권한으로 동시에 매핑되는 **불법 이중 쓰기 매핑(Illegal Double Mapping)**이 발생할 수 있음.
    2. 익명 메모리(Anonymous Page, 힙/스택 등)와 파일 캐시 페이지(Named/File Page)가 동일한 물리 프레임을 가리키는 **메모리 타입 오염(Type Confusion)**이 발생할 수 있음.
  - 이러한 오염은 매핑 시점에는 적발되지 않고, 나중에 데이터가 덮어씌워지거나 시스템 크래시가 발생하는 한참 뒤에야 발견되어 디버깅이 극도로 어렵고 익스플로잇에 악용됨.
- **`CONFIG_PAGE_TABLE_CHECK`의 핵심 방어 철학**:
  - 유저 공간 페이지 테이블 엔트리(PTE, PMD, PUD)가 설정되거나 해제되는 **그 순간(Synchronously)**, 해당 페이지의 할당 유형과 매핑 카운터를 즉시 검증함.
  - 불법적인 다중 쓰기 매핑, 파일/익명 혼동 매핑, 잔여 UAF 매핑을 등록 즉시 포착하여 즉각적인 `BUG_ON()` 패닉을 유도함으로써 데이터 오염 확산 및 커널 권한 탈취를 원천 차단함.

### 1.2 직관적 실전 비유: 국가 토지 등기소와 분양권 이중 매매 방지 시스템 (The Land Registry vs Double-Selling Prevention Metaphor)

- **비유 설명**:
  - 물리 메모리 페이지를 **실제 존재하는 한 필지의 토지**, 페이지 테이블 엔트리(PTE)를 **토지 소유권 등기부 등본**, 프로세스 가상 주소를 **토지 구매자의 소유 증서**로 비유할 수 있음.
  - **하드닝 이전 (`page_table_check=off`)**:
    - 등기소 직원이 업무 과중을 이유로 등기 신청서가 들어올 때마다 해당 필지가 이미 다른 사람에게 배타적 건축 권한(Read/Write)으로 등록되어 있는지 원장을 대조하지 않고 도장을 찍어줌.
    - 악의적인 기획부동산(공격자)이 동일한 토지를 여러 구매자에게 전용 주거권(익명 RW 매핑)으로 이중, 삼중 매도(이중 매핑)하여 사기를 쳐도, 실제 건축 공사가 시작되어 충돌이 일어날 때까지 아무도 불법을 눈치채지 못함.
  - **하드닝 적용 (`page_table_check=on`)**:
    - 모든 토지 필지마다 실시간 감시 바코드(`struct page_table_check` 원자적 카운터)가 부여됨.
    - 등기소에서 새로운 등기를 등록하는 순간, 시스템이 즉각 바코드를 조회하여 "이미 다른 소유자에게 독점 건축권(RW)이 부여된 필지"임이 감지되면 그 자리에서 경보를 울리고 등기소 전체 업무를 즉각 정지(`BUG_ON()`)시킴.
    - 이로써 불법 이중 매매가 성립되는 순간 시스템 레벨에서 거래를 물리적으로 동기 차단함.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 페이지 확장 인프라 (`PAGE_EXTENSION`) 기반 카운터 추적

- **`struct page_table_check` 메타데이터 구조체**:
  - `mm/page_table_check.c`에 구현된 구조체로, 각 물리 페이지(`struct page`)마다 할당된 `page_ext` 메모리에 저장됨:
    ```c
    /* mm/page_table_check.c */
    struct page_table_check {
        atomic_t anon_map_count;  /* 익명 페이지 매핑 참조 횟수 */
        atomic_t file_map_count;  /* 파일/명명된 페이지 매핑 참조 횟수 */
    };
    ```
- **정적 브랜치 키 (`page_table_check_disabled`)**:
  - 커널 부팅 시 `page_table_check=on` 또는 `CONFIG_PAGE_TABLE_CHECK_ENFORCED=y`가 적용되면 `static_branch_disable(&page_table_check_disabled)`를 통해 런타임 검증 훅을 무조건 활성화함:
    ```c
    DEFINE_STATIC_KEY_TRUE(page_table_check_disabled);
    EXPORT_SYMBOL(page_table_check_disabled);
    ```

### 2.2 동기식 매핑 및 해제 검증 규칙 (Validation Rules)

- **새로운 페이지 테이블 엔트리 등록 시 (`page_table_check_set`)**:
  ```c
  /* mm/page_table_check.c */
  static void page_table_check_set(unsigned long pfn, unsigned long pgcnt, bool rw)
  {
      ...
      anon = PageAnon(page);
      for (i = 0; i < pgcnt; i++) {
          struct page_table_check *ptc = get_page_table_check(page_ext);
          if (anon) {
              /* 익명 페이지는 절대 파일 카운터를 가질 수 없음 */
              BUG_ON(atomic_read(&ptc->file_map_count));
              /* 익명 페이지는 둘 이상의 프로세스에 RW 권한으로 동시 매핑될 수 없음 */
              BUG_ON(atomic_inc_return(&ptc->anon_map_count) > 1 && rw);
          } else {
              /* 파일 페이지는 절대 익명 카운터를 가질 수 없음 */
              BUG_ON(atomic_read(&ptc->anon_map_count));
              BUG_ON(atomic_inc_return(&ptc->file_map_count) < 0);
          }
      }
  }
  ```
- **페이지 엔트리 해제 시 (`page_table_check_clear`)**:
  - 페이지 테이블에서 매핑이 제거될 때 카운터를 정확히 감소시키며, 카운터가 음수가 되거나 반대 유형의 카운터가 남아있을 경우 즉시 `BUG_ON()`을 발동함.
- **페이지 해제 시점 잔여 매핑 검증 (`page_table_check_free`)**:
  - 슬랩/버디 할당자에서 페이지를 해제(`free_pages_prepare()`)할 때 `page_table_check_free()`가 호출되어 두 카운터가 모두 0인지 검사함으로써 Use-After-Free 댕글링 매핑을 동기 탐지함.

---

## 3. 실습 환경 및 구현 상세 (Hands-on Lab Implementation)

### 3.1 취약 타깃 드라이버 (`vuln_page_table_check.c`)

- `/proc/vuln_page_table_check` (모드 0666) 인터페이스 제공:
  - **하드웨어 및 커널 텔레메트리**:
    - `ARCHITECTURE`: `x86_64` 또는 `arm64 (aarch64)`
    - `CONFIG_PAGE_TABLE_CHECK`: `ENABLED (y)`
    - `STATIC_KEY_STATE`: `page_table_check_disabled` 상태 판별
    - `PROTECTION_STATUS`: `ENABLED (Hardened)` vs `DISABLED (page_table_check=off)`
    - 매핑 검증 규칙 매트릭스(Anonymous RW 금지, Anon/File 혼동 금지 등) 노출.
  - **프로브 핸들러**:
    - 유저 프로세스가 할당한 가상 메모리 주소를 전달받아 커널 정적 키 및 페이지 테이블 검증 훅의 활성화 여부를 안전하게 실증 로깅.

### 3.2 메모리 매핑 검증 익스플로잇 PoC (`exploit.c`)

- 비특권 사용자(`lab`, UID 1000) 공간에서 실행되는 `/bin/exploit_page_table_check`:
  - `mmap()` 시스템 콜을 통해 익명 비공개(Anonymous Private) 메모리 영역을 할당하고 매직 데이터(`0x5041474554424C45ULL`, "PAGETBLE")를 기록.
  - `/proc/vuln_page_table_check`에 할당된 페이지 주소를 전달하여 커널 드라이버와 상호작용.
  - 리턴된 텔레메트리를 검증하여 런타임 페이지 테이블 체크 활성화 여부 판정.

### 3.3 인게스트 자동 검증 러너 (`test.sh`)

- `/bin/test_page_table_check` 자동화 검증 스크립트:
  - Test 1: 커널 커맨드라인 파라미터(`page_table_check=on` vs `page_table_check=off`) 검증.
  - Test 2: `/proc/vuln_page_table_check` 텔레메트리 출력.
  - Test 3: 비특권 계정 `lab` 권한으로 `/bin/exploit_page_table_check` 실행.
  - Test 4: `dmesg` 보안 이벤트 로깅 분석.

---

## 4. 검증 결과 및 분석 (Verification Results)

### 4.1 x86_64 실측 로그 (Base vs Hardened)

#### [Base] x86_64 페이지 테이블 체크 비활성화 (`page_table_check=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
Page Table Check Status: DISABLED (page_table_check=off active)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             x86_64
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_ENABLED (Checks Bypassed)
PROTECTION_STATUS:        DISABLED (page_table_check=off active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: x86_64
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            x86_64
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_ENABLED (Checks Bypassed)
    Enforcement State:       DISABLED (page_table_check=off active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0x7ff0b480f000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x00007ff0b480f000
    Probe Result:            UNPROTECTED (Page Table Check Inactive / Bypassed)

[!] =========================================================
[!] BASELINE CONFIRMED (CONFIG_PAGE_TABLE_CHECK Disabled):
[!] Page table verification hooks are bypassed (page_table_check=off).
[!] Kernel does not synchronously detect double-mappings or page leaks.
[!] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
[    0.118447] Kernel command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
[    0.120208] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    1.594553] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 0)
[    2.432137]     lab_test=test_page_table_check
[    3.276630] [vuln_page_table_check] Received probe request for user address 0x7ff0b480f000
[    3.276770] [vuln_page_table_check] [!] WARNING: Page Table Check is disabled (page_table_check=off)!
[    3.276839] [vuln_page_table_check] [!] Page table verification hooks bypassed. Memory corruption detection inactive.
```

#### [Hardened] x86_64 페이지 테이블 체크 활성화 (`page_table_check=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
Page Table Check Status: ACTIVE (page_table_check=on enforced)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             x86_64
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_DISABLED (Checks Armed)
PROTECTION_STATUS:        ENABLED (Hardened - Synchronous verification active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: x86_64
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            x86_64
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_DISABLED (Checks Armed)
    Enforcement State:       ENABLED (Hardened - Synchronous verification active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0x7efc25f8a000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x00007efc25f8a000
    Probe Result:            PROTECTED (Page Table Integrity Enforced by Core MM)

[+] =========================================================
[+] HARDENING VERIFIED (CONFIG_PAGE_TABLE_CHECK Active):
[+] Kernel is actively monitoring PTE/PMD/PUD page tables!
[+] Illegal double-mappings (Anon RW > 1) & file aliasing are prohibited.
[+] UAF lingering mappings during page free will trigger immediate crash.
[+] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
[    0.127950] Kernel command line: console=ttyS0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
[    0.129710] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    0.162573] allocated 2097152 bytes of page_ext
[    1.605843] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 1)
[    2.377685]     lab_test=test_page_table_check
[    3.221274] [vuln_page_table_check] Received probe request for user address 0x7efc25f8a000
[    3.223529] [vuln_page_table_check] [+] DEFENSE ACTIVE: CONFIG_PAGE_TABLE_CHECK is actively enforcing page table integrity!
[    3.223630] [vuln_page_table_check] [+] Synchronous double-map prevention & anonymous/file separation verified.
```

---

### 4.2 ARM64 실측 로그 (Base vs Hardened)

#### [Base] ARM64 페이지 테이블 체크 비활성화 (`page_table_check=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
Page Table Check Status: DISABLED (page_table_check=off active)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             arm64 (aarch64)
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_ENABLED (Checks Bypassed)
PROTECTION_STATUS:        DISABLED (page_table_check=off active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: arm64 (aarch64)
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            arm64 (aarch64)
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_ENABLED (Checks Bypassed)
    Enforcement State:       DISABLED (page_table_check=off active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0xffffb6c4e000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x0000ffffb6c4e000
    Probe Result:            UNPROTECTED (Page Table Check Inactive / Bypassed)

[!] =========================================================
[!] BASELINE CONFIRMED (CONFIG_PAGE_TABLE_CHECK Disabled):
[!] Page table verification hooks are bypassed (page_table_check=off).
[!] Kernel does not synchronously detect double-mappings or page leaks.
[!] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Kernel command line: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=off
[    0.000000] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    0.721444] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 0)
[    0.861172]     lab_test=test_page_table_check
[    1.419653] [vuln_page_table_check] Received probe request for user address 0xffffb6c4e000
[    1.419858] [vuln_page_table_check] [!] WARNING: Page Table Check is disabled (page_table_check=off)!
[    1.419890] [vuln_page_table_check] [!] Page table verification hooks bypassed. Memory corruption detection inactive.
```

#### [Hardened] ARM64 페이지 테이블 체크 활성화 (`page_table_check=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Feature Configuration
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
Page Table Check Status: ACTIVE (page_table_check=on enforced)

=========================================================
  [Test 2/3] Kernel Page Table Check Telemetry (/proc/vuln_page_table_check)
=========================================================
ARCHITECTURE:             arm64 (aarch64)
FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK
CONFIG_PAGE_TABLE_CHECK:  ENABLED (y)
CONFIG_PTC_ENFORCED:      ENABLED (y)
CONFIG_EXCLUSIVE_SYS_RAM: ENABLED (y)
CONFIG_PAGE_EXTENSION:    ENABLED (y)
STATIC_KEY_STATE:         KEY_DISABLED (Checks Armed)
PROTECTION_STATUS:        ENABLED (Hardened - Synchronous verification active)
RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)
RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)
RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)
RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)
LAST_PROBE_ADDR:          0x0000000000000000
LAST_PROBE_RESULT:        NOT_TESTED

=========================================================
  [Test 3/3] Page Table Mapping Integrity Demonstration
  Target: /proc/vuln_page_table_check
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Page Table Integrity PoC
  Target: CONFIG_PAGE_TABLE_CHECK
  Architecture: arm64 (aarch64)
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Page Table Check Configuration Telemetry:
    Architecture:            arm64 (aarch64)
    Mechanism:               CONFIG_PAGE_TABLE_CHECK
    PAGE_TABLE_CHECK:        ENABLED (y)
    PTC_ENFORCED:            ENABLED (y)
    EXCLUSIVE_SYSTEM_RAM:    ENABLED (y)
    PAGE_EXTENSION:          ENABLED (y)
    Static Branch Key:       KEY_DISABLED (Checks Armed)
    Enforcement State:       ENABLED (Hardened - Synchronous verification active)

[*] User-Space Memory Mapping Setup:
    Mapping Type:            Anonymous Private (RW)
    Allocated Address:       0xffffb16d2000 (Size: 4096 bytes)
    Magic Signature:         0x5041474554424c45 ("PAGETBLE")

=========================================================
[*] Probing Page Table Integrity via Kernel Driver...
=========================================================

[*] Post-Probe Verification Telemetry:
    Probed Target Address:   0x0000ffffb16d2000
    Probe Result:            PROTECTED (Page Table Integrity Enforced by Core MM)

[+] =========================================================
[+] HARDENING VERIFIED (CONFIG_PAGE_TABLE_CHECK Active):
[+] Kernel is actively monitoring PTE/PMD/PUD page tables!
[+] Illegal double-mappings (Anon RW > 1) & file aliasing are prohibited.
[+] UAF lingering mappings during page free will trigger immediate crash.
[+] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.000000] Kernel command line: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_page_table_check page_table_check=on
[    0.000000] Unknown kernel command line parameters "nokaslr lab_test=test_page_table_check", will be passed to user space.
[    0.000000] allocated 2097152 bytes of page_ext
[    1.264390] [vuln_page_table_check] Initialized /proc/vuln_page_table_check (active: 1)
[    1.475725]     lab_test=test_page_table_check
[    2.327193] [vuln_page_table_check] Received probe request for user address 0xffffb16d2000
[    2.327322] [vuln_page_table_check] [+] DEFENSE ACTIVE: CONFIG_PAGE_TABLE_CHECK is actively enforcing page table integrity!
[    2.327349] [vuln_page_table_check] [+] Synchronous double-map prevention & anonymous/file separation verified.
```

---

### 4.3 보안 매핑 규칙 및 엔지니어링 매트릭스

| 검증 항목 (Dimension) | 베이스라인 (`page_table_check=off`) | 하드닝 (`page_table_check=on`) | 보안 및 아키텍처 영향 |
| :--- | :--- | :--- | :--- |
| **정적 키 (`page_table_check_disabled`)** | 활성 (`true`, 검증 우회) | 비활성 (`false`, 검증 무장) | 런타임 분기 오버헤드 없이 제로-코스트 전환 |
| **익명 이중 쓰기 매핑 (Anon RW > 1)** | **묵인됨 (지연된 메모리 오염 발생)** | **즉시 차단 (`BUG_ON()` 패닉)** | UAF 및 익명 메모리 하이재킹 원천 차단 |
| **익명/파일 타입 혼동 매핑** | **묵인됨 (캐시 오염 및 권한 우회)** | **즉시 차단 (`BUG_ON()` 패닉)** | 페이지 구조체 무결성 및 격리 강제 |
| **페이지 해제 시 잔여 매핑 검증** | 미수행 | `page_table_check_free()` 검증 | 할당 해제된 페이지를 가리키는 댕글링 PTE 적발 |
| **페이지 확장 메모리 추적** | 미사용 | `page_ext` 원자적 카운터 추적 | 물리 메모리 단위의 완전한 소유권 추적 보장 |

---

## 5. 영어 발표 대본 (Global Technical Presentation Script)

```text
"Hello everyone, and welcome to this deep-dive into Linux kernel memory integrity. Today, we focus on CONFIG_PAGE_TABLE_CHECK—a vital synchronous hardening feature introduced in modern kernels to prevent illegal page table corruption.

Traditionally, the memory management subsystem defers validation of page mappings to preserve throughput. Unfortunately, kernel race conditions, faulty driver remappings, or Use-After-Free bugs can lead to silent corruption, where the exact same physical memory frame is mapped as writable into two separate address spaces. By the time this double mapping causes an application crash or privilege escalation, the root cause is long gone.

CONFIG_PAGE_TABLE_CHECK completely transforms this paradigm by verifying page table entries synchronously at the exact moment they are added or removed from user page tables. By maintaining atomic tracking counters inside struct page_ext, the kernel guarantees strict invariant rules: anonymous pages can never be mapped writable more than once, and anonymous pages can never alias with named file pages.

If an illegal mapping is attempted, the kernel crashes immediately with BUG_ON(), pinning the corruption to the exact violating code path before any user data is poisoned.

In our lab, we demonstrated how the static key seamlessly arms or bypasses these checks across x86_64 and ARM64, providing robust runtime defense against complex heap and page table exploitation. Thank you."
```

---

## 6. 핵심 용어 사전 (Terminology & Architectural Reference)

- **`CONFIG_PAGE_TABLE_CHECK`**:
  - 리눅스 5.17+ 커널에 도입된 페이지 테이블 무결성 검증 메커니즘. PTE, PMD, PUD가 설정되거나 해제될 때 불법적인 이중 매핑 및 잘못된 페이지 공유를 동기식으로 검사함.
- **`PAGE_EXTENSION` (`page_ext`)**:
  - 각 물리 페이지 프레임(`struct page`)마다 추가적인 디버깅/보안 메타데이터를 저장하기 위해 커널이 제공하는 확장 메모리 인프라.
- **Anonymous Page (익명 페이지)**:
  - 파일 시스템 상의 파일에 백업되지 않고, 프로세스의 힙, 스택, BSS 등 실행 시간 메모리 용도로 동적 할당된 순수 RAM 메모리 페이지.
- **Named / File-backed Page (파일 매핑 페이지)**:
  - 디스크 파일이나 특수 파일 시스템에 매핑되어 페이지 캐시를 통해 관리되는 메모리 페이지.
- **Double Mapping (이중 매핑)**:
  - 단일 물리 메모리 페이지가 두 개 이상의 가상 주소(또는 서로 다른 두 프로세스)에 중복 매핑되는 현상. 특히 둘 이상의 엔트리가 쓰기(Writable) 권한을 가질 경우 심각한 동시성 오염이 유발됨.
- **`CONFIG_EXCLUSIVE_SYSTEM_RAM`**:
  - `/dev/mem` 등을 통해 시스템 RAM 영역이 임의로 유저 공간에 매핑되는 것을 방지하여 페이지 테이블 체크의 메타데이터 신뢰성을 보장하는 전제 Kconfig 옵션.
- **`static_branch_likely()` / `static_key_true`**:
  - 리눅스 커널의 Jump Label 인프라. 런타임에 명령어 패칭(NOP vs JMP)을 통해 조건 분기 오버헤드 없이 특정 보안 기능을 동적으로 활성화/비활성화함.

