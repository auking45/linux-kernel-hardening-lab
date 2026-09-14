# CONFIG_RANDOMIZE_MEMORY: 물리 메모리 다이렉트 매핑 주소 랜덤화 및 ret2dir 방어

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/randomize-memory/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="CONFIG_RANDOMIZE_MEMORY Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: 결정론적 물리 메모리 다이렉트 매핑과 ret2dir 공격

- **코드 KASLR의 한계와 데이터/힙 메모리의 취약성**:
  - 기본 KASLR(`CONFIG_RANDOMIZE_BASE=y`)은 커널 코드(`.text`) 및 정적 심볼 영역만을 가상 주소 공간에서 무작위화함.
  - 커널 힙 할당자(kmalloc, SLAB/SLUB)와 페이지 프레임 할당자(Buddy Allocator)가 관리하는 전체 물리 메모리는 **물리 메모리 다이렉트 매핑(Direct Physical Mapping / `PAGE_OFFSET`)** 영역을 통해 1:1로 가상 주소 공간에 선형 매핑됨.
  - 다이렉트 매핑 베이스 주소가 고정되어 있을 경우(x86_64: `0xffff888000000000`), 임의의 물리 주소 $P$에 대응하는 커널 가상 주소는 항상 `0xffff888000000000 + P`로 확정 예측 가능함.
- **ret2dir (Return-to-Direct-Mapped-Memory) 공격 메커니즘**:
  - 공격자는 비특권 사용자 공간에서 대량의 메모리를 할당(`mmap`)하고 악성 페이로드(쉘코드, 가짜 `struct cred`, ROP 체인)를 물리 RAM에 대량 살포(Physmap Spraying)함.
  - 이후 커널 취약점(함수 포인터 변조, UAF)을 트리거하여, 고정된 다이렉트 매핑 공식을 통해 유저 공간 페이로드가 상주하는 물리 페이지의 커널 가상 주소로 직접 분기함.
  - 이 공격은 커널 코드 영역(`.text`)의 KASLR을 전혀 우회할 필요 없이 100% 신뢰성 있는 익스플로잇을 성공시킴.
- **CONFIG_RANDOMIZE_MEMORY의 방어 철학**:
  - 부팅 시 하드웨어 난수를 기반으로 물리 메모리 다이렉트 매핑(`page_offset_base`), 동적 가상 메모리 할당 영역(`vmalloc_base`), 페이지 디스크립터 배열(`vmemmap_base`)의 가상 주소 베이스와 영역 간 패딩을 무작위화함.
  - 30,000개 이상의 무작위 슬롯 엔트로피를 부여하여, 공격자가 물리 페이지의 커널 가상 주소를 예측하지 못하도록 차단함.

### 1.2 직관적 실전 비유: 비밀 터널 출입구 이동 (The Shuffled Tunnel Entrances Metaphor)

- **비유 설명**:
  - 전체 물리 메모리(RAM)를 보물이 보관된 지하 금고실로 비유할 수 있음.
  - **하드닝 이전 (`CONFIG_RANDOMIZE_MEMORY=n`)**: 지상(가상 메모리)에서 지하 금고실(물리 RAM)로 통하는 비밀 터널의 출입구(`PAGE_OFFSET`)가 항상 '중앙역 1번 출구(`0xffff888000000000`)'로 고정되어 있음. 도둑(공격자)은 지하 금고실 30번 보관함에 폭탄(스프레이 페이로드)을 넣어둔 뒤, 중앙역 1번 출구에서 정확히 30미터 직진하는 통로를 타고 침투하여 금고를 폭파함.
  - **하드닝 적용 (`CONFIG_RANDOMIZE_MEMORY=y`)**: 비밀 터널 출입구의 위치가 매일 밤(부팅할 때마다) 도시 전역의 수만 개 후보지 중 하나(`page_offset_base`)로 무작위 변경됨. 도둑이 과거의 중앙역 1번 출구 좌표로 진입하면 옹벽(Unmapped Virtual Hole)에 부딪혀 즉각 체포(Page Fault)됨.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 3대 핵심 메모리 영역 분산 알고리즘 (`arch/x86/mm/kaslr.c`)

- **무작위화 대상 3대 영역 (`kaslr_regions`)**:
  1. `page_offset_base`: 물리 메모리 전체의 1:1 다이렉트 매핑 시작 가상 주소.
  2. `vmalloc_base`: `vmalloc()`, 모듈 로딩, 커널 스택 등에 사용되는 비연속 가상 메모리 영역.
  3. `vmemmap_base`: 시스템의 모든 물리 페이지 프레임에 대응하는 `struct page` 메타데이터 배열.
- **엔트로피 생성 및 슬롯 배치**:
  - 부팅 시 `kernel_randomize_memory()` 함수가 호출되어 사용 가능한 가상 주소 공간(PGD/PUD 단위)의 잔여 엔트로피(`remain_entropy`)를 계산함:
    ```c
    /* arch/x86/mm/kaslr.c */
    prandom_seed_state(&rand_state, kaslr_get_random_long("Memory"));
    for (i = 0; i < ARRAY_SIZE(kaslr_regions); i++) {
        unsigned long entropy;
        ...
        rand = prandom_u32_state(&rand_state);
        entropy = (rand % (remain_entropy + 1)) & PUD_PAGE_MASK;
        vaddr += entropy;
        *kaslr_regions[i].base = vaddr;
        vaddr += get_padding(&kaslr_regions[i]);
    }
    ```
  - 영역 간의 상대 순서(Direct Map $\rightarrow$ Vmalloc $\rightarrow$ Vmemmap)는 유지되되, 각 영역의 시작 주소와 영역 간 간격(Padding)이 난수화됨.

### 2.2 ARM64 아키텍처 구현 메커니즘 (`arch/arm64/mm/init.c`)

- ARM64에서는 `CONFIG_RANDOMIZE_BASE=y` 활성화 시 리니어 매핑 베이스인 `memstart_addr`가 부팅 시 전달된 `memstart_offset_seed`를 기반으로 자동으로 무작위화됨:
  ```c
  /* arch/arm64/mm/init.c */
  if (memstart_offset_seed > 0 && range >= (s64)ARM64_MEMSTART_ALIGN) {
      range /= ARM64_MEMSTART_ALIGN;
      memstart_addr -= ARM64_MEMSTART_ALIGN * ((range * memstart_offset_seed) >> 16);
  }
  ```
- x86_64와 마찬가지로 물리 주소와 가상 주소 간의 고정 오프셋 관계가 파괴되어 선형 매핑 스프레이 공격이 차단됨.

---

## 3. 실습 환경 및 취약 드라이버 구현 (Hands-on Lab Implementation)

### 3.1 취약 타깃 드라이버 (`vuln_randmem.c`)

- `/proc/vuln_randmem` (mode 0666) 인터페이스 제공:
  - **메모리 영역 베이스 텔레메트리**:
    - `PAGE_OFFSET_BASE`: 실제 런타임 다이렉트 매핑 베이스 주소.
    - `STATIC_PAGE_OFFSET`: 고정 기준 베이스 주소 (x86_64: `0xffff888000000000`).
    - `VMALLOC_BASE`: 현재 vmalloc 영역 베이스.
    - `RANDMEM_SLIDE`: 고정 베이스 대비 실제 다이렉트 매핑의 런타임 오프셋 차이.
    - `TARGET_PAGE_PHYS`: 테스트용 물리 페이지의 실제 RAM 주소.
    - `TARGET_DIRECT_VIRT`: 해당 물리 페이지의 실제 커널 가상 주소 (`__va(phys)`).
    - `STATIC_GUESS_VIRT`: 공격자가 고정 공식을 통해 계산한 추정 가상 주소.
  - **공격 디스패치 검증**:
    - 유저 공간에서 전송한 주소가 실제 `TARGET_DIRECT_VIRT`와 일치하는지 대조.

### 3.2 ret2dir 공격 익스플로잇 PoC (`exploit.c`)

- 일반 사용자 권한(`lab`, UID 1000)으로 실행되는 ret2dir 시뮬레이션 바이너리 (`/bin/exploit_randomize_memory`):
  - **1단계 (블라인드 ret2dir 공격)**:
    - 공격자는 커널 인포리크 없이 고정 공식($Target = STATIC\_BASE + TARGET\_PHYS$)을 사용하여 계산된 주소로 커널 접근 요청.
    - **Base (`randomize-memory-disabled`)**: 고정 베이스가 적중하여 100% 공격 성공 (`[!] VULNERABILITY CONFIRMED: Direct memory mapping is deterministic!`).
    - **Hardened (`randomize-memory`)**: 난수 슬라이드로 인해 주소 불일치 오류 반환 (`[+] DEFENSE ACTIVE: CONFIG_RANDOMIZE_MEMORY verified!`).
  - **2단계 (인포리크 연계 시나리오)**:
    - 실제 다이렉트 매핑 베이스 유출 시의 위험성을 검증하고, 스택/힙 소거(`STACKLEAK`)와의 다층 방어 연계 필요성 입증.

---

## 4. QEMU 실측 검증 및 분석 (Dual-Architecture Verification)

### 4.1 x86_64 아키텍처 실측 결과

#### Base Kernel (`randomize-memory-disabled`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_randomize_memory
Memory Randomization: ACTIVE (KASLR enabled)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xff11000000000000
STATIC_PAGE_OFFSET:    0xff11000000000000
VMALLOC_BASE:          0xffa0000000000000
RANDMEM_SLIDE:         0x0000000000000000
RANDMEM_STATUS:        DISABLED (Deterministic)
TARGET_PAGE_PHYS:      0x0000000001325000
TARGET_DIRECT_VIRT:    0xff11000001325000
STATIC_GUESS_VIRT:     0xff11000001325000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Regions Telemetry:
    Direct Map Base:     0xff11000000000000
    Static Default Base: 0xff11000000000000
    Vmalloc Base:        0xffa0000000000000
    Randmem Slide:       0x0000000000000000
    Randomization Status: DISABLED (Deterministic)

[*] Target Physical Page Mapping:
    Physical Address:    0x0000000001325000
    Actual Direct Virt:  0xff11000001325000
    Static Guess Virt:   0xff11000001325000

=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xff11000001325000
=========================================================
[!] Target memory accessed successfully!
[!] VULNERABILITY CONFIRMED: Direct memory mapping is deterministic!
[!] Attacker predicted kernel virtual address (0xff11000001325000) without infoleak.
[!] ret2dir exploit enables attackers to execute/dereference sprayed physical pages.
```

#### Hardened Kernel (`randomize-memory`, `CONFIG_RANDOMIZE_MEMORY=y`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 kaslr lab_test=test_randomize_memory
Memory Randomization: ACTIVE (KASLR enabled)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xff19396580000000
STATIC_PAGE_OFFSET:    0xff11000000000000
VMALLOC_BASE:          0xff5a7019c0000000
RANDMEM_SLIDE:         0x0008396580000000
RANDMEM_STATUS:        ENABLED (Randomized)
TARGET_PAGE_PHYS:      0x00000000013b2000
TARGET_DIRECT_VIRT:    0xff193965813b2000
STATIC_GUESS_VIRT:     0xff110000013b2000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Regions Telemetry:
    Direct Map Base:     0xff19396580000000
    Static Default Base: 0xff11000000000000
    Vmalloc Base:        0xff5a7019c0000000
    Randmem Slide:       0x0008396580000000
    Randomization Status: ENABLED (Randomized)

[*] Target Physical Page Mapping:
    Physical Address:    0x00000000013b2000
    Actual Direct Virt:  0xff193965813b2000
    Static Guess Virt:   0xff110000013b2000

=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xff110000013b2000
=========================================================
[-] Write returned error: Invalid argument (errno = 22)
[+] Access blocked or target address was invalid!
[+] DEFENSE ACTIVE: CONFIG_RANDOMIZE_MEMORY verified!
[+] Static guess missed actual direct map by 0x8396580000000 bytes.
[+] ret2dir / direct-map spraying exploitation is completely foiled!
```

---

### 4.2 ARM64 아키텍처 실측 결과

#### Base Kernel (`randomize-memory-disabled`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_randomize_memory
Memory Randomization: DISABLED (nokaslr active)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xffff000000000000
STATIC_PAGE_OFFSET:    0xffff000000000000
VMALLOC_BASE:          0xffff800080000000
RANDMEM_SLIDE:         0x0000000000000000
RANDMEM_STATUS:        DISABLED (Deterministic)
TARGET_PAGE_PHYS:      0x00000000414cb000
TARGET_DIRECT_VIRT:    0xffff0000014cb000
STATIC_GUESS_VIRT:     0xffff0000014cb000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xffff0000014cb000
=========================================================
[!] Target memory accessed successfully!
[!] VULNERABILITY CONFIRMED: Direct memory mapping is deterministic!
[!] Attacker predicted kernel virtual address (0xffff0000014cb000) without infoleak.
[!] ret2dir exploit enables attackers to execute/dereference sprayed physical pages.
```

#### Hardened Kernel (`randomize-memory`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Memory Randomization
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 kaslr lab_test=test_randomize_memory
Memory Randomization: ACTIVE (KASLR enabled)

=========================================================
  [Test 2/3] Memory Section Telemetry (/proc/vuln_randmem)
=========================================================
PAGE_OFFSET_BASE:      0xffff000000000000
STATIC_PAGE_OFFSET:    0xffff000000000000
VMALLOC_BASE:          0xffff800080000000
RANDMEM_SLIDE:         0x00004ca5c0000000
RANDMEM_STATUS:        ENABLED (Randomized)
TARGET_PAGE_PHYS:      0x00000000415e0000
TARGET_DIRECT_VIRT:    0xffff4ca5c15e0000
STATIC_GUESS_VIRT:     0xffff0000015e0000

=========================================================
  [Test 3/3] Real-World ret2dir Exploit Demonstration
  Target: /proc/vuln_randmem
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Stage 1: ret2dir Attack using Static Direct Map Base
    Formula: Target_Virt = STATIC_PAGE_OFFSET + Phys_Addr
    Attempting access to: 0xffff0000015e0000
=========================================================
[-] Write returned error: Invalid argument (errno = 22)
[+] Access blocked or target address was invalid!
[+] DEFENSE ACTIVE: CONFIG_RANDOMIZE_MEMORY verified!
[+] Static guess missed actual direct map by 0x4ca5c0000000 bytes.
[+] ret2dir / direct-map spraying exploitation is completely foiled!
```

---

### 4.3 하드닝 전후 보안 비교 분석표

| 항목 | Base (`CONFIG_RANDOMIZE_MEMORY=n`) | Hardened (`CONFIG_RANDOMIZE_MEMORY=y`) |
| :--- | :--- | :--- |
| **다이렉트 매핑 베이스** | `0xffff888000000000` (고정 불변) | 부팅 시 약 30,000개 슬롯 중 난수 배치 |
| **vmalloc / vmemmap 배치** | 고정 가상 주소 영역 할당 | 가상 주소 베이스 및 영역 간 패딩 무작위화 |
| **ret2dir 공격 저항성** | **취약** (물리 주소 알면 가상 주소 확정) | **원천 방어** (가상 주소 예측 불가) |
| **힙/물리 페이지 살포 방어** | 유저 스프레이 데이터를 커널 모드에서 쉽게 지정 | 스프레이 위치 추정 불가능 |
| **런타임 성능 오버헤드** | 0% | **0%** (부팅 시 1회 페이지 테이블 베이스 설정) |
| **코드 KASLR과의 관계** | 코드만 보호되고 힙/메모리는 무방비 | 코드 + 물리 메모리 + 힙 다층 무작위화 완성 |

---

## 5. 성능 영향 및 보안 아키텍처 제언 (Trade-offs & Recommendations)

### 5.1 성능 및 엔지니어링 비용
- **런타임 오버헤드 전무**:
  - 부팅 시 초기 페이지 테이블을 빌드할 때 가상 주소 베이스(`page_offset_base`)를 1회 난수화하여 설정하므로, 시스템 실행 중 발생하는 CPU 사이클 오버헤드는 0%임.
- **KASAN과의 상충 관계**:
  - KASAN(Kernel Address Sanitizer) 섀도 메모리 매핑은 PGD 정렬에 엄격히 의존하므로, KASAN 빌드 환경에서는 `kaslr_memory_enabled()`에 의해 자동으로 비활성화됨.

### 5.2 권장 적용 시나리오
- **모든 프로덕션 리눅스 서버 및 컨테이너 호스트**:
  - 런타임 성능 저하가 전혀 없으므로, 기본 KASLR(`CONFIG_RANDOMIZE_BASE=y`)과 함께 **반드시 상시 활성화(`CONFIG_RANDOMIZE_MEMORY=y`)**하는 것이 권장됨.

---

## 6. 부록 (Appendix)

### 6.1 영문 기술 발표 대본 (Technical Presentation Script)

> "Hello everyone. Today we examine CONFIG_RANDOMIZE_MEMORY, which expands KASLR beyond executable code to protect the entire physical memory direct map.
>
> Many developers assume KASLR completely hides kernel memory. However, traditional KASLR only relocates the .text code section. The kernel's direct physical mapping—which maps all physical RAM linearly into kernel space—remains at a deterministic fixed address such as 0xffff888000000000 on x86_64.
>
> This creates a severe vector known as ret2dir, or return-to-direct-mapped-memory. An attacker can spray malicious data or fake credentials across user space physical pages, and then reliably calculate their exact kernel virtual addresses without needing any kernel infoleak.
>
> By enabling CONFIG_RANDOMIZE_MEMORY, the kernel randomizes the base virtual address of the direct physical map, vmalloc, and vmemmap regions with over 30,000 entropy slots. As demonstrated in our lab, blind ret2dir attacks result in immediate page faults or rejected dispatches, shutting down physmap exploitation with zero runtime performance cost."

### 6.2 보안 용어 사전 (Glossary)

- **CONFIG_RANDOMIZE_MEMORY**: 커널의 물리 메모리 다이렉트 매핑, vmalloc, vmemmap 영역의 가상 주소 시작점을 부팅 시 무작위화하는 x86_64/ARM64 보안 설정.
- **ret2dir (Return-to-Direct-Mapped-Memory)**: 유저 공간에서 대량의 물리 페이지를 살포한 뒤, 결정론적인 커널 다이렉트 매핑 주소를 통해 해당 페이로드로 분기하는 커널 권한 상승 기법.
- **Physmap (Direct Physical Mapping)**: 전체 물리 RAM을 커널 가상 주소 공간에 1:1로 선형 매핑해 놓은 연속 메모리 구역 (`PAGE_OFFSET`).
- **page_offset_base**: x86_64 아키텍처에서 다이렉트 매핑 영역의 시작 가상 주소를 가리키는 커널 내부 전역 변수.
- **vmalloc_base**: `vmalloc()` 동적 가상 메모리 할당 영역의 시작 가상 주소.
- **vmemmap_base**: 시스템의 모든 물리 페이지 프레임에 대응하는 `struct page` 메타데이터 배열의 가상 주소.
