# ARM64 MTE (Memory Tagging Extension) 메모리 안전성 강화

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**ARM64 MTE (`CONFIG_ARM64_MTE`, ARMv8.5-A+)**는 실리콘 하드웨어 레벨에서 메모리 포인터와 실제 물리 메모리 그래뉼(Granule)에 **4비트 암호학적/논리적 컬러 태그(0x0 ~ 0xF)를 부여하고, 메모리 접근(Load/Store) 시 하드웨어 비교를 수행하여 공간적/시간적 메모리 오염 공격을 원천 탐지 및 차단하는 차세대 하드웨어 보안 기술**임.

마이크로소프트, 구글, 크로미움 보안 리서치 통계에 따르면 현대 운영체제 및 브라우저에서 발생하는 치명적인 제로데이 보안 취약점의 약 70%가 C/C++ 언어의 메모리 안전성 결함(Memory Safety Issues)에서 기인함:

1. **시간적 메모리 결함 (Temporal Safety - Use-After-Free, UAF)**:
   - 메모리 객체가 해제(`free`)된 이후에도 해제된 포인터를 유지하는 댕글링 포인터(Dangling Pointer)를 통해 이미 반환되거나 다른 용도로 재할당된 메모리를 조작하는 공격.
   - 공격자가 힙 스프레이(Heap Spraying)를 통해 가짜 객체를 주입하고 가상 함수 테이블(vtable)이나 함수 포인터를 변조하여 원격 코드 실행(RCE)을 달성함.
2. **공간적 메모리 결함 (Spatial Safety - Buffer Overflow / Out-Of-Bounds, OOB)**:
   - 할당된 배열이나 버퍼의 경계를 벗어나 인접한 객체, 힙 메타데이터, 제어 구조체를 덮어쓰는 공격.
3. **MTE의 하드웨어 차단 혁신**:
   - 소프트웨어 새니타이저(AddressSanitizer/KASAN)는 2배 이상의 CPU 오버헤드와 막대한 메모리 소비로 인해 실서비스 환경(Production) 적용이 불가능했음.
   - ARM64 MTE는 16바이트 메모리 그래뉼당 4비트의 태그 저장소를 하드웨어에 내장하고, 포인터 상위 비트(TBI, Top-Byte-Ignore)를 활용하여 **단일 사이클 내 하드웨어 검증을 수행함으로써 1~2% 미만의 성능 부하로 프로덕션 레벨 완벽한 방어 제공**.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. ARM64 MTE 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/arm64-mte/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 최고급 스마트 호텔의 '색상 매칭 전자 도어록'

ARM64 MTE의 동작 원리는 **호텔의 객실 키카드 색상 일치 시스템**과 정확히 일치함:

```
[ 비활성화 상태 (레거시 무방비 시스템) ]
  공격자:   "투숙 기간이 끝난 방 번호(Dangling Pointer)가 적힌 구형 열쇠를 그대로 들고 온다!"
  도어록:   "방 번호만 맞으면 누구든 입장 허용!" (Use-After-Free 무단 침입 발생)

[ MTE 활성화 상태 (정상 접근: Logical Tag == Allocation Tag) ]
  손님:     "체크인 시 발급받은 '보라색(0xA)' 키카드를 객실 문에 태그!"
  도어록:   "현재 객실 문(16바이트 그래뉼)의 색상 센서가 '보라색(0xA)'인지 비교!"
  결과:     "0xA == 0xA 완벽 일치! 문 열림 (Load/Store 성공, 성능 지연 없음)."

[ MTE UAF 방어: 재할당 시 색상 강제 재도색 (Re-coloring) ]
  공격자:   "체크아웃 후 방을 비웠으나, 복사해둔 보라색(0xA) 키카드로 방을 다시 열려고 시도!"
  호텔:     "손님이 체크아웃(`free`)하는 즉시 도어록 색상을 무작위 '주황색(0x3)'으로 자동 변경!"
  도어록:   "비교 수행: 키카드(0xA) != 객실 색상(0x3)! 태그 불일치 감지!"
  조치:     "즉각 침입 경보 발령! (하드웨어 트랩, SIGSEGV / SEGV_MTESERR 발생, 프로세스 즉시 종료)!"

[ MTE OOB 방어: 인접 객체 간 색상 분리 (Color Divergence) ]
  공격자:   "내 방(0xA) 창문을 깨고 옆방(0x7) 침대로 넘어가려고 시도!"
  경계선:   "16바이트 그래뉼 경계를 넘어서는 순간 태그가 0x7로 변경됨! 0xA != 0x7 불일치로 즉시 감전 차단!"
```

---

### 3. MTE 결함 트랩 모드 매트릭스

| 트랩 모드 | 제어 상수 (`prctl`) | 하드웨어 동작 특성 | 성능 오버헤드 | 주 용도 및 적용 분야 |
| :--- | :--- | :--- | :--- | :--- |
| **동기식 (Synchronous)** | `PR_MTE_TCF_SYNC` | 태그 불일치 발생 시 즉시 CPU 명령 파이프라인 정지, 정확한 PC 주소와 함께 `SIGSEGV`(`SEGV_MTESERR`) 전달 | ~2% | 개발 환경, 보안 진단, 보안 취약점 익스플로잇 즉각 무력화 |
| **비동기식 (Asynchronous)** | `PR_MTE_TCF_ASYNC` | 명령을 중단하지 않고 하드웨어 레지스터(`TFSR_EL1`)에 누적 기록 후 컨텍스트 스위칭 시 지연 `SEGV_MTEAERR` 전달 | < 0.5% | 모바일 프로덕션 배포(Android), 배터리 민감 환경, 대규모 텔레메트리 수집 |
| **비대칭형 (Asymmetric)** | `PR_MTE_TCF_ASYMM` | 메모리 읽기(Read)는 동기식 즉시 트랩, 쓰기(Write)는 비동기식 누적 처리 | ~1% | 최신 안드로이드(Android 13+) 권장 하이브리드 프로덕션 모드 |

---

## 3. 커널 설정 및 플래그 분석 (Kernel Configurations)

### 1. Hardening Kconfig (`configs/features/mte.config`)

```ini
# Linux Kernel Hardening Lab - ARM64 MTE Feature Config
CONFIG_ARM64_MTE=y
CONFIG_ARM64_TAGGED_ADDR_ABI=y
```

- `CONFIG_ARM64_MTE=y`: 커널 레벨 MTE 하드웨어 지원 활성화. 유저 공간 MTE 제어 및 커널 Tag 기반 KASAN(`CONFIG_KASAN_HW_TAGS`) 기반 제공.
- `CONFIG_ARM64_TAGGED_ADDR_ABI=y`: Top-Byte-Ignore(TBI) 기술을 통해 시스템 콜 인자로 전달되는 유저 포인터 상위 8비트에 태그가 포함되어도 커널이 오류 없이 주소를 해석하도록 보장함.

### 2. 유저 공간 MTE 활성화 인터페이스

```c
#include <sys/prctl.h>
#include <sys/mman.h>

/* 1. MTE 동기식 모드 및 태그 마스크 활성화 */
prctl(PR_SET_TAGGED_ADDR_CTRL,
      PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | (0xfffe << PR_MTE_TAG_SHIFT),
      0, 0, 0);

/* 2. MTE 태그 메모리 할당 (PROT_MTE 플래그 지정) */
void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_MTE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

---

## 4. 실습 및 검증 (Hands-on Lab: `labs/41-arm64-mte`)

### 1. 실습 환경 구성 요소

1. **타깃 드라이버 (`labs/41-arm64-mte/vuln_mte.c`)**:
   - 16바이트 그래뉼 기반 4비트 MTE 할당 태그 저장소 및 포인터 검증 엔진 구현.
   - `/proc/vuln_mte` (0666) 인터페이스:
     - `alloc <slot> <size> [tag]`: 지정된 4비트 태그로 메모리 슬롯 할당.
     - `access <slot> <offset> <tag>`: 태그가 부여된 논리 포인터로 읽기/쓰기 접근.
     - `free <slot>`: 슬롯 해제 및 물리 그래뉼 색상 자동 재도색(Re-tagging).
     - `mode <sync|async>`: 동기식/비동기식 결함 모드 전환.
2. **공격 PoC 바이너리 (`labs/41-arm64-mte/exploit.c`)**:
   - `AT_HWCAP2`의 `HWCAP2_MTE` 플래그 확인 (ARM64 네이티브 하드웨어 지원 여부 판별).
   - Stage 1: 일치하는 태그(0xA == 0xA)로 정상 접근 검증.
   - Stage 2: 변조된 포인터 태그(0xB vs 0xA) 접근 시 MTE 하드웨어 트랩 검증.
   - Stage 3: Heap Use-After-Free 공격 시도 및 MTE 재도색을 통한 공격 차단 검증.
   - Stage 4: Out-Of-Bounds 버퍼 오버플로우 시도 시 인접 그래뉼 태그 불일치 차단 검증.
   - Stage 5: Asynchronous 모드 전환 후 TFSR_EL1 누적 레지스터 동작 검증.
3. **자동화 검증 스크립트 (`labs/41-arm64-mte/test.sh`)**:
   - 아키텍처 판별, 드라이버 존재 확인, PoC 구동 및 dmesg 트랩 로그 종합 검증.

---

### 2. 단계별 실습 절차

```bash
# 1. ARM64 가상머신 기동 (MTE 에뮬레이션 포함)
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. CPU MTE 지원 여부 확인
cat /proc/cpuinfo | grep -i mte

# 3. ARM64 MTE 자동화 검증 스위트 실행
/bin/test_arm64_mte
```

### 3. 검증 출력 예시

```text
================================================================
   Lab 41: ARM64 Memory Tagging Extension (MTE) Suite           
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking CPU Architecture and MTE hardware support...
    Architecture: aarch64
[+] Native ARMv8.5+ MTE detected in /proc/cpuinfo!

[*] Step 2: Checking target driver at /proc/vuln_mte...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== ARM64 MTE (Memory Tagging Extension) Status ===
Kernel MTE Support       : CONFIG_ARM64_MTE=y
Current Fault Mode       : Synchronous (PR_MTE_TCF_SYNC)
Granule Size             : 16 bytes (4-bit tag per granule)
Total Allocations        : 0
Valid Tagged Accesses    : 0
UAF Attacks Trapped      : 0
OOB Overflows Trapped    : 0
Active Allocated Slots   :
====================================================

[*] Step 4: Running ARM64 MTE PoC...
===============================================================
   ARM64 Memory Tagging Extension (MTE) Evaluation PoC         
===============================================================

[+] Hardware ARMv8.5+ MTE detected via AT_HWCAP2!
[*] Initial Driver Status:

[*] Stage 1: Allocating Memory with MTE 4-bit Tag (0xA)...
[+] Accessing memory with MATCHING logical tag (0xA)...
[+] SUCCESS: Tag match verified (0xA == 0xA). Memory access granted.

[*] Stage 2: Accessing Memory with MISMATCHED logical tag (0xB vs 0xA)...
[+] DEFENSE SUCCESS: MTE hardware trap triggered! Tag mismatch blocked (errno=14: Bad address)

[*] Stage 3: Simulating Heap Use-After-Free (UAF) Attack...
[+] Freeing memory slot 0 (MTE re-colors physical granules with new tag)...
[+] Attacker attempts to access freed memory using dangling pointer (Tag 0xA)...
[+] DEFENSE SUCCESS: UAF blocked by MTE! Stale tag rejected (-EFAULT / SEGV_MTESERR)

[*] Stage 4: Simulating Out-of-Bounds (OOB) Heap Overflow...
[+] Allocating slot 1 (32 bytes = 2 granules, Tag 0x5)...
[+] Attacker attempts buffer overflow (accessing offset 48, beyond 32-byte boundary)...
[+] DEFENSE SUCCESS: Out-of-bounds overflow caught by MTE! Boundary enforced.

[*] Stage 5: Testing Asynchronous Fault Mode (PR_MTE_TCF_ASYNC)...
[+] Sending mismatched tag access in ASYNC mode...
[+] ASYNC Mode: Trap recorded to TFSR accumulator without halting instruction pipeline.

[*] Final ARM64 MTE Driver Diagnostics Report:
=== ARM64 MTE (Memory Tagging Extension) Status ===
Kernel MTE Support       : CONFIG_ARM64_MTE=y
Current Fault Mode       : Asynchronous (PR_MTE_TCF_ASYNC)
Granule Size             : 16 bytes (4-bit tag per granule)
Total Allocations        : 2
Valid Tagged Accesses    : 1
UAF Attacks Trapped      : 1
OOB Overflows Trapped    : 1
Active Allocated Slots   :
  [Slot 1] Size: 32 B, Granules: 2, Tag: 0x5
====================================================
[+] ARM64 MTE verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for MTE events:
[   58.201412] vuln_mte: Slot 0 allocated 64 bytes (4 granules). Assigned Allocation Tag: 0xA
[   58.202315] vuln_mte: [SYNC FAULT] Tag Mismatch! Logical: 0xB vs Allocation: 0xA at granule 1. Immediate SIGSEGV
[   58.203102] vuln_mte: Slot 0 freed. Granules re-tagged from 0xA to 0xF (UAF Trap Arming)
[   58.203890] vuln_mte: [HARDWARE TRAP - UAF] Dangling pointer access! Logical Tag 0xA != Re-tagged Allocation Tag 0xF. (SEGV_MTESERR)
[   58.204612] vuln_mte: Slot 1 allocated 32 bytes (2 granules). Assigned Allocation Tag: 0x5
[   58.205210] vuln_mte: [HARDWARE TRAP - OOB] Buffer Overflow! Offset 48 >= size 32. MTE Tag mismatch! (SEGV_MTESERR)
[   58.205901] vuln_mte: [ASYNC FAULT] Tag Mismatch recorded to TFSR_EL1 register! Asynchronous exception.

================================================================
   Lab 41 Test Complete: Verified ARM64 Memory Tagging Extension 
================================================================
```

---

## 5. 결론 및 보안 점검표 (Checklist)

| 점검 항목 | 권장 설정값 | 보안 보증 내용 |
| :--- | :--- | :--- |
| **MTE 커널 서브시스템** | `CONFIG_ARM64_MTE=y` | 하드웨어 4비트 그래뉼 태그 관리 및 트랩 핸들링 제공 |
| **태그 주소 ABI 활성화** | `CONFIG_ARM64_TAGGED_ADDR_ABI=y` | 시스템 콜 인터페이스에서 포인터 상위 태그 보존 및 TBI 해석 |
| **프로덕션 힙 트랩 모드** | `PR_MTE_TCF_ASYNC` 또는 `ASYMM` | 0.5% 미만 성능 오버헤드로 모바일/서버 런타임 제로데이 방어 |
| **디버그/진단 트랩 모드** | `PR_MTE_TCF_SYNC` | 정밀한 오류 주소(`si_addr`) 제공을 통한 UAF/OOB 원인 즉시 식별 |
| **메모리 할당자 연동** | Scudo / Hardened Malloc | 객체 해제 시 물리 그래뉼 자동 재도색 및 댕글링 포인터 무력화 |
