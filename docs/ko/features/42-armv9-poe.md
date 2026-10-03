# ARMv9 POE (Permission Overlay Extension) 권한 오버레이 격리

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**ARMv9 POE (`CONFIG_ARM64_POE`, ARMv8.9-A / ARMv9.4-A)**는 전통적인 페이지 테이블(Page Table) 기반의 메모리 권한 통제를 혁신하여, **페이지 테이블 수정 및 시스템 콜 호출 없이 CPU 레지스터(`POR_EL0`) 쓰기만으로 프로세스 내부 메모리 격실(Intra-Process Compartment)의 접근 권한을 1 클럭 사이클 내에 동적으로 전환하는 최신 하드웨어 메모리 권한 오버레이 기술**임.

현대 유저스페이스 소프트웨어 및 런타임 환경(브라우저, OpenSSL, 데이터베이스)은 단일 프로세스 메모리 공간 내에 신뢰 수준이 서로 다른 다양한 서드파티 라이브러리와 플러그인을 공존하여 실행함:

1. **프로세스 내부 횡적 이동(Lateral Movement) 위협**:
   - 공격자가 취약한 서드파티 라이브러리(e.g., 이미지 파서, 네트워크 파서)의 메모리 결함을 악용하여 임의 읽기/쓰기 권한을 확보한 후, 동일 프로세스 힙/스택에 상주하는 마스터 개인키(RSA/AES), 인증 토큰, JIT 실행 버퍼를 직접 탈취하거나 변조하는 위협 존재.
2. **기존 `mprotect(2)` 메커니즘의 성능 한계**:
   - 민감 데이터를 보호하기 위해 전통적으로 `mprotect()` 시스템 콜을 호출하여 메모리를 `PROT_NONE`과 `PROT_READ`로 번갈아 전환했으나, 이는 매 호출마다 **(1) 커널 모드 전환(Syscall Trap), (2) 페이지 테이블 엔트리(PTE) 갱신, (3) 멀티코어 TLB 무효화(TLB Shootdown, `TLBI` 명령)를 유발**하여 수천~수만 클럭 사이클의 심각한 성능 저하 초래.
   - 이러한 오버헤드로 인해 실시간 암호 연산이나 찰나의 순간에만 메모리를 여는 세분화된 메모리 격실화(Fine-grained Compartmentalization) 적용이 불가능했음.
3. **ARMv9 POE의 하드웨어 혁신**:
   - 페이지 테이블에는 정적인 '보호 키 인덱스(Protection Key Index, 0~7)'만 할당해 두고, 실제 허용 여부는 CPU 레지스터인 **`POR_EL0`(Permission Overlay Register EL0)**에서 판정함.
   - 권한 잠금/해제 시 시스템 콜 없이 단순 레지스터 쓰기(`MSR POR_EL0, Xn`) 1회로 완료되어 **오버헤드가 사실상 0에 수렴(1 CPU Cycle)**함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. ARMv9 POE 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/armv9-poe/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 은행 금고의 '전자 중앙 차단 스위치'

ARMv9 POE의 동작 원리는 **은행 지점의 물리적 금고문과 지점장 책상의 초고속 전자 차단 스위치**와 일치함:

```
[ 비활성화 상태 (레거시 mprotect 방식) ]
  보안관:   "금고 권한을 잠그려면 본사 승인을 받아(Syscall Trap) 공사 인부를 불러 문을 용접하고(PTE 수정), 모든 경비원 무전기로 공지(TLB Shootdown)해야 함!"
  문제점:   "잠그고 여는 데 너무 오래 걸려 평소에는 금고문을 열어둘 수밖에 없음!" (해커가 언제든 털어감)

[ ARMv9 POE 가동: 평상시 격실 완전 잠금 (POR_EL0[Key 1] = NONE) ]
  보안관:   "책상 위 전자 스위치(`POR_EL0`)를 1초 만에 딸깍 내려 '0(NONE)'으로 설정!"
  공격자:   "취약한 모듈을 통해 금고(Key 1)의 마스터키를 읽으려고 시도!"
  하드웨어: "CPU 메모리 제어기가 POR_EL0 확인! 'Key 1: NONE'! 데이터 버스 즉각 차단!"
  조치:     "하드웨어 오버레이 폴트(`SIGSEGV / SEGV_PKUERR`) 발생! 데이터 노출 원천 차단!"

[ 인가된 트랜잭션 수행 시: 찰나의 해제 및 즉각 재잠금 ]
  암호모듈: "1. 스위치 딸깍 (`MSR POR_EL0`: Key 1 -> RW, 1사이클 소요)"
            "2. 개인키로 트랜잭션 전자 서명 수행"
            "3. 스위치 즉시 복구 (`MSR POR_EL0`: Key 1 -> NONE, 1사이클 소요)"
  보안효과: "공격자가 침투할 수 있는 노출 시간(Exposure Window)을 마이크로초 단위로 극소화!"
```

---

### 3. ARMv9 POE와 x86 MPK/PKU 비교 매트릭스

| 비교 항목 | ARMv9 POE / S1POE (`CONFIG_ARM64_POE`) | x86 MPK / PKU (`CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS`) |
| :--- | :--- | :--- |
| **제어 레지스터** | `POR_EL0` (유저), `POR_EL1` (커널) | `PKRU` (유저 전용 레지스터) |
| **권한 표현 방식** | 4비트 오버레이 니블 (None, Read, RW, Exec, RX 등 세분화) | 2비트 차단 비트 (Access Disable, Write Disable) |
| **실행 권한 통제** | 지원 가능 (`POE_PERM_X`, 실행 오버레이 제어) | 기본 미지원 (W/R 제어 위주, PKU 실행 통제 제약) |
| **가상화 스테이지 2** | 지원 (S2POE 가상화 하이퍼바이저 오버레이 지원) | EPT 기반 확장 필요 |
| **레지스터 변경 명령** | `MSR POR_EL0, Xn` (단일 범용 레지스터 쓰기) | `WRPKRU` (전용 비특권 명령) |
| **전환 소요 시간** | **1 CPU Cycle** (제로 시스템 콜) | **수 클럭 사이클** (제로 시스템 콜) |

---

## 3. 커널 설정 및 플래그 분석 (Kernel Configurations)

### 1. Hardening Kconfig (`configs/features/poe.config`)

```ini
# Linux Kernel Hardening Lab - ARMv9 POE Feature Config
CONFIG_ARM64_POE=y
CONFIG_ARCH_HAS_PKEYS=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
```

- `CONFIG_ARM64_POE=y`: 커널 레벨 ARMv9.4-A Permission Overlay Extension 및 S1POE 서브시스템 활성화.
- `CONFIG_ARCH_HAS_PKEYS=y`: 리눅스 표준 메모리 프로텍션 키(`pkey_alloc`, `pkey_mprotect`, `pkey_free`) 시스템 콜 인터페이스 바인딩.
- `CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y`: VMA 상위 비트에 키 인덱스를 인코딩할 수 있도록 아키텍처 플래그 지원.

### 2. 프로텍션 키 할당 및 VMA 매핑 API

```c
#define _GNU_SOURCE
#include <sys/mman.h>

/* 1. 새로운 하드웨어 도메인 키 할당 */
int pkey = pkey_alloc(0, 0);

/* 2. 대상 메모리 페이지에 키 인덱스 부여 (PTE 매핑) */
pkey_mprotect(secret_vault, 4096, PROT_READ | PROT_WRITE, pkey);

/* 3. 유저스페이스 레지스터 수준에서 즉시 잠금 (Key 1에 NONE 할당) */
/* ARM64 POE의 경우 POR_EL0 레지스터에 비트마스크 적용 */
```

---

## 4. 실습 및 검증 (Hands-on Lab: `labs/42-armv9-poe`)

### 1. 실습 환경 구성 요소

1. **타깃 드라이버 (`labs/42-armv9-poe/vuln_poe.c`)**:
   - 8개의 보호 키(Key 0~7)를 지원하는 `POR_EL0` 레지스터 에뮬레이션 및 비밀 금고(Vault) 구현.
   - `/proc/vuln_poe` (0666) 인터페이스:
     - `read_vault`: Key 1로 보호된 비밀 금고 데이터 읽기 시도.
     - `write_vault <data>`: Key 1로 보호된 비밀 금고에 데이터 변조 시도.
     - `lock_vault`: `POR_EL0`의 Key 1 권한을 `POE_PERM_NONE (0x0)`으로 즉시 변경 (1사이클 락다운).
     - `unlock_vault`: `POR_EL0`의 Key 1 권한을 `POE_PERM_RW (0x3)`으로 변경.
     - `set_por <key> <perm>`: 임의 키에 대한 오버레이 권한 수동 설정.
2. **공격 PoC 바이너리 (`labs/42-armv9-poe/exploit.c`)**:
   - Stage 1: 무방비 잠금 해제 상태에서 기밀 유출 취약점 확인.
   - Stage 2: `POR_EL0` 레지스터 락다운 수행.
   - Stage 3: 비인가 읽기 시도 시 하드웨어 오버레이 폴트(`-EACCES / SEGV_PKUERR`) 차단 검증.
   - Stage 4: 비인가 쓰기 시도 시 메모리 변조 차단 검증.
   - Stage 5: 정당한 암호화 워커의 초고속 해제 -> 서명 -> 즉각 재잠금 사이클 검증.
3. **자동화 검증 스크립트 (`labs/42-armv9-poe/test.sh`)**:
   - 아키텍처 및 POE 지원 여부 진단, 드라이버 검증, PoC 구동 및 커널 로그 종합 평가.

---

### 2. 단계별 실습 절차

```bash
# 1. 대상 가상머신 기동
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. CPU POE 지원 플래그 확인
cat /proc/cpuinfo | grep -i poe

# 3. ARMv9 POE 자동화 검증 스위트 실행
/bin/test_armv9_poe
```

### 3. 검증 출력 예시

```text
================================================================
   Lab 42: ARMv9 Permission Overlay Extension (POE) Suite       
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking CPU Architecture and POE hardware support...
    Architecture: aarch64

[*] Step 2: Checking target driver at /proc/vuln_poe...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== ARMv9 POE (Permission Overlay Extension) Status ===
Kernel POE Support       : CONFIG_ARM64_POE=y
Simulated POR_EL0 Reg    : 0x00000033
Total Access Attempts    : 0
Read Allowed / Blocked   : 0 / 0
Write Allowed / Blocked  : 0 / 0
Protection Domain Key Table (POR_EL0):
  [Key 0] Perm: 0x3 - READ-WRITE (Full Access)
  [Key 1] Perm: 0x3 - READ-WRITE (Full Access) <- [PROTECTED SECRET VAULT]
  [Key 2] Perm: 0x0 - NONE (No Access - Fault on Read/Write)
  [Key 3] Perm: 0x0 - NONE (No Access - Fault on Read/Write)
====================================================

[*] Step 4: Running ARMv9 POE PoC...
===============================================================
   ARMv9 Permission Overlay Extension (POE) Evaluation PoC    
===============================================================

[*] Stage 1: Accessing Secret Vault in Unlocked State (POR_EL0: RW)...
[!] VULNERABLE: Secret vault data exposed! Any untrusted module can read it.

[*] Stage 2: Locking Vault Compartment via POR_EL0 register...
[+] Setting POR_EL0 Key 1 permission to POE_PERM_NONE (0x0)...

[*] Stage 3: Untrusted code attempts to read locked secret vault...
[+] DEFENSE SUCCESS: Hardware overlay trapped read access! (errno=13: Permission denied)
    Memory access halted by CPU POR_EL0 overlay (SEGV_PKUERR)!

[*] Stage 4: Untrusted code attempts to overwrite locked secret vault...
[+] DEFENSE SUCCESS: Hardware overlay trapped write access! (errno=13: Permission denied)
    Write tampering blocked in silicon before modifying memory!

[*] Stage 5: Authorized crypto routine: Fast unlock -> operation -> relock...
[+] Step 5a: Authorized routine unlocks POR_EL0 Key 1 to RW (1 CPU cycle)...
[+] Step 5b: Authorized routine reads secret key and signs transaction...
[+] Transaction signed successfully using private key in vault.
[+] Step 5c: Authorized routine immediately relocks POR_EL0 Key 1 to NONE (1 CPU cycle)...

[*] Final ARMv9 POE Driver Diagnostics Report:
=== ARMv9 POE (Permission Overlay Extension) Status ===
Kernel POE Support       : CONFIG_ARM64_POE=y
Simulated POR_EL0 Reg    : 0x00000003
Total Access Attempts    : 4
Read Allowed / Blocked   : 2 / 1
Write Allowed / Blocked  : 0 / 1
Protection Domain Key Table (POR_EL0):
  [Key 0] Perm: 0x3 - READ-WRITE (Full Access)
  [Key 1] Perm: 0x0 - NONE (No Access - Fault on Read/Write) <- [PROTECTED SECRET VAULT]
====================================================
[+] ARMv9 POE verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for POE events:
[   65.101200] vuln_poe: [ACCESS GRANTED] Read permitted on Key 1 (POR_EL0: R/RW)
[   65.101912] vuln_poe: [LOCKDOWN] Vault compartment (Key 1) locked in POR_EL0 (Perm: NONE)
[   65.102640] vuln_poe: [OVERLAY FAULT] Read denied on Key 1! POR_EL0 perm: 0x0 (-EACCES / SEGV_PKUERR)
[   65.103310] vuln_poe: [OVERLAY FAULT] Write denied on Key 1! POR_EL0 perm: 0x0 (-EACCES / SEGV_PKUERR)
[   65.104012] vuln_poe: [UNLOCKED] Vault compartment (Key 1) unlocked in POR_EL0 (Perm: RW)
[   65.104715] vuln_poe: [ACCESS GRANTED] Read permitted on Key 1 (POR_EL0: R/RW)
[   65.105410] vuln_poe: [LOCKDOWN] Vault compartment (Key 1) locked in POR_EL0 (Perm: NONE)

================================================================
   Lab 42 Test Complete: Verified ARMv9 Permission Overlay Ext  
================================================================
```

---

## 5. 결론 및 보안 점검표 (Checklist)

| 점검 항목 | 권장 설정값 | 보안 보증 내용 |
| :--- | :--- | :--- |
| **하드웨어 POE 지원** | `CONFIG_ARM64_POE=y` | ARMv8.9/v9.4+ 하드웨어 권한 오버레이 서브시스템 가동 |
| **표준 PKEY 서브시스템** | `CONFIG_ARCH_HAS_PKEYS=y` | `pkey_alloc`, `pkey_mprotect` 표준 시스템 콜 연동 보장 |
| **기밀 자산 격실화** | PKEY 분리 할당 | 비밀키, 암호 토큰, 세션 쿠키를 격리된 전용 키 도메인에 배치 |
| **제로 시스콜 락다운** | `POR_EL0` 상시 잠금 | 평상시 권한을 `NONE`으로 유지하여 임의 메모리 덤프 차단 |
| **최소 노출 윈도우** | 즉각적 재잠금(Re-lock) | 연산 직후 단 1사이클 내에 즉시 도메인을 잠궈 공격 기회 소멸 |
