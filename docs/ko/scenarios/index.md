# 실전 공격 시나리오와 하드닝 방어 (Attack Scenarios & Defense)

본 섹션은 정적인 보안 기능 설명서에서 벗어나, **사이버-물리 시스템(CPS) 및 휴머노이드 로봇 환경에서 실제로 발생할 수 있는 공격자의 침투 킬 체인(Kill Chain)**과 이를 무력화하는 **리눅스 커널 하드닝 메커니즘**을 문제 해결 관점에서 분석함.

---

## 🎯 학습 접근법: "공격자 관점(Offensive)에서 방어자 관점(Defensive)으로"

기존 `Features` 탭이 44개 하드닝 기능의 내부 소스코드와 레지스터 명세를 담은 사전식 레퍼런스라면, 본 `Attack Scenarios` 탭은 다음과 같은 **실전 인과관계 파이프라인**을 제공함:

1. **위협 모델 및 실제 CVE 분석 (Real-World CVE Study)**:
   - 양산형 휴머노이드 로봇(예: Unitree G1 EDU) 및 임베디드 리눅스 시스템에서 발생한 실제 취약점 분석.
2. **사이버-물리적 피해 분석 (Cyber-Physical Hazards)**:
   - 메모리 오염이나 권한 상승이 모터 토크 폭주, 보행 붕괴, 세이프티 가드 해제 등 실제 하드웨어 파손으로 연결되는 과정 추적.
3. **수직 스크롤 아키텍처 다이어그램 (Vertical Storytelling)**:
   - 탭 클릭 없이 마우스 스크롤만으로 **정상 동작 ➔ 공격 침투 ➔ 하드닝 차단 ➔ 페일세이프 정지**를 한눈에 파악.
4. **프레젠테이션 카드 & 엔지니어링 딥다이브 (Progressive Disclosure)**:
   - 슬라이드 브리핑용 요약 카드와 하단 레퍼런스 주석을 통해 개요부터 어셈블리/커널 소스 레벨까지 점진적 학습 제공.

---

## 🗺️ 휴머노이드 보안 시나리오 로드맵 (Roadmap)

| 시나리오 | 핵심 취약점 및 공격 기술 | 실제 현실 CVE 사례 | 1차 및 2차 방어선 | 상태 |
| :---: | :--- | :--- | :--- | :---: |
| **01** | **[스택 버퍼 오버플로우 (BOF)](01-humanoid-bof.md)** | **CVE-2026-76640** (Unitree G1 EDU BLE 데몬 BOF ➔ Locomotion PC Root) | **Stack Protector** & **Fortify Source** | <span style="color: #22c55e; font-weight: bold;">완료</span> |
| **02** | **[유저 코드 실행 점프 (ret2usr)](02-ret2usr.md)** | **CVE-2017-7308** (소켓 취약점 ➔ 커널 권한 유저 쉘코드 실행) | **SMEP** (x86) & **PXN** (ARM64) | <span style="color: #22c55e; font-weight: bold;">완료</span> |
| **03** | **[유저 데이터 오염 (ret2dir / SMAP)](03-smap.md)** | **CVE-2016-8655** (UAF ➔ 커널 모드 유저 메모리 데이터 변조) | **SMAP** (x86) & **PAN** (ARM64) | <span style="color: #22c55e; font-weight: bold;">완료</span> |
| **04** | **힙 UAF & 슬랩 메모리 오염** | **CVE-2022-0185** (fs_context Heap BOF ➔ `struct cred` 덮어쓰기) | **SLAB Freelist Hardening** & **KFENCE** | 준비 중 |
| **05** | **제어 흐름 하이재킹 (CFI)** | **CVE-2021-4154** (Type Confusion ➔ 간접 함수 포인터 조작) | **Clang kCFI** & **ARM64 PAC/BTI** | 준비 중 |
| **06** | **부채널/예측 실행 정보 유출** | **CVE-2018-3646** / **Spectre v1/v2** (비전 AI 가속기와 CPU 간 누출) | **array_index_nospec** & **Retpoline/KPTI** | 준비 중 |

---

## 3. 🛡️ 핵심 아키텍처 원리: Rooting (UID 0 / Ring 3) vs Kernel Space (Ring 0)의 본질적 차이 {: #security-boundary-root-vs-kernel }

많은 시스템 관리자와 개발자가 **"루팅(UID 0)을 당하면 공격자가 OS 전체와 하드웨어를 무제한 장악한다"**고 오해함. 그러나 리눅스 아키텍처 관점에서 **유저 공간 루트 권한(Rooting)과 커널 제어권 장악(Kernel Compromise)은 완전히 다른 차원의 보안 경계(Security Boundary)**임:

```
+---------------------------------------------------------------------------------------+
| [USER SPACE (Ring 3 / EL0)]                                                           |
|   - 일반 사용자 (UID 1000)                                                             |
|   - 루트 관리자 (UID 0)  <=== 네트워크 데몬 취약점(Scenario 01) 장악 시 공격자 도달 지점!   |
|     * 파일 시스템(/etc, 설정 파일) 및 일반 네트워크 제어 가능                          |
|     * [하드웨어 격리] CPU 특권 명령어(CR0/CR4, TTBR/SCTLR) 및 물리 메모리 직접 조작 불가!   |
+---------------------------------------------------------------------------------------+
       │
       │ === [하드웨어 특권 전이 경계 (System Call / Exception Boundary)] ===
       │ (커널 하드닝 방어선: Lockdown LSM, Module Signing, Strict Devmem, Seccomp)
       ▼
+---------------------------------------------------------------------------------------+
| [KERNEL SPACE (Ring 0 / EL1)]                                                         |
|   - MMU 페이지 테이블 매핑, 커널 텍스트/데이터, 인터럽트 디스크립터(IDT/VBAR)           |
|   - 하드웨어 완전 제어권 (커널 하드닝 무력화, 메모리 감시 우회, 영구 루트킷 상주 가능)   |
+---------------------------------------------------------------------------------------+
```

### 3.1 유저 공간 권한(UID)과 하드웨어 특권 링(Ring)의 분리 원리

리눅스 시스템의 보안 모델은 **운영체제 수준의 신원 격리(Identity)**와 **CPU 수준의 실행 특권 격리(Hardware Privilege)**라는 2중 구조로 설계됨:

1. **User ID (UID 0 vs UID 1000) — 운영체제 논리 권한**:
   - 커널 내부의 자격 증명 구조체(`struct cred`)에서 관리되는 논리적 정수값임.
   - UID 0(`root`)은 POSIX 표준 파일 시스템 권한 체크(`rwxr-xr-x`)와 Linux Capabilities(`CAP_SYS_ADMIN`, `CAP_NET_ADMIN` 등)를 통과할 수 있는 유저 공간 최고 권한임.
   - 그러나 **UID 0 프로세스 또한 CPU 입장에서는 여전히 비특권 유저 모드(Ring 3 / EL0)**에서 실행되는 태스크에 불과함.

2. **CPU Execution Rings (Ring 3 vs Ring 0) — 하드웨어 물리 격리**:
   - CPU 아키텍처(x86_64 CPL 레지스터, ARM64 CurrentEL 레지스터)가 물리 회로 레벨에서 강제하는 메모리 및 명령어 접근 제한임.
   - Ring 3(EL0)에서는 페이지 테이블을 조작하거나 하드웨어 제어 레지스터(x86의 `CR0`, `CR3`, `CR4` / ARM의 `SCTLR_EL1`, `TTBR0/1_EL1`)에 쓰기 작업을 수행할 수 없음.
   - 이를 위반하는 명령어를 실행할 경우, CPU 하드웨어가 즉각 **Illegal Instruction (`SIGILL`)** 또는 **General Protection Fault (`#GP`)** 예외를 발생시키고 실행을 중단함.

---

### 3.2 루트(UID 0) 상태에서도 커널 하드닝에 의해 차단되는 4대 핵심 작업

과거의 레거시 리눅스에서는 root 권한을 획득하면 `/dev/mem`을 통해 커널 메모리를 덮어쓰거나 악성 모듈을 로드하여 손쉽게 Ring 0로 진입할 수 있었음. 그러나 **현대의 강화된 리눅스 커널(Hardened Kernel)**에서는 UID 0 권한을 획득하더라도 다음 핵심 작업들이 Ring 3 유저 공간에서 원천 차단됨:

| 차단 대상 작업 | 공격자의 목적 | 동작 차단 커널 하드닝 메커니즘 | 방어 결과 및 영향 |
| :--- | :--- | :--- | :--- |
| **물리 메모리 및 커널 코드 직접 변조** | 실행 중인 커널 메모리에 쉘코드 삽입 또는 함수 후킹 | `CONFIG_STRICT_DEVMEM`<br>+ Kernel Lockdown LSM (`integrity` 모드) | root 권한으로 `/dev/mem`, `/dev/kmem`을 오픈하려 시도해도 커널이 `EPERM` 거부 |
| **미서명 악성 커널 모듈 로드** | LKM 루트킷을 로드하여 커널 공간에 영구 상주 | `CONFIG_MODULE_SIG_FORCE`<br>+ `CONFIG_MODULE_SIG_ALL` | 개인키 서명이 없는 임의 모듈의 `init_module()` 호출 시 로드 즉각 거부 |
| **CPU 특권 제어 레지스터 변조** | SMEP/SMAP 보호 비트 해제 또는 MMU 페이지 디렉터리 조작 | Hardware Ring 3 Trap<br>(CPU CPL / Exception Level 검증) | `mov %rax, %cr4` 등의 하드웨어 명령어 실행 시 CPU가 즉각 `#GP` / `SIGILL` 트랩 발생 |
| **핵심 바이너리 및 커널 파라미터 위변조** | 부팅 이미지 교체 또는 kexec를 통한 비인가 커널 점프 | IMA (무결성 측정) / EVM (메타데이터)<br>+ `CONFIG_KEXEC_SIG` | 디지털 서명 불일치 바이너리 실행 거부 및 비인가 커널 kexec 점프 차단 |

---

### 3.3 공격 체인의 필연적 진화: 1차 데몬 침투에서 2차 커널 침투로의 피벗

이와 같은 Ring 3와 Ring 0 간의 견고한 하드웨어 및 커널 하드닝 장벽 때문에, 실제 공격자의 침투 킬 체인은 단일 공격으로 끝나지 않고 **필연적인 다단계 피벗(Multi-Stage Pivot)** 과정을 거치게 됨:

```mermaid
flowchart TD
    subgraph Stage1 ["1단계: 유저 공간 원격 침투 (User Space RCE)"]
        A["원격 공격 벡터 (BLE / Wi-Fi / Web)"] -->|"BOF / RCE 취약점"| B["통신 데몬 장악 (UID 0 / Ring 3)"]
        B --> C["[Scenario 01] Unitree G1 BLE BOF & Stack Canary"]
    end

    subgraph Stage2 ["보안 경계 도달 및 차단 (Hardening Boundary)"]
        C -->|"직접 커널 조작 시도"| D{"커널 하드닝 활성화 여부"}
        D -->|"Strict Devmem / Lockdown / ModSig"| E["[차단] 커널 메모리 직접 쓰기 불가!"]
    end

    subgraph Stage3 ["2단계: 커널 공간 권한 상승 피벗 (Kernel Privilege Escalation)"]
        E -->|"로컬 2차 공격 벡터 모색"| F["커널 시스템 콜 취약점 익스플로잇"]
        F --> G["[Scenario 02] ret2usr 기법 ➔ SMEP/PXN 방어선과 충돌"]
        F --> H["[Scenario 03] ret2dir / SMAP 기법 ➔ 커널의 유저 데이터 접근 방어"]
        F --> I["[Scenario 04] Heap UAF / SLAB 오염 ➔ struct cred 변조 차단"]
    end

    style Stage1 fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#fff
    style Stage2 fill:#334155,stroke:#ef4444,stroke-width:2px,color:#fff
    style Stage3 fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#fff
```

1. **1단계 (Scenario 01 - 외부 진입점)**:
   - 네트워크/무선 인터페이스 데몬의 메모리 결함(BOF)을 뚫고 프로세스 제어권을 획득하여 유저 공간 관리자 권한(UID 0)에 도달함.
2. **경계 차단 (하드닝 장벽)**:
   - 루트 권한을 얻었음에도 불구하고 커널 하드닝(`Strict Devmem`, `Lockdown`, `Module Signing`)에 가로막혀 영구 루트킷 설치나 하드웨어 완전 장악이 불가능함을 체감함.
3. **2단계 (Scenario 02 ~ 06 - 커널 침투 피벗)**:
   - 공격자는 시스템 콜 핸들러나 소켓 서브시스템의 취약점을 찾아 **Ring 3에서 Ring 0로 침투하는 2차 로컬 권한 상승(LPE)**을 시도함.
   - 이때 유저 공간 쉘코드로 점프하려는 공격을 막아내는 메커니즘이 바로 **[Scenario 02. ret2usr & SMEP/PXN]**이며, 커널 힙 메모리 변조를 막아내는 기법이 **[Scenario 04. Heap UAF]**임.

---

## 4. 🚀 학습 시작 가이드 (Get Started)

가장 기본적인 메모리 침범 결함이자 실제 양산형 휴머노이드 로봇을 위협한 **[Scenario 01. 휴머노이드 무선 통신 데몬의 버퍼 오버플로우와 스택 카나리 방어](01-humanoid-bof.md)**부터 학습을 시작함.
