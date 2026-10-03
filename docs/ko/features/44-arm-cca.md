# Arm CCA (Confidential Compute Architecture) 기밀 컴퓨팅

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**Arm CCA (`CONFIG_ARM64_RME`, ARMv9-A)**는 퍼블릭 클라우드 및 멀티테넌트 가상화 환경에서 **호스트 운영체제 및 하이퍼바이저를 잠재적 위협(Untrusted Hypervisor)으로 규정하고, 하드웨어 레벨의 4-World 격리와 과립형 메모리 보호(GPC)를 통해 테넌트 기밀 가상머신(Realm VM)의 실행 무결성 및 메모리 기밀성을 절대적으로 보장하는 차세대 기밀 컴퓨팅(Confidential Computing) 아키텍처**임.

전통적인 클라우드 컴퓨팅 환경에서는 클라우드 인프라 제공자(CSP), 하이퍼바이저(KVM/ESXi), 서버 팜 관리자 계정이 모든 가상머신의 메모리를 물리적으로 읽고 쓸 수 있는 완전한 권한을 보유함:

1. **신뢰할 수 없는 클라우드 인프라 위협 (Untrusted Infrastructure)**:
   - 악의적인 내부자(Rogue Cloud Admin), 하이퍼바이저 취약점 공격자, 국가 기관의 법적 영장 집행 등을 통해 클라우드 호스트 레벨에서 고객 VM 메모리를 직접 덤프하는 스누핑(Memory Snooping) 공격.
   - 금융 데이터, 독점 인공지능(AI) 모델 가중치(Weights), 블록체인 검증자 개인키 등 핵심 비즈니스 자산이 무단 탈취될 수 있는 구조적 한계 노출.
2. **Arm CCA의 4-World 아키텍처 혁신**:
   - 기존의 2-World(Secure vs Non-Secure) 구조를 넘어 **4-World(Root, Realm, Secure, Non-Secure)**로 하드웨어 실행 영역을 확장함.
   - **Root World (EL3)**: 플랫폼 보안 모니터 및 하드웨어 신뢰 기저.
   - **Realm World (R-EL2 / R-EL1)**: 기밀 가상머신(Realm VM) 및 이를 관장하는 RMM(Realm Management Monitor).
   - **하드웨어 과립형 보호 테이블 (GPT / GPC)**: MMU가 물리 메모리 버스 접근 시 요청자의 World와 GPT 상태를 대조하여, Non-Secure(하이퍼바이저)가 Realm 메모리를 읽거나 쓰려는 즉시 **Granule Protection Fault (GPF)**를 발생시켜 하드웨어 선에서 차단함.
3. **원격 증명(Remote Attestation)**:
   - 고객은 클라우드에 데이터를 전송하기 전, 하드웨어 칩셋 서명이 포함된 SHA-256 측정 증명 토큰을 검증하여 Realm VM이 변조 없이 안전하게 부팅되었음을 수학적으로 확인함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. Arm CCA 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/arm-cca/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 상업 물류센터 내 '스위스 비밀 은행 금고'

Arm CCA의 보호 원리는 **상업 물류센터(클라우드 호스트) 내부에 설치된 스위스 은행의 독립 장갑 금고(Realm)**와 일치함:

```
[ 비활성화 상태 (레거시 클라우드 가상화) ]
  침입자:   "클라우드 하이퍼바이저 root 권한을 탈취했다!"
  하이퍼바이저: "물류창고 주인이므로 모든 고객의 컨테이너를 열고 귀중품(AI 가중치, 암호키)을 털어가겠다!" (기밀성 상실)

[ Arm CCA 가동: 물리 과립 위임 (RMI_GRANULE_DELEGATE) ]
  고객:     "금고 공간을 스위스 은행(Realm World)에 등록하고 특수 하드웨어 잠금장치(GPT_REALM)를 체결!"
  하이퍼바이저: "고객 금고 메모리를 직접 읽으려고 시도!"
  하드웨어: "실리콘 MMU의 Granule Protection Check (GPC) 유닛 작동! '비보안 호스트 접근 불가' 판정!"
  조치:     "물리 버스 신호 즉각 차단! Granule Protection Fault (-EPERM) 발생! 데이터 유출 차단!"

[ 원격 검증: 암호학적 디지털 봉인 증명 (Remote Attestation) ]
  고객:     "스위스 은행 중앙 서버(Root EL3)에서 발급한 실리콘 서명과 금고 내용물 SHA-256 해시값 대조!"
  판정:     "부팅 후 단 한 바이트도 변조되지 않았음을 확인 완료! 안심하고 1급 기밀 데이터 주입!"
```

---

### 3. 기밀 컴퓨팅 아키텍처 3사 비교 매트릭스

| 비교 항목 | Arm CCA (`CONFIG_ARM64_RME`) | AMD SEV-SNP | Intel TDX |
| :--- | :--- | :--- | :--- |
| **격리 기반** | **4-World 하드웨어 분리 (RMM + GPT)** | 메모리 암호화 엔진 (AES-128/256) | Trust Domain (SEAM / KeyLocker) |
| **물리 메모리 보호** | **Granule Protection Check (GPC)** | Reverse Map Table (RMT) | Secure EPT (S-EPT) |
| **하이퍼바이저 권한** | 리소스 스케줄링 전담 (메모리 접근 불가) | 페이지 매핑 전담 (암호화로 인해 판독 불가) | CPU 시간 할당 전담 (접근 차단) |
| **원격 증명 방식** | RMM SHA-256 측정 + 칩셋 RoT 서명 | VCEK 기반 증명 보고서 | Quote 검증 서비스 (QGS) |
| **메모리 오버헤드** | GPT 테이블 (~1.5% RAM 소비) | 암호화 태그 오버헤드 | TDX 메타데이터 메모리 |

---

## 3. 커널 설정 및 플래그 분석 (Kernel Configurations)

### 1. Hardening Kconfig (`configs/features/arm-cca.config`)

```ini
# Linux Kernel Hardening Lab - Arm CCA Feature Config
CONFIG_KVM=y
CONFIG_ARM64_RME=y
CONFIG_CRYPTO=y
CONFIG_CRYPTO_SHA256=y
CONFIG_ARM64_4K_PAGES=y
```

- `CONFIG_ARM64_RME=y`: 커널 레벨 Realm Management Extension(RME) 및 KVM 호스트 Realm 제어 서브시스템 활성화.
- `CONFIG_KVM=y`: Realm 가상머신 생명주기 및 vCPU 스케줄링을 관장하는 KVM 인터페이스 제공.
- `CONFIG_CRYPTO_SHA256=y`: 원격 증명 보고서 및 런타임 측정 다이제스트 계산 지원.

---

## 4. 실습 및 검증 (Hands-on Lab: `labs/44-arm-cca`)

### 1. 실습 환경 구성 요소

1. **타깃 드라이버 (`labs/44-arm-cca/vuln_cca.c`)**:
   - 4-World 모델 및 Granule Protection Table (GPT) 하드웨어 로직을 모사한 실습 드라이버.
   - `/proc/vuln_cca` (0666) 인터페이스:
     - `create <id>`: Realm VM 인스턴스 생성 (초기 측정치 초기화).
     - `delegate <id> <secret>`: 물리 메모리 과립을 `GPT_REALM`으로 위임하고 기밀 데이터 적재.
     - `host_read <id>`: Non-Secure 호스트의 Realm 메모리 직접 엿보기 시도 (GPC Fault 유도).
     - `host_write <id> <data>`: Non-Secure 호스트의 Realm 메모리 코드 주입 시도 (GPC Write Protect 차단).
     - `attest <id>`: SHA-256 기반 암호학적 원격 증명 보고서 발급 및 검증.
     - `mode <cca|legacy>`: Arm CCA GPC 강제 모드와 레거시 취약 하이퍼바이저 모드 간 전환.
2. **공격 PoC 바이너리 (`labs/44-arm-cca/exploit.c`)**:
   - Stage 1: 레거시 클라우드 가상머신의 메모리 탈취 취약점 시연.
   - Stage 2: Arm CCA 기반 Realm VM 생성 및 물리 과립 `GPT_REALM` 위임.
   - Stage 3: 침해된 클라우드 호스트의 Realm 메모리 덤프 시도 시 Granule Protection Fault (`-EPERM`) 차단 검증.
   - Stage 4: 클라우드 호스트의 백도어 주입 및 코드 변조 시도 차단 검증.
   - Stage 5: 암호학적 원격 증명 측정 보고서 검증을 통한 무결성 입증.
3. **자동화 검증 스크립트 (`labs/44-arm-cca/test.sh`)**:
   - 아키텍처 및 RME 지원 상태 진단, 타깃 드라이버 확인, PoC 구동 및 커널 GPC 이벤트 종합 진단.

---

### 2. 단계별 실습 절차

```bash
# 1. 가상머신 기동
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. CPU RME/CCA 플래그 확인
cat /proc/cpuinfo | grep -i rme

# 3. Arm CCA 자동화 검증 스위트 실행
/bin/test_arm_cca
```

### 3. 검증 출력 예시

```text
================================================================
   Lab 44: Arm Confidential Compute Architecture (Arm CCA)      
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking CPU Architecture and Arm CCA hardware support...
    Architecture: aarch64

[*] Step 2: Checking target driver at /proc/vuln_cca...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== Arm Confidential Compute Architecture (Arm CCA) Status ===
Hardware CCA Engine      : ENABLED (Granule Protection Active)
Security World Model     : 4-World (Root, Realm, Secure, Non-Secure)
Total Host Access Events : 0
GPC Read Faults (GPF)    : 0
GPC Write Faults (GPF)   : 0
Attestation Verifications: 0
Active Realm VMs (R-EL1):
==============================================================

[*] Step 4: Running Arm CCA PoC...
===============================================================
   Arm Confidential Compute Architecture (Arm CCA) PoC         
===============================================================

[*] Stage 1: Evaluating Legacy Cloud Hypervisor (Unhardened)...
[!] VULNERABLE: Cloud hypervisor stole tenant private key!
    In standard cloud setups, rogue hypervisors have complete memory access.

[*] Stage 2: Deploying Confidential Realm VM #1 under Arm CCA...
[+] Physical memory granules transitioned to GPT_REALM under RMM control.

[*] Stage 3: Untrusted Cloud Hypervisor attempts to inspect Realm VM #1...
[+] DEFENSE SUCCESS: Hardware GPC raised Granule Protection Fault! (errno=1: Operation not permitted)
    Silicon MMU prevented Non-Secure CPU core from reading Realm memory!

[*] Stage 4: Untrusted Cloud Hypervisor attempts to inject code into Realm...
[+] DEFENSE SUCCESS: Hardware GPC blocked write! (errno=1: Operation not permitted)
    Physical memory write-protect enforced by Granule Protection Table!

[*] Stage 5: Performing Cryptographic Remote Attestation...
[+] SUCCESS: Remote attestation report cryptographically verified!
    Proves Realm code integrity and uncompromised initial state.

[*] Final Arm CCA Driver Diagnostics Report:
=== Arm Confidential Compute Architecture (Arm CCA) Status ===
Hardware CCA Engine      : ENABLED (Granule Protection Active)
Security World Model     : 4-World (Root, Realm, Secure, Non-Secure)
Total Host Access Events : 3
GPC Read Faults (GPF)    : 1
GPC Write Faults (GPF)   : 1
Attestation Verifications: 1
Active Realm VMs (R-EL1):
  [Realm #1] GPT State: GPT_REALM (Hardware Protected), Measurement: a3f5b721e89b4317...
==============================================================
[+] Arm CCA verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for Arm CCA events:
[   81.101200] arm_cca: [RMI_REALM_CREATE] Realm VM #0 created in Realm World (R-EL1).
[   81.101912] arm_cca: [VULNERABLE SNOOP] Host read tenant VM #0 memory! (Legacy Hypervisor)
[   81.102640] arm_cca: [RMI_REALM_CREATE] Realm VM #1 created in Realm World (R-EL1).
[   81.103310] arm_cca: [RMI_GRANULE_DELEGATE] Physical granule transitioned to GPT_REALM. Managed by RMM.
[   81.104012] arm_cca: [GRANULE PROTECTION FAULT] Host read denied! GPC: Non-Secure CPU cannot read GPT_REALM (-EPERM)
[   81.104715] arm_cca: [GRANULE PROTECTION FAULT] Host write denied! GPC: Non-Secure CPU cannot write GPT_REALM (-EPERM)
[   81.105410] arm_cca: [RMI_ATTESTATION] Cryptographic measurement validated: a3f5b721e89b4317...

================================================================
   Lab 44 Test Complete: Verified Arm Confidential Compute (CCA)
================================================================
```

---

## 5. 결론 및 보안 점검표 (Checklist)

| 점검 항목 | 권장 설정값 | 보안 보증 내용 |
| :--- | :--- | :--- |
| **RME 하이퍼바이저 지원** | `CONFIG_ARM64_RME=y` | ARMv9 Realm Management Extension 및 RMM 통신 활성화 |
| **과립 위임 상태 전환** | `GPT_REALM` 위임 확인 | 테넌트 메모리 할당 시 하드웨어 GPC 필터링 강제 적용 |
| **원격 증명 필수 검증** | 클라이언트단 토큰 검증 | 기밀 데이터 송신 전 SHA-256 측정값 및 RoT 서명 대조 |
| **메모리 잔류 방지** | Undelegate 시 제로화 | Realm 종료 시 물리 메모리 스크러빙을 통해 정보 잔존 차단 |
| **비보안 접근 전면 차단** | Granule Protection Fault | 호스트 root 및 하이퍼바이저의 직접 물리 메모리 접근 차단 |
