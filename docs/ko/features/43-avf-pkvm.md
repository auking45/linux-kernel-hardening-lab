# 안드로이드 가상화 프레임워크 (AVF) 및 pKVM 격리

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**안드로이드 가상화 프레임워크 (AVF) 및 pKVM (`CONFIG_KVM`, Protected KVM)**은 안드로이드 13부터 도입된 차세대 하드웨어 가상화 보안 아키텍처로, **호스트 안드로이드 OS(Host OS, EL1)의 권한을 강등(Deprivileging)시키고 EL2 하이퍼바이저가 관리하는 Stage-2 페이지 테이블(S2PT)을 통해 격리된 마이크로 가상머신(pVM) 메모리를 호스트로부터 원천 은닉 및 차단하는 모바일 하드웨어 격리 기술**임.

전통적인 가상화(Legacy KVM, Type-2 Hypervisor) 및 컨테이너 환경에서는 호스트 커널(Host Kernel)이 모든 게스트 가상머신의 물리 메모리 매핑을 전적으로 소유하고 관리함:

1. **호스트 커널 침해 시 게스트 데이터 전멸 위협**:
   - 공격자가 유저스페이스 취약점이나 커널 로컬 권한 상승(LPE) 익스플로잇을 통해 호스트 안드로이드 커널(EL1)의 root 권한 및 코드 실행 권한을 탈취한 경우, `/dev/mem` 접근, 호스트 페이지 테이블 워크, 하이퍼바이저 제어권 탈취를 통해 게스트 메모리를 무단 덤프할 수 있었음.
   - 지문/안면 생체 인증 템플릿, DRM 마스터 암호키, 디지털 차 키(Digital Car Key), 프라이빗 블록체인 지갑 등 국가 기반시설 및 모바일 금융의 핵심 자산이 호스트 커널 침해 한 번으로 즉시 유출되는 치명적 위협 존재.
2. **pKVM의 권한 강등 혁신**:
   - pKVM은 안드로이드 호스트 OS(EL1)를 **신뢰할 수 없는 엔티티(Untrusted Host)**로 규정함.
   - EL2에서 실행되는 초경량 pKVM 하이퍼바이저는 호스트가 마이크로 게스트(pVM)를 생성할 때 할당한 물리 메모리 페이지를 **호스트의 Stage-2 페이지 테이블(S2PT)에서 완전히 매핑 해제(Unmap)**함.
   - 호스트 커널이 침해당하더라도 pVM 물리 메모리에 접근하는 순간 하드웨어 레벨에서 **Stage-2 Data Abort**가 발생하여 EL2 하이퍼바이저에 즉시 포획 및 차단됨.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. AVF / pKVM 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/avf-pkvm/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 특급 호텔 내 '독립 치외법권 외교 금고실'

AVF 및 pKVM의 방어 원리는 **호텔 건물 내부에 입주한 외국 대사관의 치외법권 외교 금고실**과 일치함:

```
[ 비활성화 상태 (레거시 가상화) ]
  공격자:   "호텔 지배인(Host Kernel root)의 마스터키를 훔쳤다!"
  지배인:   "호텔 내 모든 객실과 투숙객 금고의 마스터 열쇠를 내가 갖고 있으므로 전부 개방!" (게스트 기밀 전면 노출)

[ pKVM 가동 (Host 권한 강등 및 Stage-2 매핑 해제) ]
  호텔:     "특정 방(pVM)을 외국 대사관에 기부(Memory Donation)함과 동시에 호텔 마스터 열쇠 목록(Host S2PT)에서 영구 삭제!"
  공격자:   "훔친 지배인 마스터키로 대사관 금고실 문을 열려고 시도!"
  경비대:   "EL2 하이퍼바이저 경비대가 출동하여 즉각 무력 저지 (Stage-2 Data Abort 발생, -EPERM 거부)!"
  결과:     "호텔 지배인이 통째로 납치당해도 대사관 금고 안의 외교 문서와 생체 정보는 100% 안전 보존!"

[ 합법적 통신: 규격화된 외교 파우치 (virtio-vsock) ]
  호스트:   "금고 안을 직접 보지 않고, 창구(vsock 포트)를 통해 '본인 인증 결과만 확인해 달라'고 요청"
  pVM:      "내부에서 안전하게 지문 대조 수행 후 '일치함(SUCCESS)' 결과 토큰만 전달"
```

---

### 3. 모바일 격리 기술 비교 매트릭스

| 격리 기술 | 실행 위치 | 하이퍼바이저 의존성 | 호스트 커널 침해 시 방어력 | 주 용도 및 한계 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux Containers / Namespace** | Host EL1 | 없음 (동일 커널 공유) | **완전 붕괴** (Kernel LPE 시 즉시 탈취) | 일반 앱 격리 (보안 경계 취약) |
| **ARM TrustZone (TEE)** | Secure EL1 / EL3 | 보안 세계(Secure World) 분리 | **보호됨** | 칩셋 벤더 종속적, 서드파티 앱 배포 어려움, 메모리 용량 극소 |
| **AVF / pKVM (Protected KVM)** | Non-Secure Guest EL1 (Hypervisor EL2) | **ARMv8/v9 pKVM (EL2)** | **완벽 보호 (Stage-2 차단)** | 범용 안드로이드 앱 가상화, 대용량 AI/ML 모델 및 생체키 격리 |

---

## 3. 커널 설정 및 플래그 분석 (Kernel Configurations)

### 1. Hardening Kconfig (`configs/features/avf-pkvm.config`)

```ini
# Linux Kernel Hardening Lab - AVF / pKVM Feature Config
CONFIG_KVM=y
CONFIG_VHOST_VSOCK=y
CONFIG_VIRTIO_VSOCK=y
CONFIG_ARM64_4K_PAGES=y
```

- `CONFIG_KVM=y`: 커널 기반 가상화 모듈 활성화.
- `CONFIG_VHOST_VSOCK=y` & `CONFIG_VIRTIO_VSOCK=y`: 호스트와 마이크로 게스트 간 직접 메모리 공유 없는 격리된 소켓 RPC 통신 프로토콜 제공.
- 부팅 매개변수: `kvm-arm.mode=protected` 지정을 통해 pKVM EL2 하이퍼바이저 활성화 및 호스트 권한 강등 강제.

---

## 4. 실습 및 검증 (Hands-on Lab: `labs/43-avf-pkvm`)

### 1. 실습 환경 구성 요소

1. **타깃 드라이버 (`labs/43-avf-pkvm/vuln_avf.c`)**:
   - pKVM의 Stage-2 메모리 기부 및 매핑 해제 메커니즘을 모사하는 가상화 격리 엔진 구현.
   - `/proc/vuln_avf` (0666) 인터페이스:
     - `create <id> <secret>`: 마이크로 게스트 pVM 생성 및 Stage-2 격리 적용.
     - `host_peek <id>`: 호스트 커널 입장에서 pVM 메모리 직접 읽기 시도 (Stage-2 Data Abort 차단 유도).
     - `host_tamper <id> <data>`: 호스트 커널 입장에서 pVM 메모리 변조 시도 (Stage-2 Write Fault 유도).
     - `vsock <id> <msg>`: 격리된 virtio-vsock 채널을 통한 정상 인증 통신.
     - `mode <pkvm|legacy>`: pKVM 격리와 레거시 취약 가상화 모드 간 전환.
2. **공격 PoC 바이너리 (`labs/43-avf-pkvm/exploit.c`)**:
   - Stage 1: 레거시 가상화 환경에서 침해된 호스트의 게스트 메모리 덤프 시연 (취약점 확인).
   - Stage 2: pKVM 기반 마이크로 게스트 pVM 생성 (Stage-2 메모리 기부 및 매핑 해제).
   - Stage 3: root 권한 호스트의 pVM 메모리 엿보기 시도 시 Stage-2 Data Abort (`-EPERM`) 차단 검증.
   - Stage 4: root 권한 호스트의 pVM 메모리 코드 변조 시도 차단 검증.
   - Stage 5: virtio-vsock 보안 RPC 채널을 통한 정상 인증 요청 처리 검증.
3. **자동화 검증 스크립트 (`labs/43-avf-pkvm/test.sh`)**:
   - 가상화 서브시스템 확인, 타깃 드라이버 점검, PoC 실행 및 dmesg 하이퍼바이저 이벤트 종합 진단.

---

### 2. 단계별 실습 절차

```bash
# 1. 가상머신 기동
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=arm64

# 2. KVM 장치 파일 확인
ls -l /dev/kvm

# 3. AVF / pKVM 자동화 검증 스위트 실행
/bin/test_avf_pkvm
```

### 3. 검증 출력 예시

```text
================================================================
   Lab 43: Android Virtualization Framework & pKVM Suite        
   Kernel: 6.12.109 on aarch64                                  
================================================================

[*] Step 1: Checking KVM virtualization subsystem...
[+] /dev/kvm character device present!

[*] Step 2: Checking target driver at /proc/vuln_avf...
[+] Target driver detected.

[*] Step 3: Querying driver status report...
=== Android Virtualization Framework (AVF / pKVM) Status ===
pKVM Protection Mode     : ENABLED (Protected KVM Active)
Total Host Access Events : 0
Host Peeks Blocked (S2PT): 0
Host Tampers Blocked     : 0
Vsock RPC Exchanges      : 0
Active Micro-Guests (pVMs):
============================================================

[*] Step 4: Running AVF / pKVM PoC...
===============================================================
   Android Virtualization Framework (AVF / pKVM) PoC           
===============================================================

[*] Stage 1: Evaluating Legacy KVM (Unhardened Host Snooping)...
[!] VULNERABLE: Host kernel successfully inspected guest memory!
    In legacy virtualization, compromised host can steal all guest secrets.

[*] Stage 2: Enabling pKVM (Protected KVM) and Spawning pVM #1...
[+] pVM #1 memory donated and unmapped from Host Stage-2 Page Tables (S2PT).

[*] Stage 3: Rooted Host attempts to dump pVM #1 memory directly...
[+] DEFENSE SUCCESS: pKVM EL2 intercepted host read! (errno=1: Operation not permitted)
    Hypervisor Stage-2 Data Abort prevented host kernel snoop!

[*] Stage 4: Rooted Host attempts to overwrite pVM #1 memory...
[+] DEFENSE SUCCESS: pKVM EL2 intercepted host write! (errno=1: Operation not permitted)
    Memory write forbidden in Stage-2 page table; pVM integrity intact!

[*] Stage 5: Legitimate RPC over isolated virtio-vsock channel...
[+] SUCCESS: Vsock RPC communication handled securely by pVM enclave.

[*] Final AVF / pKVM Driver Diagnostics Report:
=== Android Virtualization Framework (AVF / pKVM) Status ===
pKVM Protection Mode     : ENABLED (Protected KVM Active)
Total Host Access Events : 3
Host Peeks Blocked (S2PT): 1
Host Tampers Blocked     : 1
Vsock RPC Exchanges      : 1
Active Micro-Guests (pVMs):
  [pVM #1] Stage-2 Isolated: YES, Secret Status: [SECURED]
============================================================
[+] AVF / pKVM verification completed successfully.

[*] Step 5: Inspecting kernel dmesg for AVF / pKVM events:
[   72.101412] avf_pkvm: [PVM-CREATE] Micro-guest pVM #0 spawned. Memory donated. Stage-2 Isolated: NO
[   72.102315] avf_pkvm: [VULNERABLE SNOOP] Host read pVM #0 memory (Legacy KVM without pKVM Stage-2 isolation)
[   72.103102] avf_pkvm: [PVM-CREATE] Micro-guest pVM #1 spawned. Memory donated. Stage-2 Isolated: YES (Unmapped from Host S2PT)
[   72.103890] avf_pkvm: [STAGE-2 DATA ABORT] Host EL1 tried to read pVM #1 memory! pKVM EL2 intercepted and blocked access (-EPERM)
[   72.104612] avf_pkvm: [STAGE-2 WRITE FAULT] Host EL1 tried to overwrite pVM #1 memory! Blocked by pKVM hypervisor (-EPERM)
[   72.105340] avf_pkvm: [VSOCK RPC] Authenticated request processed by pVM #1 enclave.

================================================================
   Lab 43 Test Complete: Verified Android Virtualization & pKVM 
================================================================
```

---

## 5. 결론 및 보안 점검표 (Checklist)

| 점검 항목 | 권장 설정값 | 보안 보증 내용 |
| :--- | :--- | :--- |
| **pKVM 하이퍼바이저 활성화** | `kvm-arm.mode=protected` | EL2 하이퍼바이저 수준에서 호스트 커널 권한 강등 보장 |
| **Stage-2 매핑 해제** | Memory Donation 자동화 | pVM 실행 시 호스트 S2PT에서 물리 페이지 완전 격리 |
| **격리 통신 프로토콜** | `CONFIG_VIRTIO_VSOCK=y` | 호스트-게스트 간 원시 메모리 노출 없는 소켓 통신 강제 |
| **메모리 스크러빙 보증** | pVM 종료 시 Zeroing | 마이크로 게스트 반환 시 잔류 기밀 데이터 완전 소거 |
| **최소 TCB(신뢰 컴퓨팅 기저)** | 초경량 pVM 이미지 | 수 MB 크기의 마이크로 리눅스 게스트를 통한 공격 표면 극소화 |
