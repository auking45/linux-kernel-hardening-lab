# 커널 메모리 모델 및 보안 아키텍처 (Memory & Protection Models)

x86_64 및 arm64 아키텍처의 가상 메모리 분할 구조, 특권 레벨 모델 및 커널 하드닝 방어 계층 분석.

---

## 1. 특권 레벨 모델 비교

```mermaid
graph TD
    subgraph x86_64 ["x86_64 Privilege Rings"]
        R3["Ring 3: User Space (Applications)"]
        R0["Ring 0: Kernel Space (Kernel Core, Modules)"]
        R3 -->|"syscall / sysenter"| R0
    end

    subgraph arm64 ["ARM64 Exception Levels"]
        EL0["EL0: User Space (Applications)"]
        EL1["EL1: Kernel Space (OS Kernel)"]
        EL2["EL2: Hypervisor (KVM)"]
        EL3["EL3: Secure Monitor (Firmware)"]
        EL0 -->|"svc (Supervisor Call)"| EL1
    end
```

---

## 2. 64비트 가상 주소 공간 분할 (Virtual Address Space)

### 2.1 x86_64 (48-bit / 4-Level Paging 기준)
- `0x0000_0000_0000_0000` ~ `0x0000_7FFF_FFFF_FFFF` (128TB): **유저 공간 (User Space)**
- `0x0000_8000_0000_0000` ~ `0xFFFF_7FFF_FFFF_FFFF`: 비정규 주소 홀 (Canonical Hole)
- `0xFFFF_8000_0000_0000` ~ `0xFFFF_FFFF_FFFF_FFFF` (128TB): **커널 공간 (Kernel Space)**
  - Direct Mapping (페이지-프레임 매핑)
  - vmalloc / ioremap 영역
  - Module / Kernel Text 영역 (`CONFIG_RANDOMIZE_BASE`에 의해 난수화 적용)

### 2.2 ARM64 (48-bit VA 기준, TTBR0 vs TTBR1)
- `0x0000_0000_0000_0000` ~ `0x0000_FFFF_FFFF_FFFF`: **TTBR0_EL1** (유저 공간)
- `0xFFFF_0000_0000_0000` ~ `0xFFFF_FFFF_FFFF_FFFF`: **TTBR1_EL1** (커널 공간)
- 하드웨어 레벨에서 상위 주소 레지스터(TTBR1)와 하위 주소 레지스터(TTBR0)가 엄격히 분리되어 동작함.

---

## 3. 커널 하드닝의 다중 방어 계층 (Defense-in-Depth)

```mermaid
flowchart LR
    A["공격 벡터 유입"] --> B["1차: 진입 차단 (Seccomp, Landlock, AppArmor)"]
    B --> C["2차: 제어 흐름 보호 (Stack Canary, kCFI, IBT/BTI)"]
    C --> D["3차: 메모리 배치 교란 (KASLR, FG-KASLR, Randstruct)"]
    D --> E["4차: 실행 및 접근 권한 격리 (SMEP/SMAP, W^X Strict RWX)"]
    E --> F["5차: 결함 격리 및 패닉 (KFENCE, Page Table Check)"]
```
