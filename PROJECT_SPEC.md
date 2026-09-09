# [Project Specification] Linux Kernel Hardening Engineering Lab

## 1. Project Overview & Objectives

- **Goal:** 리눅스 커널 보안 하드닝(Hardening) 기능의 원리를 체계적으로 해설하고, 각 기능을 실제 커널(x86_64 및 arm64)에 적용/빌드한 뒤 QEMU에서 직접 실행·검증할 수 있는 **인터랙티브 기술 문서 사이트(GitHub Pages)** 및 **실습 랩 환경** 구축.
- **Key Principles:**
  - **듀얼 아키텍처 지원:** 모든 하드닝 기능은 x86_64 및 arm64(aarch64) 아키텍처를 동시 지원함.
  - **이원화된 고품질 시각화:** 복잡한 시스템 아키텍처 및 상태 전이는 **Archify(`tt-a1i/archify`)** 인터랙티브 HTML 다이어그램으로, 프로세스 및 공격/방어 흐름은 **Mermaid**로 직관적 시각화 제공.
  - **명사 종결형 문체 표준:** 문서 내 "~합니다"체를 전면 배제하고 간결한 개조식 명사 종결형("~함", "~임", "~제공", "~수행", 명사구) 준수.
  - **다국어(한/영) 1:1 동기화:** `mkdocs-static-i18n` 기반 한국어(`ko`, 기본) 및 영어(`en`) 문서 트리 1:1 완벽 대칭 유지.
  - **원자적(Atomic) 점진적 빌드업:** 1개 커밋에 1개의 하드닝 피처 또는 인프라 단위만 작업하며, 모든 커밋은 깨지지 않은 상태(Functional)를 유지함.

---

## 2. Strict Rules for AI Agent (Antigravity)

1. **Step-by-Step Atomic Execution with User Approval:**
   - 한 번에 여러 태스크나 여러 피처를 임의로 대량 작성하지 않고, **지정된 1개의 Task/피처만 수행**한 뒤 사용자에게 검증 및 완료 보고를 수행함.
   - 사용자가 커밋 내역과 결과를 확인하고 다음 단계 진행을 승인하기 전까지 후속 Task를 시작하지 않음.

2. **English Commit Messages Only (Conventional Commits):**
   - 모든 Git 커밋 메시지는 **반드시 영어로 작성**함.
   - `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:` 접두사를 준수하며, 명확하고 간결한 변경 요약을 포함함.
   - 예시: `feat(stack-protector): add CONFIG_STACKPROTECTOR_STRONG lab and docs`

3. **Strict Nominal Ending Style (명사 종결형 문체 엄수):**
   - 한국어 기술 문서는 구어체나 존댓말("~합니다", "~습니다") 및 서술형 평서체("~다")를 지양하고, **명사 또는 명사형 어미("~함", "~임", "~제공", "~수행", "~분석")**로 종결함.

4. **Every Commit Must Be Functional:**
   - 매 커밋마다 MkDocs 빌드(`mkdocs build --strict`) 에러가 없어야 함.
   - 추가된 셸 스크립트는 구문 에러 없이 정상 파싱되어야 함(`bash -n`).

5. **Visual-First (다이어그램 의무 배치):**
   - 모든 피처 문서 개요에는 개념을 즉시 파악할 수 있는 **Archify 시스템 맵** 또는 **Mermaid 다이어그램**을 반드시 상단에 배치함.

6. **Roadmap Checklist Synchronization:**
   - Task가 완료되고 사용자의 승인을 받으면, 본 문서(`PROJECT_SPEC.md`)의 해당 Task 체크박스를 `[x]`로 업데이트함.

---

## 3. Kernel Hardening Feature Taxonomy & Master Roadmap

### [Phase 0] Master Specification & Standards

- [x] **Task 0-1:** 프로젝트 마스터 스펙(`PROJECT_SPEC.md`), 작성 표준(`SKILL.md`), `.gitignore`, 초기 `README.md` 작성.

### [Phase 1] MkDocs Multilingual Infrastructure & GitHub Pages CI/CD

- [x] **Task 1-1:** MkDocs 다국어 설정(`mkdocs.yml`, `requirements.txt`, `mkdocs-static-i18n`, Mermaid/MathJax 테마).
- [x] **Task 1-2:** GitHub Actions Pages 자동 배포 워크플로우(`.github/workflows/docs.yml`) 작성.
- [x] **Task 1-3:** 초기 문서 골격(`docs/ko/index.md`, `docs/en/index.md`, 가이드 페이지) 구축 및 빌드 검증.

### [Phase 2] Kernel Build & Dual-Arch QEMU Runner Framework

- [x] **Task 2-1:** 커널 소스 자동 다운로드 및 캐싱 스크립트(`scripts/download_kernel.sh`).
- [x] **Task 2-2:** BusyBox 기반 초경량 initramfs 빌더(`scripts/build_rootfs.sh` - x86_64 & arm64).
- [x] **Task 2-3:** Kconfig fragment 병합 커널 빌더(`scripts/build_kernel.sh`).
- [x] **Task 2-4:** x86_64 / arm64 QEMU 자동 런처 스크립트(`scripts/run_qemu.sh`).
- [x] **Task 2-5:** 기본 최소 defconfig 템플릿(`configs/base/x86_64_defconfig`, `configs/base/arm64_defconfig`).
- [x] **Task 2-6:** 원클릭 E2E 오케스트레이터 스크립트(`scripts/run_lab.sh`) 및 단축 실행 `Makefile` 작성.
- [x] **Task 2-7:** 재현 가능한 Docker 컨테이너 환경(`docker/Dockerfile.lab`, `compose.yaml`) 및 GitHub Actions CI(`.github/workflows/test.yml`) 파이프라인 구축.

---

### [Phase 3] Category 1: Stack & Buffer Overflow Protection

- [ ] **Task 3-1:** `CONFIG_STACKPROTECTOR_STRONG` (Stack Canary 메커니즘 및 스택 변조 탐지 실습).
- [ ] **Task 3-2:** `CONFIG_FORTIFY_SOURCE` (컴파일/런타임 버퍼 경계 검사 메커니즘).
- [ ] **Task 3-3:** `CONFIG_SHADOW_CALL_STACK` (ARM64 리턴 주소 보호용 그림자 호출 스택).
- [ ] **Task 3-4:** `CONFIG_GCC_PLUGIN_STACKLEAK` (커널 스택 데이터 소거 및 스택 고갈 공격 방어).

### [Phase 4] Category 2: Memory Layout & Address Space Randomization

- [ ] **Task 4-1:** KASLR (Kernel Address Space Layout Randomization) & `nokaslr` 부팅 파라미터 비교.
- [ ] **Task 4-2:** FG-KASLR (Function Granular KASLR - 함수 단위 배치 무작위화).
- [ ] **Task 4-3:** `CONFIG_RANDOMIZE_MEMORY` (물리 메모리 다이렉트 매핑 주소 랜덤화).

### [Phase 5] Category 3: Memory Permissions & Access Separation

- [ ] **Task 5-1:** `CONFIG_STRICT_KERNEL_RWX` & `CONFIG_STRICT_MODULE_RWX` (W^X 메모리 불변 정책).
- [ ] **Task 5-2:** SMEP (x86) / PXN (ARM64) (유저스페이스 코드 커널 모드 실행 차단).
- [ ] **Task 5-3:** SMAP (x86) / PAN (ARM64) (커널의 무분별한 유저스페이스 메모리 직접 접근 차단).
- [ ] **Task 5-4:** `CONFIG_PAGE_TABLE_CHECK` (페이지 테이블 오염 및 불법 페이지 매핑 런타임 탐지).
- [ ] **Task 5-5:** KPTI (Kernel Page Table Isolation - 유저/커널 페이지 테이블 완전 분리 및 Meltdown 방어).

### [Phase 6] Category 4: Control Flow Integrity (CFI)

- [ ] **Task 6-1:** Clang kCFI (컴파일 타임 순방향 간접 함수 호출 무결성 검증).
- [ ] **Task 6-2:** x86 IBT & Shadow Stack (Intel CET 기반 하드웨어 지원 간접 분기 추적 및 섀도 스택).
- [ ] **Task 6-3:** ARM64 BTI & PAC (Branch Target Identification 및 Pointer Authentication Code).

### [Phase 7] Category 5: Heap & Slab Allocator Hardening

- [ ] **Task 7-1:** `CONFIG_SLAB_FREELIST_RANDOM` & `CONFIG_SLAB_FREELIST_HARDENED` (프리리스트 무작위화 및 메타데이터 포인터 난독화).
- [ ] **Task 7-2:** `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` & `CONFIG_INIT_ON_FREE_DEFAULT_ON` (할당/해제 시 자동 0 초기화로 UAF 완화).
- [ ] **Task 7-3:** `CONFIG_HARDENED_USERCOPY` (유저 공간 복사 시 슬랩 버퍼 경계 엄격 검증).
- [ ] **Task 7-4:** KFENCE (Kernel Electric Fence - 낮은 오버헤드의 프로덕션 힙 결함 샘플링 탐지).

### [Phase 8] Category 6: Structure & Compiler Level Protections

- [ ] **Task 8-1:** `CONFIG_GCC_PLUGIN_STRUCTLEAK` (초기화되지 않은 커널 구조체 정보 누출 방어).
- [ ] **Task 8-2:** `CONFIG_GCC_PLUGIN_RANDSTRUCT` (커널 핵심 구조체 멤버 오프셋 랜덤화).

### [Phase 9] Category 7: Speculative Execution Defenses

- [ ] **Task 9-1:** Spectre v1 (`array_index_nospec`) 방어 메커니즘.
- [ ] **Task 9-2:** Spectre v2 (Retpoline, IBPB, STIBP) 간접 분기 예측 방어.
- [ ] **Task 9-3:** Speculative Store Bypass Disable (SSBD - Spectre v4).
- [ ] **Task 9-4:** MDS (Microarchitectural Data Sampling) & TAA 완화.

### [Phase 10] Category 8: Mandatory Access Control & LSM Framework

- [ ] **Task 10-1:** Stackable LSM 아키텍처 및 복수 LSM 활성화 (`lsm=...` 부팅 파라미터).
- [ ] **Task 10-2:** AppArmor (프로필 기반 프로세스 격리 및 파일/네트워크 경로 통제 실습).
- [ ] **Task 10-3:** SELinux (Type Enforcement, 도메인 전이 및 MLS 보안 컨텍스트 실습).
- [ ] **Task 10-4:** Landlock (비특권 유저스페이스 프로세스 자체 샌드박싱 실습).

### [Phase 11] Category 9: System & Binary Integrity Verification

- [ ] **Task 11-1:** IMA (Integrity Measurement Architecture - 실행 파일 해시 측정 및 무결성 검증 실습).
- [ ] **Task 11-2:** EVM (Extended Verification Module - 파일 xattr 전자서명 및 무결성 보호).
- [ ] **Task 11-3:** IPE (Integrity Policy Enforcement - dm-verity/fs-verity 기반 신규 정책 강제 LSM).
- [ ] **Task 11-4:** Kernel Lockdown LSM (`integrity` vs `confidentiality` 모드 비교 및 실습).
- [ ] **Task 11-5:** Module Signature Verification (`CONFIG_MODULE_SIG_FORCE` 및 신뢰 키링 실습).

### [Phase 12] Category 10: Attack Surface Reduction & System Hardening

- [ ] **Task 12-1:** Seccomp-BPF (시스템 콜 공격 표면 차단 및 샌드박싱 실습).
- [ ] **Task 12-2:** BPF Hardening (`CONFIG_BPF_JIT_ALWAYS_ON`, `unprivileged_bpf_disabled`).
- [ ] **Task 12-3:** Strict Devmem (`CONFIG_STRICT_DEVMEM`, `CONFIG_IO_STRICT_DEVMEM`).
- [ ] **Task 12-4:** Kernel Information Leaks 방어 (`CONFIG_SECURITY_DMESG_RESTRICT`, `kptr_restrict`).
- [ ] **Task 12-5:** Ptrace Restrictions (`CONFIG_SECURITY_YAMA`).
- [ ] **Task 12-6:** Kexec Restrictions (`kexec_load_disabled`).
