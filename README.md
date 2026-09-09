# Linux Kernel Hardening Lab (리눅스 커널 하드닝 랩)

[![Docs](https://img.shields.io/badge/docs-MkDocs%20Material-blue.svg)](https://auking45.github.io/linux-kernel-hardening-lab/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Arch](https://img.shields.io/badge/arch-x86__64%20%7C%20arm64-orange.svg)]()

> 리눅스 커널 보안 하드닝(Hardening) 기능들의 심층 동작 원리를 분석하고, 실제 커널 빌드 및 QEMU(x86_64 / arm64) 가상머신 환경에서 각 보안 기능을 실습·검증하는 오픈소스 엔지니어링 가이드.

---

## 1. 프로젝트 목적 및 핵심 특징

- **이론과 실습의 1:1 결합**: 단순 이론 나열이 아닌, 각 하드닝 피처별 커널 Kconfig 설정, 공격 PoC/LKDTM 트리거, QEMU 실행 결과 로그를 함께 제공함.
- **x86_64 & arm64 듀얼 아키텍처 지원**: 인텔/AMD 서버 환경과 ARM 모바일/임베디드/클라우드 환경의 하드닝 메커니즘 차이를 직접 비교 검증함.
- **고품질 인터랙티브 시각화**: **Archify(`tt-a1i/archify`)** 기반 인터랙티브 아키텍처 다이어그램 및 Mermaid 프로세스 흐름도 탑재.
- **다국어 기술 문서 지원**: 한국어(기본, 명사 종결형 표준) 및 영어 문서 1:1 완벽 제공.
- **원클릭 재현 환경**: 커널 소스 다운로드부터 BusyBox initramfs 빌드, 피처별 Kconfig 머지, QEMU 구동까지 스크립트로 자동화 지원.

---

## 2. 하드닝 피처 로드맵 (10개 핵심 카테고리)

상세 구현 항목 및 체크리스트는 [`PROJECT_SPEC.md`](PROJECT_SPEC.md) 참조.

1. **Stack & Buffer Protection**: Stack Canary (`CONFIG_STACKPROTECTOR_STRONG`), FORTIFY_SOURCE, Shadow Call Stack, Stackleak.
2. **Memory Layout & Randomization**: KASLR, FG-KASLR, Randomize Memory.
3. **Memory Permissions & Access Separation**: Strict Kernel/Module RWX, SMEP/PXN, SMAP/PAN, Page Table Check, KPTI (Meltdown).
4. **Control Flow Integrity (CFI)**: Clang kCFI, x86 IBT & SHSTK (Intel CET), ARM64 BTI & PAC.
5. **Heap & Slab Allocator Hardening**: SLAB Freelist Random/Hardened, Init on Alloc/Free, Hardened Usercopy, KFENCE.
6. **Structure & Compiler Defenses**: Structleak, Randstruct GCC Plugins.
7. **Speculative Execution Defenses**: Retpoline, IBPB/STIBP (Spectre v2), SSBD (Spectre v4), MDS/TAA.
8. **Mandatory Access Control & LSM**: AppArmor, SELinux, Landlock, Stackable LSM.
9. **System & Binary Integrity Verification**: IMA (Integrity Measurement Architecture), EVM (Extended Verification Module), IPE (Integrity Policy Enforcement), Lockdown LSM, Module Signature Verification.
10. **Attack Surface Reduction & System Hardening**: Seccomp-BPF, BPF JIT Hardening, Strict Devmem, Yama Ptrace, Dmesg Restrict.

---

## 3. 빠른 시작 (Quick Start)

### 3.1 문서 로컬 뷰어 실행

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
# http://127.0.0.1:8000 접속 (한/영 토글 가능)
```

### 3.2 커널 빌드 및 QEMU 실행 환경 준비

```bash
# 1. 커널 소스 자동 다운로드
./scripts/download_kernel.sh

# 2. x86_64 및 arm64 초경량 BusyBox rootfs 빌드
./scripts/build_rootfs.sh --arch x86_64
./scripts/build_rootfs.sh --arch arm64

# 3. 특정 피처 적용 커널 빌드 및 QEMU 실행
./scripts/build_kernel.sh --arch x86_64 --feature stack-protector
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64/arch/x86/boot/bzImage
```

---

## 4. 문서 및 기여 표준

- 문서 작성 표준 및 문체 규칙: [`SKILL.md`](SKILL.md)
- 프로젝트 명세 및 진행 상황: [`PROJECT_SPEC.md`](PROJECT_SPEC.md)
- 라이선스: MIT License ([`LICENSE`](LICENSE))
