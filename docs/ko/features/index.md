# 하드닝 피처 로드맵 카탈로그 (Hardening Features Taxonomy)

리눅스 커널 보안 하드닝 피처 10개 핵심 카테고리 및 단계별 실습 아티클 매핑 테이블.

---

## 1. 하드닝 카테고리별 아티클 구성

```mermaid
mindmap
  root((Linux Kernel Hardening))
    Stack and Buffer
      Stack Canary
      FORTIFY_SOURCE
      Shadow Call Stack
      Stackleak
    Memory Layout
      KASLR
      FG-KASLR
      Randomize Memory
    Permissions
      Strict RWX
      SMEP and PXN
      SMAP and PAN
      KPTI
    CFI
      Clang kCFI
      Intel CET
      ARM PAC and BTI
    Heap and SLAB
      Freelist Random
      Freelist Hardened
      Init on Alloc
      KFENCE
    Compilers
      Structleak
      Randstruct
    Speculative
      Retpoline
      IBPB and STIBP
      SSBD
    MAC and LSM
      AppArmor
      SELinux
      Landlock
    Integrity
      IMA
      EVM
      IPE
      Lockdown
    Attack Surface
      Seccomp
      BPF Hardening
      Strict Devmem
```

---

## 2. 세부 피처별 실습 상태

| 번호 | 피처 명칭 | Kconfig 심볼 | 지원 아키텍처 | 실습 상태 |
| :--- | :--- | :--- | :--- | :--- |
| **01** | [Stack Protector (Canary)](01-stack-protector.md) | `CONFIG_STACKPROTECTOR_STRONG` | x86_64, arm64 | 실습 준비 완료 |
| **02** | Fortify Source | `CONFIG_FORTIFY_SOURCE` | x86_64, arm64 | 예정 |
| **03** | Shadow Call Stack | `CONFIG_SHADOW_CALL_STACK` | arm64 | 예정 |
| **04** | Stackleak Plugin | `CONFIG_GCC_PLUGIN_STACKLEAK` | x86_64, arm64 | 예정 |
| **05** | KASLR | `CONFIG_RANDOMIZE_BASE` | x86_64, arm64 | 예정 |
| **06** | Strict Kernel RWX | `CONFIG_STRICT_KERNEL_RWX` | x86_64, arm64 | 예정 |
| **07** | SMEP & SMAP / PAN & PXN | CPU Feature | x86_64, arm64 | 예정 |
| **08** | Kernel CFI | `CONFIG_CFI_CLANG` | x86_64, arm64 | 예정 |
| **09** | SLAB Freelist Hardening | `CONFIG_SLAB_FREELIST_HARDENED` | x86_64, arm64 | 예정 |
| **10** | KFENCE | `CONFIG_KFENCE` | x86_64, arm64 | 예정 |
| **11** | AppArmor LSM | `CONFIG_SECURITY_APPARMOR` | x86_64, arm64 | 예정 |
| **12** | IMA / EVM | `CONFIG_IMA`, `CONFIG_EVM` | x86_64, arm64 | 예정 |
| **13** | IPE LSM | `CONFIG_SECURITY_IPE` | x86_64, arm64 | 예정 |
| **14** | Kernel Lockdown | `CONFIG_SECURITY_LOCKDOWN_LSM` | x86_64, arm64 | 예정 |
| **15** | Seccomp-BPF | `CONFIG_SECCOMP_FILTER` | x86_64, arm64 | 예정 |
