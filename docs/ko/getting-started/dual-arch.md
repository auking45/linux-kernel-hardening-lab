# 듀얼 아키텍처 환경 구성 (Dual-Arch Environment)

x86_64 및 arm64(aarch64) 아키텍처 간 커널 실행 환경 및 QEMU 에뮬레이션 구성 비교 분석.

---

## 1. 아키텍처별 가상머신 구동 모델 비교

| 항목                        | x86_64                            | ARM64 (aarch64)                                |
| :-------------------------- | :-------------------------------- | :--------------------------------------------- |
| **QEMU 바이너리**           | `qemu-system-x86_64`              | `qemu-system-aarch64`                          |
| **머신 타입**               | `q35` 또는 `pc`                   | `virt` (Standard Virtual Machine)              |
| **CPU 모델**                | `host` (KVM 가속 시) 또는 `max`   | `host` (KVM 가속 시) 또는 `cortex-a72` / `max` |
| **부팅 펌웨어**             | Direct Kernel Boot 또는 SeaBIOS   | Direct Kernel Boot (`-kernel`)                 |
| **콘솔 인터페이스**         | `ttyS0` (Serial 16550A)           | `ttyAMA0` (PL011 UART)                         |
| **커널 바이너리 타깃**      | `arch/x86/boot/bzImage`           | `arch/arm64/boot/Image`                        |
| **주요 하드웨어 보안 기능** | Intel CET (IBT/SHSTK), SMEP, SMAP | ARMv8.3 PAC, ARMv8.5 BTI, PAN, PXN             |

---

## 2. QEMU 실행 파라미터 구조

### 2.1 x86_64 에뮬레이션 명령 규격

```bash
qemu-system-x86_64 \
    -m 1024M \
    -smp 2 \
    -kernel build_dir/x86_64/arch/x86/boot/bzImage \
    -initrd rootfs/initramfs-x86_64.cpio.gz \
    -append "console=ttyS0 quiet panic=1 nokaslr" \
    -nographic \
    -no-reboot
```

### 2.2 ARM64 에뮬레이션 명령 규격

```bash
qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a72 \
    -m 1024M \
    -smp 2 \
    -kernel build_dir/arm64/arch/arm64/boot/Image \
    -initrd rootfs/initramfs-arm64.cpio.gz \
    -append "console=ttyAMA0 quiet panic=1 nokaslr" \
    -nographic \
    -no-reboot
```

---

## 3. 크로스 컴파일러 설정 및 검증

x86_64 호스트에서 aarch64 바이너리를 빌드하기 위한 환경 변수 정의:

```bash
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
```

툴체인 정상 동작 확인:

```bash
${CROSS_COMPILE}gcc --version
```
