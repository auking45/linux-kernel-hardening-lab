# Dual-Architecture Environment Configuration

Comparison of kernel execution environments and QEMU emulation parameters between x86_64 and arm64 (aarch64).

---

## 1. Virtual Machine Emulation Model Comparison

| Parameter                 | x86_64                            | ARM64 (aarch64)                           |
| :------------------------ | :-------------------------------- | :---------------------------------------- |
| **QEMU Binary**           | `qemu-system-x86_64`              | `qemu-system-aarch64`                     |
| **Machine Type**          | `q35` or `pc`                     | `virt` (Standard Virtual Machine)         |
| **CPU Model**             | `host` (with KVM) or `max`        | `host` (with KVM) or `cortex-a72` / `max` |
| **Boot Firmware**         | Direct Kernel Boot or SeaBIOS     | Direct Kernel Boot (`-kernel`)            |
| **Console Interface**     | `ttyS0` (Serial 16550A)           | `ttyAMA0` (PL011 UART)                    |
| **Kernel Target**         | `arch/x86/boot/bzImage`           | `arch/arm64/boot/Image`                   |
| **Key Hardware Security** | Intel CET (IBT/SHSTK), SMEP, SMAP | ARMv8.3 PAC, ARMv8.5 BTI, PAN, PXN        |

---

## 2. QEMU Command Line Structures

### 2.1 x86_64 Emulation

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

### 2.2 ARM64 Emulation

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

## 3. Cross-Compiler Setup

Environment variables for cross-compiling ARM64 on x86_64 host:

```bash
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
```

Verification command:

```bash
${CROSS_COMPILE}gcc --version
```
