# Quick Start Guide

Prerequisites, dependency setup, kernel source preparation, and QEMU virtual machine environment configuration for Linux Kernel Hardening Lab.

---

## 1. Prerequisites Installation

Install build toolchains, cross-compilers for x86_64/arm64, and QEMU emulators on Ubuntu 22.04 / 24.04 LTS:

```bash
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    flex \
    bison \
    libncurses-dev \
    libssl-dev \
    libelf-dev \
    bc \
    qemu-system-x86 \
    qemu-system-arm \
    gcc-x86-64-linux-gnu \
    gcc-aarch64-linux-gnu \
    busybox-static \
    cpio \
    python3-venv \
    git
```

---

## 2. Running Local Documentation

Set up a Python virtual environment and run the MkDocs development server:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
```

Navigate to `http://127.0.0.1:8000` to preview docs with dynamic language toggling.

---

## 3. Kernel Source & Rootfs Preparation

1. **Download LTS Kernel**:
   ```bash
   ./scripts/download_kernel.sh
   ```
2. **Build Lightweight BusyBox Rootfs (x86_64 / arm64)**:
   ```bash
   ./scripts/build_rootfs.sh --arch x86_64
   ./scripts/build_rootfs.sh --arch arm64
   ```
3. **Build Base Kernel & Boot in QEMU**:
   ```bash
   ./scripts/build_kernel.sh --arch x86_64 --feature base
   ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64/arch/x86/boot/bzImage
   ```
