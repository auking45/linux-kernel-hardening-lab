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

## 3. One-Click Kernel Build & QEMU Boot

Full automated pipeline from source download and rootfs generation to compilation and QEMU execution in a single command:

```bash
# [Option A] Via Makefile (Recommended)
make run            # One-click x86_64 baseline build & boot
make run-arm64      # One-click ARM64 baseline build & boot

# [Option B] Direct run_lab.sh orchestrator
./scripts/run_lab.sh                                    # x86_64 execution
./scripts/run_lab.sh --arch arm64                       # ARM64 execution
./scripts/run_lab.sh --feature stack-protector          # Hardened kernel build & run
```
