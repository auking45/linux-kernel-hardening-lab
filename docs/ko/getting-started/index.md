# 빠른 시작 가이드 (Quick Start Guide)

리눅스 커널 하드닝 랩 실습을 위한 호스트 패키지 의존성 설치, 커널 소스 코드 준비 및 QEMU 가상머신 환경 구성 절차 안내.

---

## 1. 사전 요구 패키지 설치

호스트 환경(Ubuntu 22.04 / 24.04 LTS 기준)에서 x86_64 및 arm64 교차 빌드 툴체인 및 QEMU 에뮬레이터 설치 수행:

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

## 2. 문서 뷰어 로컬 실행

Python 가상환경 생성 및 MkDocs 의존성 패키지 설치:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
```

웹 브라우저로 `http://127.0.0.1:8000` 접속 후 상단 언어 선택기를 통해 한국어 및 영어 실시간 전환 확인 가능함.

---

## 3. 커널 소스 및 루트 파일시스템 준비

1. **LTS 커널 다운로드**:
   ```bash
   ./scripts/download_kernel.sh
   ```
2. **초경량 BusyBox Rootfs 생성 (x86_64 / arm64)**:
   ```bash
   ./scripts/build_rootfs.sh --arch x86_64
   ./scripts/build_rootfs.sh --arch arm64
   ```
3. **베이스 커널 빌드 및 QEMU 부팅 테스트**:
   ```bash
   ./scripts/build_kernel.sh --arch x86_64 --feature base
   ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64/arch/x86/boot/bzImage
   ```
