# Linux Kernel Hardening Lab - Makefile

.PHONY: all run run-arm64 build build-arm64 docs docs-build clean help

help:
	@echo "Linux Kernel Hardening Lab"
	@echo ""
	@echo "Quick Start Targets:"
	@echo "  make run             - One-click build & boot x86_64 baseline kernel in QEMU"
	@echo "  make run-arm64       - One-click build & boot ARM64 baseline kernel in QEMU"
	@echo "  make build           - Build x86_64 baseline kernel without launching QEMU"
	@echo "  make build-arm64     - Build ARM64 baseline kernel without launching QEMU"
	@echo "  make docs            - Serve bilingual documentation locally (http://localhost:8000)"
	@echo "  make docs-build      - Build strict static documentation site"
	@echo "  make clean           - Clean build artifacts (keeps downloads/)"
	@echo ""
	@echo "Docker Isolated Targets:"
	@echo "  make docker-build    - Build isolated Docker container image"
	@echo "  make docker-run      - Run one-click kernel build & QEMU inside Docker"
	@echo "  make docker-shell    - Enter interactive Docker shell"
	@echo ""
	@echo "Advanced Feature Runs (via scripts/run_lab.sh):"
	@echo "  ./scripts/run_lab.sh --feature stack-protector"
	@echo "  ./scripts/run_lab.sh --arch arm64 --feature stack-protector"

run:
	@./scripts/run_lab.sh --arch x86_64 --feature base

run-arm64:
	@./scripts/run_lab.sh --arch arm64 --feature base

build:
	@./scripts/run_lab.sh --arch x86_64 --feature base --build-only

build-arm64:
	@./scripts/run_lab.sh --arch arm64 --feature base --build-only

docs:
	@python3 -m venv .venv 2>/dev/null || true
	@.venv/bin/pip install -q -r requirements.txt
	@.venv/bin/mkdocs serve

docs-build:
	@python3 -m venv .venv 2>/dev/null || true
	@.venv/bin/pip install -q -r requirements.txt
	@.venv/bin/mkdocs build --strict

docker-pull:
	@docker compose pull lab

docker-build:
	@docker compose build lab

docker-run:
	@docker compose run --rm lab ./scripts/run_lab.sh --arch x86_64

docker-shell:
	@docker compose run --rm -it lab /bin/bash

clean:
	@echo "Cleaning build outputs and rootfs..."
	@rm -rf build_dir rootfs site .cache
	@echo "Done."

