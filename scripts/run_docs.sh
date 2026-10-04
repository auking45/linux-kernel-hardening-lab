#!/usr/bin/env bash
# ==============================================================================
# Linux Kernel Hardening Lab - Documentation Helper
# Serves or builds bilingual documentation with automated virtualenv & dependency handling
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
REQUIREMENTS="${REPO_ROOT}/requirements.txt"

# Default configuration
ACTION="serve"
HOST="127.0.0.1"
DEFAULT_PORT=8000
PORT="${DEFAULT_PORT}"
STRICT_MODE=false
CLEAN_VENV=false

# Terminal colors
CYAN=$'\033[0;36m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
NC=$'\033[0m' # No Color

log_info() {
    echo -e "${CYAN}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

show_help() {
    cat << EOF
${BOLD}Linux Kernel Hardening Lab - Documentation Helper${NC}

${BOLD}USAGE:${NC}
  $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
  -s, --serve          Start local documentation server with live reload (default)
  -b, --build          Build static documentation site to site/ directory
  -p, --port PORT      Port to bind server (default: 8000, auto-increments if busy)
  -H, --host HOST      Host address to bind server (default: 127.0.0.1)
      --strict         Treat warnings as errors during build
      --clean          Recreate Python virtualenv from scratch
  -h, --help           Show this help message

${BOLD}EXAMPLES:${NC}
  $0                                      # Serve locally at http://127.0.0.1:8000
  $0 --port 8080                          # Serve at port 8080
  $0 --build                              # Build production static site
  $0 --build --strict                     # Strict build test (CI/CD style)
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--serve)
                ACTION="serve"
                shift
                ;;
            -b|--build)
                ACTION="build"
                shift
                ;;
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -H|--host)
                HOST="$2"
                shift 2
                ;;
            --strict)
                STRICT_MODE=true
                shift
                ;;
            --clean)
                CLEAN_VENV=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

setup_virtualenv() {
    # Clean virtualenv if requested
    if [[ "${CLEAN_VENV}" == true ]] && [[ -d "${VENV_DIR}" ]]; then
        log_info "Cleaning existing virtual environment at ${VENV_DIR}..."
        rm -rf "${VENV_DIR}"
    fi

    # Create virtual environment if missing
    if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
        log_info "Creating Python virtual environment at ${VENV_DIR}..."
        python3 -m venv "${VENV_DIR}"
    fi

    # Activate virtual environment
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
}

install_dependencies() {
    log_info "Checking required MkDocs packages in virtual environment..."
    local need_install=false

    if ! python3 -c "import mkdocs, material, pymdownx" 2>/dev/null; then
        need_install=true
    fi

    if [[ "${need_install}" == true ]]; then
        log_info "Installing documentation dependencies from requirements.txt (Initial setup: ~30s)..."
        if ! pip install --timeout 30 -r "${REQUIREMENTS}"; then
            log_error "Failed to install required Python packages from requirements.txt."
            log_error "Please check your network connection or configure proxy/wheels."
            exit 1
        fi
        log_success "All dependencies successfully installed."
    fi
}

is_port_in_use() {
    local target_port="$1"
    if command -v ss >/dev/null 2>&1; then
        if ss -tuln | grep -q ":${target_port} "; then
            return 0
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln | grep -q ":${target_port} "; then
            return 0
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -i ":${target_port}" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

get_base_path() {
    local raw_url
    raw_url="$(grep -E '^[[:space:]]*site_url:' "${REPO_ROOT}/mkdocs.yml" | head -n1 | awk '{print $2}' | tr -d '"'\''')"
    local path
    path="$(echo "${raw_url}" | sed -E 's|^https?://[^/]+||')"
    if [[ -z "${path}" || "${path}" == "/" ]]; then
        echo "/"
    else
        [[ "${path}" != /* ]] && path="/${path}"
        [[ "${path}" != */ ]] && path="${path}/"
        echo "${path}"
    fi
}

serve_docs() {
    local original_port="${PORT}"
    while is_port_in_use "${PORT}"; do
        log_warn "Port ${PORT} is already in use."
        PORT=$((PORT + 1))
        if [[ $((PORT - original_port)) -gt 10 ]]; then
            log_error "Could not find an available port between ${original_port} and ${PORT}. Exiting."
            exit 1
        fi
    done

    if [[ "${PORT}" != "${original_port}" ]]; then
        log_info "Using alternative available port: ${PORT}"
    fi

    local base_path
    base_path="$(get_base_path)"

    echo ""
    echo -e "${BOLD}${BLUE}================================================================${NC}"
    echo -e "${BOLD} 🚀 Linux Kernel Hardening Lab - Documentation Server ${NC}"
    echo -e "${BOLD}${BLUE}================================================================${NC}"
    echo -e " 📖 ${BOLD}Local URL:${NC}       ${GREEN}${BOLD}http://${HOST}:${PORT}${base_path}${NC}"
    echo -e " 🌐 ${BOLD}Korean Docs:${NC}     ${GREEN}http://${HOST}:${PORT}${base_path}${NC} (Default / 기본 언어)"
    echo -e " 🌐 ${BOLD}English Docs:${NC}    ${GREEN}http://${HOST}:${PORT}${base_path}en/${NC}"
    echo -e " 🗺️  ${BOLD}Scenarios (KO):${NC} ${CYAN}http://${HOST}:${PORT}${base_path}scenarios/${NC}"
    echo -e " 🦾 ${BOLD}Scenario 01 (KO):${NC} ${CYAN}http://${HOST}:${PORT}${base_path}scenarios/01-humanoid-bof/${NC}"
    echo -e " 🦾 ${BOLD}Scenario 01 (EN):${NC} ${CYAN}http://${HOST}:${PORT}${base_path}en/scenarios/01-humanoid-bof/${NC}"
    echo -e " 🔄 ${BOLD}Live Reload:${NC}     Enabled (Changes will reflect automatically)"
    echo -e " 🛑 ${BOLD}Stop Server:${NC}     Press [Ctrl + C]"
    echo -e "${BOLD}${BLUE}================================================================${NC}"
    echo ""

    exec mkdocs serve --dev-addr "${HOST}:${PORT}"
}

build_docs() {
    log_info "Building static documentation site to site/..."
    local build_args=()
    if [[ "${STRICT_MODE}" == true ]]; then
        build_args+=("--strict")
        log_info "Strict mode enabled (warnings treated as errors)."
    fi

    mkdocs build "${build_args[@]}"
    log_success "Static site build completed! Output directory: ${REPO_ROOT}/site"
}

main() {
    parse_args "$@"
    cd "${REPO_ROOT}"

    setup_virtualenv
    install_dependencies

    if [[ "${ACTION}" == "serve" ]]; then
        serve_docs
    elif [[ "${ACTION}" == "build" ]]; then
        build_docs
    else
        log_error "Unknown action: ${ACTION}"
        exit 1
    fi
}

main "$@"
