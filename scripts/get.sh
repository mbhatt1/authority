#!/bin/sh
# ============================================================================
# Authority Nanos Installer Script
#
# This script downloads and installs Authority Nanos on your system.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh
#
# Options:
#   --help              Show help message
#   --version X.Y.Z     Install specific version (default: latest)
#   --prefix /path      Install to custom directory (default: /usr/local)
#   --no-python         Skip Python SDK installation
#   --no-verify         Skip installation verification
#   --uninstall         Uninstall Authority Nanos
#
# Environment Variables:
#   AUTHORITY_VERSION   Version to install (overridden by --version)
#   AUTHORITY_PREFIX    Installation prefix (overridden by --prefix)
#   AUTHORITY_NO_PYTHON Set to 1 to skip Python SDK
#
# ============================================================================
# POSIX-compliant shell script - works with sh, bash, zsh, dash
# ============================================================================

set -e

# ============================================================================
# Configuration
# ============================================================================

GITHUB_REPO="mbhatt1/authority"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_RELEASES="https://github.com/${GITHUB_REPO}/releases"
PYPI_PACKAGE="authority-nanos"

# Default values
DEFAULT_PREFIX="/usr/local"
DEFAULT_VERSION="latest"

# Script state
VERSION="${AUTHORITY_VERSION:-$DEFAULT_VERSION}"
PREFIX="${AUTHORITY_PREFIX:-$DEFAULT_PREFIX}"
INSTALL_PYTHON=1
VERIFY_INSTALL=1
UNINSTALL=0
VERBOSE=0

# Colors (only if terminal supports them)
if [ -t 1 ] && [ -n "$TERM" ] && [ "$TERM" != "dumb" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

# ============================================================================
# Helper Functions
# ============================================================================

print_banner() {
    printf "\n"
    printf "%b============================================================%b\n" "$CYAN" "$NC"
    printf "%b     Authority Nanos Installer%b\n" "$BOLD" "$NC"
    printf "%b============================================================%b\n" "$CYAN" "$NC"
    printf "\n"
}

# All logs go to stderr so that functions which "return" a value via stdout
# (e.g. get_latest_version) are not contaminated by log lines when captured in
# a command substitution like VERSION=$(get_latest_version).
log_info() {
    printf "%b[INFO]%b %s\n" "$BLUE" "$NC" "$1" >&2
}

log_success() {
    printf "%b[OK]%b %s\n" "$GREEN" "$NC" "$1" >&2
}

log_warn() {
    printf "%b[WARN]%b %s\n" "$YELLOW" "$NC" "$1" >&2
}

log_error() {
    printf "%b[ERROR]%b %s\n" "$RED" "$NC" "$1" >&2
}

log_verbose() {
    if [ "$VERBOSE" = "1" ]; then
        printf "%b[DEBUG]%b %s\n" "$CYAN" "$NC" "$1" >&2
    fi
}

die() {
    log_error "$1"
    exit 1
}

# ============================================================================
# Platform Detection
# ============================================================================

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        freebsd)
            OS="freebsd"
            ;;
        *)
            die "Unsupported operating system: $OS"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armhf)
            ARCH="arm"
            ;;
        *)
            die "Unsupported architecture: $ARCH"
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    log_verbose "Detected platform: $PLATFORM"
}

# ============================================================================
# Dependency Checks
# ============================================================================

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_dependencies() {
    log_info "Checking dependencies..."

    # Required: curl or wget
    if check_command curl; then
        DOWNLOADER="curl"
        DOWNLOAD_CMD="curl -fsSL"
        DOWNLOAD_OUTPUT="-o"
    elif check_command wget; then
        DOWNLOADER="wget"
        DOWNLOAD_CMD="wget -q"
        DOWNLOAD_OUTPUT="-O"
    else
        die "curl or wget is required but not found. Please install one of them."
    fi
    log_verbose "Using downloader: $DOWNLOADER"

    # Required: tar
    if ! check_command tar; then
        die "tar is required but not found. Please install it."
    fi

    # Optional: Python/pip for SDK
    if [ "$INSTALL_PYTHON" = "1" ]; then
        if check_command python3; then
            PYTHON_CMD="python3"
        elif check_command python; then
            PYTHON_CMD="python"
        else
            log_warn "Python not found. Skipping Python SDK installation."
            INSTALL_PYTHON=0
        fi

        if [ "$INSTALL_PYTHON" = "1" ]; then
            if check_command pip3; then
                PIP_CMD="pip3"
            elif check_command pip; then
                PIP_CMD="pip"
            elif [ -n "$PYTHON_CMD" ]; then
                # Try python -m pip
                if $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
                    PIP_CMD="$PYTHON_CMD -m pip"
                else
                    log_warn "pip not found. Skipping Python SDK installation."
                    INSTALL_PYTHON=0
                fi
            fi
        fi
    fi

    log_success "Dependencies check passed"
}

# ============================================================================
# Version Management
# ============================================================================

get_latest_version() {
    log_info "Fetching latest version..."

    # Try GitHub API first
    if [ "$DOWNLOADER" = "curl" ]; then
        LATEST_VERSION=$(curl -fsSL "${GITHUB_API}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' | sed 's/^v//')
    else
        LATEST_VERSION=$(wget -qO- "${GITHUB_API}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' | sed 's/^v//')
    fi

    if [ -z "$LATEST_VERSION" ]; then
        # Fallback: try to scrape releases page
        log_warn "Could not fetch from GitHub API, trying alternative method..."
        if [ "$DOWNLOADER" = "curl" ]; then
            LATEST_VERSION=$(curl -fsSL "${GITHUB_RELEASES}" 2>/dev/null | \
                grep -oE 'releases/tag/v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | \
                sed -E 's/releases\/tag\/v?//')
        else
            LATEST_VERSION=$(wget -qO- "${GITHUB_RELEASES}" 2>/dev/null | \
                grep -oE 'releases/tag/v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | \
                sed -E 's/releases\/tag\/v?//')
        fi
    fi

    if [ -z "$LATEST_VERSION" ]; then
        # Final fallback: use a known version
        log_warn "Could not determine latest version. Using default: 0.1.46"
        LATEST_VERSION="0.1.46"
    fi

    log_verbose "Latest version: $LATEST_VERSION"
    printf "%s" "$LATEST_VERSION"
}

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(get_latest_version)
    fi

    # Normalize version (remove 'v' prefix if present)
    VERSION=$(printf "%s" "$VERSION" | sed 's/^v//')

    log_info "Installing version: $VERSION"
}

# ============================================================================
# Download Functions
# ============================================================================

download_file() {
    URL="$1"
    OUTPUT="$2"

    log_verbose "Downloading: $URL"

    if [ "$DOWNLOADER" = "curl" ]; then
        curl -fsSL "$URL" -o "$OUTPUT" || return 1
    else
        wget -q "$URL" -O "$OUTPUT" || return 1
    fi
}

get_download_url() {
    # Construct the release artifact URL. Asset names are produced by
    # .github/workflows/release.yml and have the form:
    #   authority-nanos-{version}-{os}-{arch}.tar.gz
    # where {os} is linux|darwin and {arch} is x86_64|arm64. Note the release
    # uses x86_64 (not the amd64 that detect_platform normalises to).
    case "$PLATFORM" in
        linux-amd64)
            TARBALL="authority-nanos-${VERSION}-linux-x86_64.tar.gz"
            ;;
        linux-arm64)
            TARBALL="authority-nanos-${VERSION}-linux-arm64.tar.gz"
            ;;
        darwin-amd64)
            TARBALL="authority-nanos-${VERSION}-darwin-x86_64.tar.gz"
            ;;
        darwin-arm64)
            TARBALL="authority-nanos-${VERSION}-darwin-arm64.tar.gz"
            ;;
        *)
            die "No pre-built binary available for platform: $PLATFORM"
            ;;
    esac

    DOWNLOAD_URL="${GITHUB_RELEASES}/download/v${VERSION}/${TARBALL}"

    # Also try without 'v' prefix
    DOWNLOAD_URL_ALT="${GITHUB_RELEASES}/download/${VERSION}/${TARBALL}"

    log_verbose "Download URL: $DOWNLOAD_URL"
}

# ============================================================================
# Installation Functions
# ============================================================================

create_directories() {
    log_info "Creating installation directories..."

    # Create directories with appropriate permissions
    INSTALL_BIN="${PREFIX}/bin"
    INSTALL_LIB="${PREFIX}/lib/authority"
    INSTALL_SHARE="${PREFIX}/share/authority"

    for DIR in "$INSTALL_BIN" "$INSTALL_LIB" "$INSTALL_SHARE"; do
        if [ ! -d "$DIR" ]; then
            if [ -w "$(dirname "$DIR")" ]; then
                mkdir -p "$DIR"
            else
                log_warn "Need elevated permissions to create $DIR"
                sudo mkdir -p "$DIR"
                sudo chown "$(id -u):$(id -g)" "$DIR"
            fi
        fi
    done

    log_success "Directories created"
}

install_binaries() {
    log_info "Downloading Authority Nanos binaries..."

    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    TARBALL_PATH="${TEMP_DIR}/authority-nanos.tar.gz"

    # Try primary URL (GitHub Releases, v-prefixed tag)
    if ! download_file "$DOWNLOAD_URL" "$TARBALL_PATH" 2>/dev/null; then
        log_verbose "Primary URL failed, trying alternative (unprefixed tag)..."
        if ! download_file "$DOWNLOAD_URL_ALT" "$TARBALL_PATH" 2>/dev/null; then
            die "Failed to download Authority Nanos. Check your internet connection and version number."
        fi
    fi

    log_info "Extracting binaries..."

    # Extract tarball
    tar -xzf "$TARBALL_PATH" -C "$TEMP_DIR" || die "Failed to extract tarball"

    # The release tarball (see .github/workflows/release.yml) packs everything
    # under a single versioned top-level directory, e.g.
    #   authority-nanos-2.0.1-darwin-arm64/{kernel.img,lib/,bin/,...}
    # That directory name is exactly the tarball stem. Descend into it so the
    # copies below find the payload; fall back to a flat layout just in case.
    SRC_DIR="${TEMP_DIR}/${TARBALL%.tar.gz}"
    if [ ! -d "$SRC_DIR" ]; then
        # Fall back to the sole extracted directory, else the temp root.
        SRC_DIR=$(find "$TEMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
        [ -n "$SRC_DIR" ] && [ -d "$SRC_DIR" ] || SRC_DIR="$TEMP_DIR"
    fi
    log_verbose "Install source dir: $SRC_DIR"

    # Find and install kernel and bootloader
    INSTALL_NEEDS_SUDO=0

    # Check if we need sudo
    if [ ! -w "$INSTALL_LIB" ]; then
        INSTALL_NEEDS_SUDO=1
    fi

    # Copy a file with the right privilege level (used for all payload files).
    install_cp() {
        _src="$1"; _dst="$2"
        if [ "$INSTALL_NEEDS_SUDO" = "1" ]; then
            sudo cp "$_src" "$_dst"
        else
            cp "$_src" "$_dst"
        fi
    }

    INSTALLED_ANY=0

    # Install kernel.img
    if [ -f "${SRC_DIR}/kernel.img" ]; then
        log_verbose "Installing kernel.img to ${INSTALL_LIB}/"
        install_cp "${SRC_DIR}/kernel.img" "${INSTALL_LIB}/"
        INSTALLED_ANY=1
    fi

    # Install boot.img
    if [ -f "${SRC_DIR}/boot.img" ]; then
        log_verbose "Installing boot.img to ${INSTALL_LIB}/"
        install_cp "${SRC_DIR}/boot.img" "${INSTALL_LIB}/"
    fi

    # Install libak (shared library)
    if [ -f "${SRC_DIR}/lib/libak.so" ]; then
        log_verbose "Installing libak.so to ${INSTALL_LIB}/"
        install_cp "${SRC_DIR}/lib/libak.so" "${INSTALL_LIB}/"
    elif [ -f "${SRC_DIR}/lib/libak.dylib" ]; then
        log_verbose "Installing libak.dylib to ${INSTALL_LIB}/"
        install_cp "${SRC_DIR}/lib/libak.dylib" "${INSTALL_LIB}/"
    fi

    # Install any additional tools found
    if [ -d "${SRC_DIR}/bin" ]; then
        for TOOL in "${SRC_DIR}/bin"/*; do
            if [ -f "$TOOL" ] && [ -x "$TOOL" ]; then
                TOOL_NAME=$(basename "$TOOL")
                log_verbose "Installing $TOOL_NAME to ${INSTALL_BIN}/"
                install_cp "$TOOL" "${INSTALL_BIN}/"
                if [ "$INSTALL_NEEDS_SUDO" = "1" ]; then
                    sudo chmod +x "${INSTALL_BIN}/${TOOL_NAME}"
                else
                    chmod +x "${INSTALL_BIN}/${TOOL_NAME}"
                fi
            fi
        done
    fi

    # Install minops/ops tool if present
    for TOOL in ops minops authority; do
        if [ -f "${SRC_DIR}/${TOOL}" ]; then
            log_verbose "Installing $TOOL to ${INSTALL_BIN}/"
            install_cp "${SRC_DIR}/${TOOL}" "${INSTALL_BIN}/"
            if [ "$INSTALL_NEEDS_SUDO" = "1" ]; then
                sudo chmod +x "${INSTALL_BIN}/${TOOL}"
            else
                chmod +x "${INSTALL_BIN}/${TOOL}"
            fi
        fi
    done

    if [ "$INSTALLED_ANY" = "0" ]; then
        die "Downloaded archive did not contain kernel.img (looked in ${SRC_DIR}). The release asset layout may have changed."
    fi

    log_success "Binaries installed"
}

install_python_sdk() {
    if [ "$INSTALL_PYTHON" != "1" ]; then
        log_verbose "Skipping Python SDK installation"
        return 0
    fi

    log_info "Installing Python SDK..."

    # Preferred: install from the SDK bundled in the release tarball we already
    # downloaded and extracted (SRC_DIR is set by install_binaries). This needs
    # no network and no git, so it avoids the slow full-history git clone /
    # on-demand archive of this repo. The SDK has no runtime dependencies.
    if [ -n "${SRC_DIR:-}" ] && [ -d "${SRC_DIR}/sdk-python" ]; then
        if $PIP_CMD install "${SRC_DIR}/sdk-python" >/dev/null 2>&1; then
            log_success "Python SDK installed from release bundle"
            return 0
        fi
        log_verbose "Bundled SDK install failed, falling back to PyPI/GitHub"
    fi

    # Next: try PyPI (only works once the package is actually published there).
    if $PIP_CMD install --upgrade "${PYPI_PACKAGE}" >/dev/null 2>&1; then
        log_success "Python SDK installed from PyPI"
        return 0
    fi

    # Last resort: install from GitHub directly (may be slow for large repos).
    log_warn "Bundled/PyPI install unavailable, trying GitHub..."

    GITHUB_SDK_URL="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${VERSION}.tar.gz"
    GITHUB_SDK_URL_ALT="https://github.com/${GITHUB_REPO}/archive/refs/heads/master.tar.gz"

    if $PIP_CMD install "git+https://github.com/${GITHUB_REPO}.git@v${VERSION}#subdirectory=sdk/python" >/dev/null 2>&1; then
        log_success "Python SDK installed from GitHub"
        return 0
    fi

    if $PIP_CMD install "git+https://github.com/${GITHUB_REPO}.git#subdirectory=sdk/python" >/dev/null 2>&1; then
        log_success "Python SDK installed from GitHub (master)"
        return 0
    fi

    log_warn "Could not install Python SDK automatically."
    log_warn "You can install it manually with:"
    log_warn "  pip install authority-nanos"
    log_warn "  # or"
    log_warn "  pip install git+https://github.com/${GITHUB_REPO}.git#subdirectory=sdk/python"
}

# ============================================================================
# Environment Setup
# ============================================================================

setup_environment() {
    log_info "Setting up environment..."

    # Create environment configuration file
    ENV_FILE="${INSTALL_SHARE}/env.sh"

    cat > "${TEMP_DIR}/env.sh" << 'ENVEOF'
# Authority Nanos Environment Configuration
# Source this file in your shell profile:
#   source /usr/local/share/authority/env.sh

# Installation paths
export AUTHORITY_HOME="${AUTHORITY_HOME:-/usr/local}"
export AUTHORITY_LIB="${AUTHORITY_HOME}/lib/authority"
export AUTHORITY_KERNEL="${AUTHORITY_LIB}/kernel.img"
export AUTHORITY_BOOT="${AUTHORITY_LIB}/boot.img"

# Add to PATH if not already present
case ":${PATH}:" in
    *:"${AUTHORITY_HOME}/bin":*)
        ;;
    *)
        export PATH="${AUTHORITY_HOME}/bin:${PATH}"
        ;;
esac

# Library path for libak
case "$(uname -s)" in
    Linux)
        case ":${LD_LIBRARY_PATH}:" in
            *:"${AUTHORITY_LIB}":*)
                ;;
            *)
                export LD_LIBRARY_PATH="${AUTHORITY_LIB}:${LD_LIBRARY_PATH:-}"
                ;;
        esac
        ;;
    Darwin)
        case ":${DYLD_LIBRARY_PATH}:" in
            *:"${AUTHORITY_LIB}":*)
                ;;
            *)
                export DYLD_LIBRARY_PATH="${AUTHORITY_LIB}:${DYLD_LIBRARY_PATH:-}"
                ;;
        esac
        ;;
esac
ENVEOF

    # Customize for actual install prefix. Write to a temp file and move it into
    # place: this avoids the sed -i portability difference between GNU (-i) and
    # BSD/macOS (-i '') sed entirely.
    sed "s|/usr/local|${PREFIX}|g" "${TEMP_DIR}/env.sh" > "${TEMP_DIR}/env.sh.new"
    mv "${TEMP_DIR}/env.sh.new" "${TEMP_DIR}/env.sh"

    # Install env.sh
    if [ -w "$INSTALL_SHARE" ]; then
        cp "${TEMP_DIR}/env.sh" "$ENV_FILE"
    else
        sudo cp "${TEMP_DIR}/env.sh" "$ENV_FILE"
    fi

    # Detect shell and profile file
    SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
    case "$SHELL_NAME" in
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                PROFILE="$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                PROFILE="$HOME/.bash_profile"
            else
                PROFILE="$HOME/.bashrc"
            fi
            ;;
        zsh)
            PROFILE="$HOME/.zshrc"
            ;;
        fish)
            PROFILE="$HOME/.config/fish/config.fish"
            ;;
        *)
            PROFILE="$HOME/.profile"
            ;;
    esac

    # Check if already sourced
    SOURCE_LINE="source \"${ENV_FILE}\""
    if [ -f "$PROFILE" ] && grep -q "authority/env.sh" "$PROFILE" 2>/dev/null; then
        log_verbose "Environment already configured in $PROFILE"
    else
        log_info "Adding Authority Nanos to $PROFILE"

        # Add source line to profile
        printf "\n# Authority Nanos\n%s\n" "$SOURCE_LINE" >> "$PROFILE" || \
            log_warn "Could not update $PROFILE. Add manually: $SOURCE_LINE"
    fi

    log_success "Environment configured"
}

# ============================================================================
# Verification
# ============================================================================

verify_installation() {
    if [ "$VERIFY_INSTALL" != "1" ]; then
        log_verbose "Skipping verification"
        return 0
    fi

    log_info "Verifying installation..."

    # Source environment
    if [ -f "${INSTALL_SHARE}/env.sh" ]; then
        . "${INSTALL_SHARE}/env.sh"
    fi

    VERIFY_FAILED=0

    # Check kernel.img
    if [ -f "${INSTALL_LIB}/kernel.img" ]; then
        log_success "kernel.img installed"
    else
        log_warn "kernel.img not found"
        VERIFY_FAILED=1
    fi

    # Check boot.img
    if [ -f "${INSTALL_LIB}/boot.img" ]; then
        log_success "boot.img installed"
    else
        log_verbose "boot.img not found (optional)"
    fi

    # Check libak
    if [ -f "${INSTALL_LIB}/libak.so" ] || [ -f "${INSTALL_LIB}/libak.dylib" ]; then
        log_success "libak installed"
    else
        log_verbose "libak not found (optional for binary-only install)"
    fi

    # Check Python SDK
    if [ "$INSTALL_PYTHON" = "1" ]; then
        if $PYTHON_CMD -c "import authority_nanos" 2>/dev/null; then
            SDK_VERSION=$($PYTHON_CMD -c "import authority_nanos; print(authority_nanos.__version__)" 2>/dev/null || echo "unknown")
            log_success "Python SDK installed (version: $SDK_VERSION)"
        else
            log_warn "Python SDK import failed"
        fi
    fi

    # Check ops/minops/authority command
    for CMD in authority minops ops; do
        if check_command "$CMD"; then
            CMD_VERSION=$($CMD version 2>/dev/null || $CMD --version 2>/dev/null || echo "installed")
            log_success "$CMD available ($CMD_VERSION)"
            break
        fi
    done

    if [ "$VERIFY_FAILED" = "1" ]; then
        log_warn "Some components may not have installed correctly"
    fi

    return 0
}

# ============================================================================
# Uninstallation
# ============================================================================

uninstall() {
    print_banner
    log_info "Uninstalling Authority Nanos..."

    INSTALL_BIN="${PREFIX}/bin"
    INSTALL_LIB="${PREFIX}/lib/authority"
    INSTALL_SHARE="${PREFIX}/share/authority"

    # Check if we need sudo
    UNINSTALL_NEEDS_SUDO=0
    if [ -d "$INSTALL_LIB" ] && [ ! -w "$INSTALL_LIB" ]; then
        UNINSTALL_NEEDS_SUDO=1
    fi

    # Remove binaries
    for CMD in authority minops ops; do
        if [ -f "${INSTALL_BIN}/${CMD}" ]; then
            log_verbose "Removing ${INSTALL_BIN}/${CMD}"
            if [ "$UNINSTALL_NEEDS_SUDO" = "1" ]; then
                sudo rm -f "${INSTALL_BIN}/${CMD}"
            else
                rm -f "${INSTALL_BIN}/${CMD}"
            fi
        fi
    done

    # Remove library directory
    if [ -d "$INSTALL_LIB" ]; then
        log_verbose "Removing $INSTALL_LIB"
        if [ "$UNINSTALL_NEEDS_SUDO" = "1" ]; then
            sudo rm -rf "$INSTALL_LIB"
        else
            rm -rf "$INSTALL_LIB"
        fi
    fi

    # Remove share directory
    if [ -d "$INSTALL_SHARE" ]; then
        log_verbose "Removing $INSTALL_SHARE"
        if [ "$UNINSTALL_NEEDS_SUDO" = "1" ]; then
            sudo rm -rf "$INSTALL_SHARE"
        else
            rm -rf "$INSTALL_SHARE"
        fi
    fi

    # Remove Python SDK
    if check_command pip3; then
        PIP_CMD="pip3"
    elif check_command pip; then
        PIP_CMD="pip"
    fi

    if [ -n "${PIP_CMD:-}" ]; then
        if $PIP_CMD show authority-nanos >/dev/null 2>&1; then
            log_info "Uninstalling Python SDK..."
            $PIP_CMD uninstall -y authority-nanos >/dev/null 2>&1 || true
        fi
    fi

    log_success "Authority Nanos uninstalled"
    log_info "Note: You may want to remove the source line from your shell profile"

    return 0
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    cat << 'HELPEOF'
Authority Nanos Installer

USAGE:
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh -s -- [OPTIONS]

OPTIONS:
    --help              Show this help message
    --version X.Y.Z     Install specific version (default: latest)
    --prefix /path      Install to custom directory (default: /usr/local)
    --no-python         Skip Python SDK installation
    --no-verify         Skip installation verification
    --uninstall         Uninstall Authority Nanos
    --verbose           Enable verbose output

ENVIRONMENT VARIABLES:
    AUTHORITY_VERSION   Version to install (overridden by --version)
    AUTHORITY_PREFIX    Installation prefix (overridden by --prefix)
    AUTHORITY_NO_PYTHON Set to 1 to skip Python SDK installation

EXAMPLES:
    # Install latest version
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh

    # Install specific version
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh -s -- --version 0.1.46

    # Install to custom directory
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh -s -- --prefix $HOME/.local

    # Uninstall
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh -s -- --uninstall

    # Install without Python SDK
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/get.sh | sh -s -- --no-python

SUPPORTED PLATFORMS:
    - Linux x86_64 (amd64)
    - Linux ARM64 (aarch64)
    - macOS x86_64 (Intel)
    - macOS ARM64 (Apple Silicon)

COMPONENTS INSTALLED:
    - kernel.img     - Authority Nanos unikernel
    - boot.img       - Bootloader
    - libak          - Authorization kernel library
    - authority      - CLI tool (ops/minops)
    - Python SDK     - authority-nanos package (optional)

For more information, visit: https://github.com/mbhatt1/authority
HELPEOF
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                if [ -z "${2:-}" ]; then
                    die "--version requires a version number"
                fi
                VERSION="$2"
                shift 2
                ;;
            --prefix|-p)
                if [ -z "${2:-}" ]; then
                    die "--prefix requires a path"
                fi
                PREFIX="$2"
                shift 2
                ;;
            --no-python)
                INSTALL_PYTHON=0
                shift
                ;;
            --no-verify)
                VERIFY_INSTALL=0
                shift
                ;;
            --uninstall)
                UNINSTALL=1
                shift
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            -*)
                die "Unknown option: $1. Use --help for usage."
                ;;
            *)
                die "Unexpected argument: $1. Use --help for usage."
                ;;
        esac
    done

    # Apply environment variable defaults if not set via args
    if [ -n "${AUTHORITY_NO_PYTHON:-}" ] && [ "$AUTHORITY_NO_PYTHON" = "1" ]; then
        INSTALL_PYTHON=0
    fi
}

# ============================================================================
# Main Installation
# ============================================================================

print_next_steps() {
    printf "\n"
    printf "%b============================================================%b\n" "$GREEN" "$NC"
    printf "%b     Installation Complete!%b\n" "$BOLD" "$NC"
    printf "%b============================================================%b\n" "$GREEN" "$NC"
    printf "\n"

    printf "%bNext steps:%b\n" "$BOLD" "$NC"
    printf "\n"
    printf "  1. Reload your shell or run:\n"
    printf "     %bsource %s/share/authority/env.sh%b\n" "$CYAN" "$PREFIX" "$NC"
    printf "\n"
    printf "  2. Verify the installation:\n"
    printf "     %bauthority version%b  # or: minops version, ops version\n" "$CYAN" "$NC"
    printf "\n"
    printf "  3. Run your first unikernel:\n"
    printf "     %becho 'print(\"Hello from Authority Nanos!\")' > hello.py%b\n" "$CYAN" "$NC"
    printf "     %bminops run hello.py%b\n" "$CYAN" "$NC"
    printf "\n"

    if [ "$INSTALL_PYTHON" = "1" ]; then
        printf "  4. Try the Python SDK:\n"
        printf "     %bpython3 -c \"import authority_nanos; print(authority_nanos.__version__)\"%b\n" "$CYAN" "$NC"
        printf "\n"
    fi

    printf "%bDocumentation:%b https://github.com/mbhatt1/authority\n" "$BOLD" "$NC"
    printf "%bSupport:%b       https://github.com/mbhatt1/authority/issues\n" "$BOLD" "$NC"
    printf "\n"
}

main() {
    parse_args "$@"

    # Handle uninstall
    if [ "$UNINSTALL" = "1" ]; then
        uninstall
        exit 0
    fi

    # Normal installation
    print_banner
    detect_platform
    check_dependencies
    resolve_version
    get_download_url
    create_directories
    install_binaries
    install_python_sdk
    setup_environment
    verify_installation
    print_next_steps
}

# Run main with all arguments
main "$@"
