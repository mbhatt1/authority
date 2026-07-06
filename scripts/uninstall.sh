#!/bin/sh
# ============================================================================
# Authority Nanos Uninstaller Script
#
# This script removes Authority Nanos from your system.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/uninstall.sh | sh
#   ./scripts/uninstall.sh
#
# Options:
#   --help              Show help message
#   --prefix /path      Uninstall from custom directory (default: /usr/local)
#   --keep-python       Keep Python SDK installed
#   --keep-config       Keep configuration files
#   --dry-run           Show what would be removed without removing
#   --yes               Skip confirmation prompt
#
# ============================================================================
# POSIX-compliant shell script - works with sh, bash, zsh, dash
# ============================================================================

set -e

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_PREFIX="/usr/local"
PREFIX="${AUTHORITY_PREFIX:-$DEFAULT_PREFIX}"
KEEP_PYTHON=0
KEEP_CONFIG=0
DRY_RUN=0
YES=0
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
    printf "%b     Authority Nanos Uninstaller%b\n" "$BOLD" "$NC"
    printf "%b============================================================%b\n" "$CYAN" "$NC"
    printf "\n"
}

log_info() {
    printf "%b[INFO]%b %s\n" "$BLUE" "$NC" "$1"
}

log_success() {
    printf "%b[OK]%b %s\n" "$GREEN" "$NC" "$1"
}

log_warn() {
    printf "%b[WARN]%b %s\n" "$YELLOW" "$NC" "$1"
}

log_error() {
    printf "%b[ERROR]%b %s\n" "$RED" "$NC" "$1" >&2
}

log_verbose() {
    if [ "$VERBOSE" = "1" ]; then
        printf "%b[DEBUG]%b %s\n" "$CYAN" "$NC" "$1"
    fi
}

log_dry_run() {
    printf "%b[DRY-RUN]%b Would remove: %s\n" "$YELLOW" "$NC" "$1"
}

die() {
    log_error "$1"
    exit 1
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    cat << 'HELPEOF'
Authority Nanos Uninstaller

USAGE:
    curl -sSfL https://raw.githubusercontent.com/mbhatt1/authority/master/scripts/uninstall.sh | sh
    ./scripts/uninstall.sh [OPTIONS]

OPTIONS:
    --help              Show this help message
    --prefix /path      Uninstall from custom directory (default: /usr/local)
    --keep-python       Keep Python SDK installed
    --keep-config       Keep configuration files
    --dry-run           Show what would be removed without removing
    --yes, -y           Skip confirmation prompt
    --verbose           Enable verbose output

ENVIRONMENT VARIABLES:
    AUTHORITY_PREFIX    Installation prefix (overridden by --prefix)

EXAMPLES:
    # Uninstall with confirmation
    ./scripts/uninstall.sh

    # Uninstall without confirmation
    ./scripts/uninstall.sh --yes

    # Preview what would be removed
    ./scripts/uninstall.sh --dry-run

    # Uninstall from custom location
    ./scripts/uninstall.sh --prefix $HOME/.local

    # Keep Python SDK
    ./scripts/uninstall.sh --keep-python

COMPONENTS REMOVED:
    - kernel.img, boot.img    (from PREFIX/lib/authority/)
    - libak.so/libak.dylib    (from PREFIX/lib/authority/)
    - authority, minops, ops  (from PREFIX/bin/)
    - env.sh                  (from PREFIX/share/authority/)
    - Python SDK              (authority-nanos pip package)

Shell profile modifications are NOT automatically removed.
You may want to manually remove the 'source .../env.sh' line.

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
            --prefix|-p)
                if [ -z "${2:-}" ]; then
                    die "--prefix requires a path"
                fi
                PREFIX="$2"
                shift 2
                ;;
            --keep-python)
                KEEP_PYTHON=1
                shift
                ;;
            --keep-config)
                KEEP_CONFIG=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --yes|-y)
                YES=1
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
}

# ============================================================================
# Discovery Functions
# ============================================================================

find_installation() {
    log_info "Scanning for Authority Nanos installation..."

    INSTALL_BIN="${PREFIX}/bin"
    INSTALL_LIB="${PREFIX}/lib/authority"
    INSTALL_SHARE="${PREFIX}/share/authority"

    # Track what we find
    FOUND_ITEMS=""
    FOUND_COUNT=0

    # Check for binaries
    for CMD in authority minops ops; do
        if [ -f "${INSTALL_BIN}/${CMD}" ]; then
            FOUND_ITEMS="${FOUND_ITEMS}  - ${INSTALL_BIN}/${CMD}\n"
            FOUND_COUNT=$((FOUND_COUNT + 1))
        fi
    done

    # Check for library directory
    if [ -d "$INSTALL_LIB" ]; then
        for FILE in kernel.img boot.img libak.so libak.dylib; do
            if [ -f "${INSTALL_LIB}/${FILE}" ]; then
                FOUND_ITEMS="${FOUND_ITEMS}  - ${INSTALL_LIB}/${FILE}\n"
                FOUND_COUNT=$((FOUND_COUNT + 1))
            fi
        done

        # Count any other files in lib directory
        OTHER_FILES=$(find "$INSTALL_LIB" -type f 2>/dev/null | grep -v -E '(kernel\.img|boot\.img|libak\.(so|dylib))' | wc -l | tr -d ' ')
        if [ "$OTHER_FILES" -gt 0 ]; then
            FOUND_ITEMS="${FOUND_ITEMS}  - ${INSTALL_LIB}/ ($OTHER_FILES additional files)\n"
        fi
    fi

    # Check for share directory
    if [ -d "$INSTALL_SHARE" ]; then
        if [ -f "${INSTALL_SHARE}/env.sh" ]; then
            FOUND_ITEMS="${FOUND_ITEMS}  - ${INSTALL_SHARE}/env.sh\n"
            FOUND_COUNT=$((FOUND_COUNT + 1))
        fi

        # Count any other files in share directory
        OTHER_FILES=$(find "$INSTALL_SHARE" -type f 2>/dev/null | grep -v 'env\.sh' | wc -l | tr -d ' ')
        if [ "$OTHER_FILES" -gt 0 ]; then
            FOUND_ITEMS="${FOUND_ITEMS}  - ${INSTALL_SHARE}/ ($OTHER_FILES additional files)\n"
        fi
    fi

    # Check for Python SDK
    if [ "$KEEP_PYTHON" != "1" ]; then
        if check_command pip3; then
            PIP_CMD="pip3"
        elif check_command pip; then
            PIP_CMD="pip"
        elif check_command python3 && python3 -m pip --version >/dev/null 2>&1; then
            PIP_CMD="python3 -m pip"
        elif check_command python && python -m pip --version >/dev/null 2>&1; then
            PIP_CMD="python -m pip"
        else
            PIP_CMD=""
        fi

        if [ -n "$PIP_CMD" ]; then
            if $PIP_CMD show authority-nanos >/dev/null 2>&1; then
                SDK_LOCATION=$($PIP_CMD show authority-nanos 2>/dev/null | grep "Location:" | cut -d: -f2 | tr -d ' ')
                FOUND_ITEMS="${FOUND_ITEMS}  - Python SDK: authority-nanos (${SDK_LOCATION:-unknown location})\n"
                FOUND_COUNT=$((FOUND_COUNT + 1))
                PYTHON_SDK_INSTALLED=1
            else
                PYTHON_SDK_INSTALLED=0
            fi
        else
            PYTHON_SDK_INSTALLED=0
        fi
    else
        PYTHON_SDK_INSTALLED=0
        log_verbose "Keeping Python SDK (--keep-python)"
    fi

    if [ "$FOUND_COUNT" -eq 0 ]; then
        log_warn "No Authority Nanos installation found at prefix: $PREFIX"
        log_info "Searched locations:"
        log_info "  - ${INSTALL_BIN}/"
        log_info "  - ${INSTALL_LIB}/"
        log_info "  - ${INSTALL_SHARE}/"
        return 1
    fi

    log_info "Found $FOUND_COUNT component(s) to remove:"
    printf "%b" "$FOUND_ITEMS"

    return 0
}

# ============================================================================
# Confirmation
# ============================================================================

confirm_uninstall() {
    if [ "$YES" = "1" ]; then
        return 0
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log_info "Dry run mode - no changes will be made"
        return 0
    fi

    printf "\n"
    printf "%bAre you sure you want to uninstall Authority Nanos? [y/N]%b " "$YELLOW" "$NC"

    # Read from terminal even if script is piped
    if [ -t 0 ]; then
        read -r REPLY
    else
        # Try to read from /dev/tty
        read -r REPLY < /dev/tty 2>/dev/null || REPLY="n"
    fi

    case "$REPLY" in
        [Yy]|[Yy][Ee][Ss])
            return 0
            ;;
        *)
            log_info "Uninstall cancelled"
            exit 0
            ;;
    esac
}

# ============================================================================
# Removal Functions
# ============================================================================

remove_file() {
    FILE="$1"

    if [ ! -e "$FILE" ]; then
        log_verbose "File does not exist: $FILE"
        return 0
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log_dry_run "$FILE"
        return 0
    fi

    if [ -w "$FILE" ] || [ -w "$(dirname "$FILE")" ]; then
        rm -f "$FILE" && log_verbose "Removed: $FILE" || log_warn "Failed to remove: $FILE"
    else
        sudo rm -f "$FILE" && log_verbose "Removed (sudo): $FILE" || log_warn "Failed to remove: $FILE"
    fi
}

remove_directory() {
    DIR="$1"

    if [ ! -d "$DIR" ]; then
        log_verbose "Directory does not exist: $DIR"
        return 0
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log_dry_run "$DIR/"
        return 0
    fi

    if [ -w "$DIR" ]; then
        rm -rf "$DIR" && log_verbose "Removed: $DIR/" || log_warn "Failed to remove: $DIR/"
    else
        sudo rm -rf "$DIR" && log_verbose "Removed (sudo): $DIR/" || log_warn "Failed to remove: $DIR/"
    fi
}

# ============================================================================
# Main Uninstall
# ============================================================================

do_uninstall() {
    log_info "Uninstalling Authority Nanos..."

    # Remove binaries
    for CMD in authority minops ops; do
        remove_file "${INSTALL_BIN}/${CMD}"
    done

    # Remove library directory
    if [ "$KEEP_CONFIG" != "1" ]; then
        remove_directory "$INSTALL_LIB"
    else
        # Just remove the main files but keep the directory
        remove_file "${INSTALL_LIB}/kernel.img"
        remove_file "${INSTALL_LIB}/boot.img"
        remove_file "${INSTALL_LIB}/libak.so"
        remove_file "${INSTALL_LIB}/libak.dylib"
    fi

    # Remove share directory
    if [ "$KEEP_CONFIG" != "1" ]; then
        remove_directory "$INSTALL_SHARE"
    else
        log_verbose "Keeping configuration files (--keep-config)"
    fi

    # Remove Python SDK
    if [ "${PYTHON_SDK_INSTALLED:-0}" = "1" ] && [ "$KEEP_PYTHON" != "1" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            log_dry_run "Python SDK: authority-nanos"
        else
            log_info "Uninstalling Python SDK..."
            $PIP_CMD uninstall -y authority-nanos >/dev/null 2>&1 && \
                log_verbose "Removed Python SDK" || \
                log_warn "Failed to remove Python SDK"
        fi
    fi
}

# ============================================================================
# Post-Uninstall
# ============================================================================

print_post_uninstall() {
    printf "\n"

    if [ "$DRY_RUN" = "1" ]; then
        printf "%b============================================================%b\n" "$YELLOW" "$NC"
        printf "%b     Dry Run Complete - No Changes Made%b\n" "$BOLD" "$NC"
        printf "%b============================================================%b\n" "$YELLOW" "$NC"
        printf "\n"
        log_info "Run without --dry-run to perform actual uninstall"
    else
        printf "%b============================================================%b\n" "$GREEN" "$NC"
        printf "%b     Uninstall Complete%b\n" "$BOLD" "$NC"
        printf "%b============================================================%b\n" "$GREEN" "$NC"
    fi

    printf "\n"
    printf "%bManual cleanup (optional):%b\n" "$BOLD" "$NC"
    printf "\n"
    printf "  You may want to remove the source line from your shell profile:\n"
    printf "\n"

    # Suggest profile locations
    SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
    case "$SHELL_NAME" in
        bash)
            printf "    %bsed -i '/authority\\/env.sh/d' ~/.bashrc%b\n" "$CYAN" "$NC"
            printf "    %bsed -i '/Authority Nanos/d' ~/.bashrc%b\n" "$CYAN" "$NC"
            ;;
        zsh)
            printf "    %bsed -i '' '/authority\\/env.sh/d' ~/.zshrc%b\n" "$CYAN" "$NC"
            printf "    %bsed -i '' '/Authority Nanos/d' ~/.zshrc%b\n" "$CYAN" "$NC"
            ;;
        *)
            printf "    Remove lines containing 'authority/env.sh' from your shell profile\n"
            ;;
    esac

    printf "\n"

    if [ "$KEEP_PYTHON" = "1" ]; then
        printf "%bNote:%b Python SDK was kept installed.\n" "$YELLOW" "$NC"
        printf "  To remove it later: pip uninstall authority-nanos\n"
        printf "\n"
    fi

    if [ "$KEEP_CONFIG" = "1" ]; then
        printf "%bNote:%b Configuration files were kept at:\n" "$YELLOW" "$NC"
        printf "  - ${INSTALL_SHARE}/\n"
        printf "\n"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    parse_args "$@"
    print_banner

    if ! find_installation; then
        exit 0
    fi

    confirm_uninstall
    do_uninstall
    print_post_uninstall
}

# Run main with all arguments
main "$@"
