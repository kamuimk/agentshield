#!/bin/sh
# AgentShield installer
# Usage: curl -fsSL https://raw.githubusercontent.com/kamuimk/agentshield/main/install.sh | sh
#
# Environment variables:
#   AGENTSHIELD_VERSION  - specific version to install (default: latest)
#   INSTALL_DIR          - installation directory (default: /usr/local/bin or ~/.local/bin)

set -e

REPO="kamuimk/agentshield"
BINARY_NAME="agentshield"

# --- Helper functions ---

info() {
    printf "\033[1;34m==>\033[0m %s\n" "$1"
}

success() {
    printf "\033[1;32m==>\033[0m %s\n" "$1"
}

error() {
    printf "\033[1;31mError:\033[0m %s\n" "$1" >&2
    exit 1
}

# --- Detect OS and architecture ---

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS_NAME="unknown-linux-gnu" ;;
        Darwin) OS_NAME="apple-darwin" ;;
        *)      error "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH_NAME="x86_64" ;;
        aarch64|arm64)  ARCH_NAME="aarch64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac

    TARGET="${ARCH_NAME}-${OS_NAME}"
}

# --- Determine install directory ---

detect_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        return
    fi

    if [ -w /usr/local/bin ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi
}

# --- Fetch latest version ---

get_version() {
    if [ -n "$AGENTSHIELD_VERSION" ]; then
        VERSION="$AGENTSHIELD_VERSION"
        return
    fi

    info "Fetching latest version..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"//;s/".*//')"

    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Set AGENTSHIELD_VERSION manually."
    fi
}

# --- Download and install ---

download_and_install() {
    ARCHIVE_NAME="${BINARY_NAME}-${TARGET}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"

    info "Downloading ${BINARY_NAME} ${VERSION} for ${TARGET}..."

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    if ! curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE_NAME}"; then
        error "Download failed. Check that ${VERSION} has a release for ${TARGET}."
    fi

    info "Installing to ${INSTALL_DIR}..."

    tar xzf "${TMPDIR}/${ARCHIVE_NAME}" -C "$TMPDIR"
    chmod +x "${TMPDIR}/${BINARY_NAME}"
    mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
}

# --- Verify installation ---

verify() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        INSTALLED_VERSION="$("$BINARY_NAME" --version 2>/dev/null || echo "unknown")"
        success "AgentShield installed successfully!"
        info "Version: ${INSTALLED_VERSION}"
        info "Location: $(command -v "$BINARY_NAME")"
    else
        success "AgentShield installed to ${INSTALL_DIR}/${BINARY_NAME}"
        if ! echo "$PATH" | tr ':' '\n' | grep -q "^${INSTALL_DIR}$"; then
            info "Add ${INSTALL_DIR} to your PATH:"
            info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        fi
    fi

    echo ""
    info "Quick start:"
    info "  agentshield quickstart"
    info "  agentshield wrap -- claude"
}

# --- Main ---

main() {
    info "AgentShield Installer"
    echo ""

    detect_platform
    detect_install_dir
    get_version
    download_and_install
    verify
}

main
