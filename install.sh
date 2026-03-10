#!/usr/bin/env bash
set -euo pipefail

# ssh-concierge installer
# Sets up a virtual environment, installs the package, creates symlinks,
# and shows SSH config instructions.

DEFAULT_VENV="$HOME/.local/share/ssh-concierge/venv"
DEFAULT_PREFIX="$HOME/.local/bin"
MIN_PYTHON_MINOR=11  # Minimum Python 3.x version

# --- Output helpers ---

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
NC=$'\033[0m'

info()    { printf "${BLUE}→${NC} %s\n" "$*"; }
ok()      { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}!${NC} %s\n" "$*"; }
err()     { printf "${RED}✗${NC} %s\n" "$*" >&2; }
die()     { err "$@"; exit 1; }
heading() { printf "\n${BOLD}%s${NC}\n" "$*"; }

# --- Parse arguments ---

VENV=""
PREFIX=""
SOURCE_DIR=""
PYTHON=""
UNINSTALL=false

usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Install ssh-concierge into a Python virtual environment.

Options:
  --venv PATH       Virtual environment path (default: $DEFAULT_VENV)
  --prefix PATH     Binary directory for symlinks (default: $DEFAULT_PREFIX)
  --python CMD      Python interpreter (default: auto-detect 3.${MIN_PYTHON_MINOR}+)
  --source PATH     Source directory (default: auto-detect)
  --uninstall       Remove ssh-concierge
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --venv)      VENV="$2"; shift 2 ;;
        --prefix)    PREFIX="$2"; shift 2 ;;
        --python)    PYTHON="$2"; shift 2 ;;
        --source)    SOURCE_DIR="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "Unknown option: $1" ;;
    esac
done

VENV="${VENV:-$DEFAULT_VENV}"
PREFIX="${PREFIX:-$DEFAULT_PREFIX}"

# --- Uninstall ---

if $UNINSTALL; then
    heading "Uninstalling ssh-concierge"

    for name in ssh-concierge ssh-concierge-py ssh-concierge-wrap ssh scp; do
        target="$PREFIX/$name"
        if [[ -L "$target" || -f "$target" ]]; then
            rm "$target"
            ok "Removed $target"
        fi
    done

    if [[ -d "$VENV" ]]; then
        rm -rf "$VENV"
        ok "Removed venv $VENV"
    fi

    warn "SSH config (~/.ssh/config) was not modified — remove the Match/Include lines manually if needed."
    exit 0
fi

# --- Detect source directory ---

find_source_dir() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -n "$SOURCE_DIR" ]]; then
        [[ -f "$SOURCE_DIR/pyproject.toml" ]] || die "No pyproject.toml found in $SOURCE_DIR"
        return
    fi

    if [[ -f "$script_dir/pyproject.toml" ]]; then
        SOURCE_DIR="$script_dir"
    elif [[ -f "./pyproject.toml" ]]; then
        SOURCE_DIR="$(pwd)"
    else
        die "Cannot find ssh-concierge source. Run from the repo directory or use --source PATH."
    fi
}

find_source_dir
info "Source: $SOURCE_DIR"

# --- Detect OS ---

detect_os() {
    case "$(uname -s)" in
        Linux*)  OS="linux" ;;
        Darwin*) OS="macos" ;;
        *)       OS="unknown" ;;
    esac
}

detect_os
info "OS: $OS"

# --- Detect shell ---

detect_shell() {
    local user_shell
    user_shell="$(basename "${SHELL:-/bin/bash}")"
    case "$user_shell" in
        zsh)  DETECTED_SHELL="zsh" ;;
        fish) DETECTED_SHELL="fish" ;;
        *)    DETECTED_SHELL="bash" ;;
    esac
}

detect_shell
info "Shell: $DETECTED_SHELL"

# --- Find Python 3.11+ ---

check_python_version() {
    local py="$1"
    "$py" -c "
import sys
if sys.version_info >= (3, $MIN_PYTHON_MINOR):
    print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')
    sys.exit(0)
sys.exit(1)
" 2>/dev/null
}

find_python() {
    if [[ -n "$PYTHON" ]]; then
        local ver
        ver=$(check_python_version "$PYTHON") || die "$PYTHON is not Python 3.${MIN_PYTHON_MINOR}+"
        ok "Python: $PYTHON ($ver)"
        return
    fi

    # Try common names in order of preference
    local candidates=("python3.13" "python3.12" "python3.11" "python3" "python")
    for py in "${candidates[@]}"; do
        if command -v "$py" &>/dev/null; then
            local ver
            ver=$(check_python_version "$py") && {
                PYTHON="$py"
                ok "Python: $py ($ver)"
                return
            }
        fi
    done

    die "Python 3.${MIN_PYTHON_MINOR}+ not found. Install it first:
  RHEL 8/9: sudo dnf install python3.11
  macOS:    brew install python@3.11
  Ubuntu:   sudo apt install python3.11"
}

find_python

# --- Check 1Password CLI ---

if command -v op &>/dev/null; then
    op_version=$(op --version 2>/dev/null || echo "unknown")
    ok "1Password CLI: $op_version"
else
    warn "1Password CLI (op) not found — ssh-concierge won't work without it."
    warn "Install from: https://developer.1password.com/docs/cli/get-started/"
fi

# --- Set up virtual environment ---

heading "Virtual environment"

if [[ -d "$VENV" ]]; then
    info "Found existing venv: $VENV"
    # Verify it's usable
    if [[ -x "$VENV/bin/python" ]]; then
        existing_ver=$("$VENV/bin/python" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "")
        if [[ -n "$existing_ver" ]]; then
            ok "Using existing venv (Python $existing_ver)"
        else
            warn "Existing venv seems broken — recreating"
            rm -rf "$VENV"
        fi
    else
        warn "Existing venv has no python — recreating"
        rm -rf "$VENV"
    fi
fi

if [[ ! -d "$VENV" ]]; then
    info "Creating venv at $VENV"
    mkdir -p "$(dirname "$VENV")"
    "$PYTHON" -m venv "$VENV"
    ok "Created venv"
fi

# --- Install ssh-concierge ---

heading "Installing ssh-concierge"

# Prefer uv for speed, fall back to pip
if command -v uv &>/dev/null; then
    info "Installing with uv"
    uv pip install --python "$VENV/bin/python" "$SOURCE_DIR"
else
    info "Installing with pip (use 'uv' for faster installs)"
    "$VENV/bin/pip" install --upgrade pip --quiet 2>/dev/null || true
    "$VENV/bin/pip" install "$SOURCE_DIR"
fi

# Verify entry points exist
for ep in ssh-concierge-py ssh-concierge-wrap; do
    [[ -x "$VENV/bin/$ep" ]] || die "Entry point $ep not found in venv after install"
done
ok "Package installed"

# --- Create symlinks ---

heading "Setting up binaries"

mkdir -p "$PREFIX"

# Helper to create symlinks/copies, with conflict detection
install_link() {
    local name="$1" target="$2"
    local dest="$PREFIX/$name"

    if [[ -L "$dest" ]]; then
        local current
        current=$(readlink "$dest")
        if [[ "$current" == "$target" ]]; then
            ok "$name → $target (already set)"
            return
        fi
        warn "$name currently points to $current — replacing"
        rm "$dest"
    elif [[ -f "$dest" ]]; then
        # For the entry point script (not a symlink), check if it's ours
        if head -5 "$dest" 2>/dev/null | grep -q 'ssh-concierge'; then
            rm "$dest"
        else
            warn "$dest exists and is not an ssh-concierge file — skipping"
            warn "  Remove it manually or use a different --prefix"
            return
        fi
    fi

    ln -s "$target" "$dest"
    ok "$name → $target"
}

# Entry point: copy the shell script (not a symlink — it's a standalone script)
install_entry_point() {
    local dest="$PREFIX/ssh-concierge"
    local src="$SOURCE_DIR/src/ssh-concierge"

    if [[ -L "$dest" ]]; then
        rm "$dest"
    elif [[ -f "$dest" ]]; then
        if head -5 "$dest" 2>/dev/null | grep -q 'ssh-concierge'; then
            rm "$dest"
        else
            warn "$dest exists and is not an ssh-concierge file — skipping"
            return
        fi
    fi

    cp "$src" "$dest"
    chmod +x "$dest"
    ok "ssh-concierge (entry point) → $dest"
}

install_entry_point
install_link "ssh-concierge-py"   "$VENV/bin/ssh-concierge-py"
install_link "ssh-concierge-wrap" "$VENV/bin/ssh-concierge-wrap"
install_link "ssh"                "$VENV/bin/ssh-concierge-wrap"
install_link "scp"                "$VENV/bin/ssh-concierge-wrap"

# --- Check PATH ---

heading "PATH check"

if echo "$PATH" | tr ':' '\n' | grep -qx "$PREFIX"; then
    ok "$PREFIX is in PATH"
else
    warn "$PREFIX is NOT in your PATH"
    echo ""
    case "$DETECTED_SHELL" in
        zsh)
            info "Add to ~/.zshrc:"
            echo "    export PATH=\"$PREFIX:\$PATH\""
            ;;
        fish)
            info "Add to ~/.config/fish/config.fish:"
            echo "    fish_add_path $PREFIX"
            ;;
        *)
            info "Add to ~/.bashrc:"
            echo "    export PATH=\"$PREFIX:\$PATH\""
            ;;
    esac
    echo ""
    warn "Then reload your shell: exec \$SHELL"
fi

# Verify ssh/scp wrappers shadow the system binaries
check_shadow() {
    local cmd="$1"
    local resolved
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [[ "$resolved" == "$PREFIX/$cmd" ]]; then
        ok "$cmd resolves to $PREFIX/$cmd"
    elif [[ -n "$resolved" ]]; then
        warn "$cmd resolves to $resolved (should be $PREFIX/$cmd)"
        warn "  Ensure $PREFIX appears before $(dirname "$resolved") in PATH"
    fi
}

check_shadow "ssh"
check_shadow "scp"

# --- SSH config ---

heading "SSH config"

# Determine runtime dir for the config snippet
if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
    runtime_example="$XDG_RUNTIME_DIR/ssh-concierge"
else
    runtime_example="/tmp/ssh-concierge-$(id -u)"
fi

SSH_CONFIG="$HOME/.ssh/config"
MATCH_LINE='Match host * exec "ssh-concierge %h"'

if [[ -f "$SSH_CONFIG" ]] && grep -qF 'ssh-concierge' "$SSH_CONFIG"; then
    ok "SSH config already references ssh-concierge"
else
    info "Add the following to $SSH_CONFIG (before any other Host/Match blocks):"
    echo ""
    cat <<EOF
    Match host * exec "ssh-concierge %h"
        Include $runtime_example/hosts.conf
EOF
    echo ""
    info "If you use the 1Password SSH agent, also add:"
    echo ""
    cat <<EOF
    Host *
        IdentityAgent ~/.1password/agent.sock
EOF
    echo ""
fi

# --- Done ---

heading "Installation complete"
echo ""
info "Test it:  ssh-concierge --generate"
info "Debug:    ssh-concierge --debug <alias>"
info "Remove:   $0 --uninstall"
echo ""
