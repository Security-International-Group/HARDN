#!/bin/bash

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# -------- Helper Functions (MUST come first) --------
error_exit() {
        echo
        echo "INSTALLATION FAILED: $1"
        echo "Please check the messages above."
        echo
        exit 1
}

detect_source_dir() {
    # Check if we're already in the source directory
    if [[ -f "Cargo.toml" && -d "src" && -f "debian/control" ]]; then
        echo "."
        return 0
    fi

    # Check for HARDN-XDR subdirectory
    if [[ -d "./HARDN-XDR" ]]; then
        echo "./HARDN-XDR"
        return 0
    fi

    # Check for common CI paths
    for path in "/work" "/src" "../HARDN-XDR" "."; do
        if [[ -f "$path/Cargo.toml" && -d "$path/src" ]]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

# -------- Config (after functions) --------
HARDN_VERSION="2.2.0"
SOURCE_DIR="$(detect_source_dir)" || error_exit "Could not locate HARDN-XDR source directory. Expected Cargo.toml and src/ directory."

PKG_NAME="hardn"    # Debian package name
BIN_NAME="hardn"    # Installed CLI binary name

LEGACY_MODULE_DIR="/usr/lib/hardn-xdr/src/setup/modules"
LEGACY_TOOL_DIR="/usr/lib/hardn-xdr/src/setup/tools"

RUNTIME_ROOT="/usr/share/hardn"
MODULE_DIR="${RUNTIME_ROOT}/modules"
TOOL_DIR="${RUNTIME_ROOT}/tools"
TEMPLATE_DIR="${RUNTIME_ROOT}/templates"

RUSTUP_HOME="${RUSTUP_HOME:-/root/.rustup}"
CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
CARGO_ENV="${CARGO_HOME}/env"

# ---- New tunables (safe defaults) ----
MIN_RUSTC="${MIN_RUSTC:-1.85.0}"             # toolchain that supports edition 2024
HARDN_RESOLVE_BUILD_DEPS="${HARDN_RESOLVE_BUILD_DEPS:-0}"  # set 1 in CI to auto apt-get build-dep
HARDN_SKIP_SYSTEMD="${HARDN_SKIP_SYSTEMD:-auto}"           # auto|0|1 (auto=skip in containers)

# -------- Helpers --------
is_container() {
        [[ -f /.dockerenv ]] || grep -qE 'docker|container' /proc/1/cgroup 2>/dev/null || [[ "${GITHUB_ACTIONS:-}" == "true" ]]
}

ver_ge() { # return 0 if $1 >= $2
        local IFS=.
        local -a A=("${1//[^0-9.]/}"); local -a B=("${2//[^0-9.]/}")
        local i x y
        for ((i=0; i<${#A[@]} || i<${#B[@]}; i++)); do
            x=${A[i]:-0}; y=${B[i]:-0}
            # Fix: Ensure x and y are valid integers before arithmetic comparison
            if [[ "$x" =~ ^[0-9]+$ ]] && [[ "$y" =~ ^[0-9]+$ ]]; then
                ((x > y)) && return 0
                ((x < y)) && return 1
            else
                # Fallback to string comparison if not pure integers
                [[ "$x" > "$y" ]] && return 0
                [[ "$x" < "$y" ]] && return 1
            fi
        done
        return 0
}

# Conditionally stub systemctl and policy-rc.d in containers or CI to prevent service start errors
maybe_stub_systemd() {
        # Only stub inside containers (avoid starting services)
        local mode="$1"
        if [[ "$mode" == "auto" ]]; then
            is_container && mode=1 || mode=0
        fi
        if [[ "$mode" == "1" ]]; then
            echo "[*] Stubbing systemd actions for container/CI…"
            printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/systemctl
            chmod +x /usr/local/bin/systemctl
            printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d
            chmod +x /usr/sbin/policy-rc.d
        fi
}

cleanup_stubs() {
        rm -f /usr/local/bin/systemctl 2>/dev/null || true
        rm -f /usr/sbin/policy-rc.d 2>/dev/null || true
}

check_root() {
        if [[ $EUID -ne 0 ]]; then
            error_exit "This script requires root privileges. Please run with sudo."
        fi
}

check_system() {
        if [[ ! -f /etc/debian_version ]]; then
            error_exit "This system is not Debian-based. HARDN requires Debian 12+ or Ubuntu 24.04+."
        fi
        echo "[+] OK: Debian-based system detected"
}

update_system() {
        echo "[*] Updating system packages..."
        apt-get update
        apt-get -y upgrade || echo "[!] WARNING: System upgrade encountered issues, continuing..."
}

install_dependencies() {
        echo "[*] Installing build and runtime dependencies (APT)..."
        apt-get update
        apt-get install -y \
             build-essential devscripts debhelper dh-cargo \
             python3-gi python3-gi-cairo python3-matplotlib python3-psutil python3-requests gir1.2-gtk-3.0 \
             auditd suricata rkhunter chkrootkit unhide debsums lynis clamav clamav-daemon \
             clamav-freshclam yara aide aide-common fail2ban rsyslog logrotate \
             needrestart apt-listchanges apt-listbugs unattended-upgrades \
             ca-certificates software-properties-common lsb-release gnupg openssh-server \
             ufw systemd-timesyncd apparmor firejail libpam-pwquality libpam-google-authenticator \
             libpam-tmpdir curl wget lsof psmisc procps git pkg-config libssl-dev \
             python3-setuptools whiptail
}

# --- Optional: keep Build-Depends in sync automatically (enable with HARDN_RESOLVE_BUILD_DEPS=1) ---
resolve_build_deps() {
    [[ "${HARDN_RESOLVE_BUILD_DEPS}" = "1" ]] || return 0
    echo "[*] Resolving Build-Depends from debian/control…"
    . /etc/os-release
    cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${VERSION_CODENAME} main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian ${VERSION_CODENAME} main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${VERSION_CODENAME}-security main contrib non-free non-free-firmware
deb-src http://security.debian.org/debian-security ${VERSION_CODENAME}-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${VERSION_CODENAME}-updates main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian ${VERSION_CODENAME}-updates main contrib non-free non-free-firmware
EOF
    apt-get update
    apt-get build-dep -y "${SOURCE_DIR}" || echo "[!] WARNING: apt-get build-dep could not resolve all deps; continuing…"
}

install_rust_toolchain() {
        local need_rustup=1 cur="" system_rust_removed=0
        if command -v rustc >/dev/null 2>&1; then
            cur="$(rustc --version | awk '{print $2}')"
            if ver_ge "$cur" "$MIN_RUSTC"; then
                echo "[*] Rust already installed: $(rustc --version)"
                need_rustup=0
            else
                echo "[!] Rust too old ($cur < ${MIN_RUSTC}); will install rustup stable."
                # Remove old system Rust packages to avoid conflicts
                if dpkg -l | grep -q "^ii.*rust"; then
                    echo "[*] Removing old system Rust packages to avoid conflicts..."
                    apt-get remove -y rustc cargo || true
                    apt-get autoremove -y || true
                    system_rust_removed=1
                fi
            fi
        fi

        if [[ $need_rustup -eq 1 ]]; then
            echo "[*] Installing Rust (rustup stable)…"
            # Set environment variable to skip PATH check warnings
            export RUSTUP_INIT_SKIP_PATH_CHECK=yes
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
                | sh -s -- -y --default-toolchain stable --no-modify-path

            if [[ $system_rust_removed -eq 1 ]]; then
                echo "[*] System Rust packages were removed and replaced with rustup-managed Rust"
            fi
        fi

        # shellcheck disable=SC1090
        [[ -f "${CARGO_ENV}" ]] && source "${CARGO_ENV}"
        export PATH="${CARGO_HOME}/bin:${PATH}"

        # CRITICAL: Always ensure default toolchain is set
        echo "[*] Ensuring rustup default toolchain is configured..."
        rustup default stable || {
            echo "[*] Setting up rustup default for the first time..."
            rustup install stable
            rustup default stable
        }

        if ! command -v rustc >/dev/null 2>&1; then
            error_exit "Rust installation failed (rustc not found in PATH)"
        fi
        echo "[*] Using Rust: $(rustc --version)"
}

ensure_rust_env() {
        # shellcheck disable=SC1090
        [[ -f "${CARGO_ENV}" ]] && source "${CARGO_ENV}"
        export PATH="${CARGO_HOME}/bin:${PATH}"
        command -v cargo >/dev/null 2>&1 || error_exit "Cargo not found after rustup install"
}

create_system_groups() {
        echo "[*] Ensuring required system users and groups..."
        getent group systemd-network >/dev/null || groupadd -r systemd-network
        id -u systemd-network >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin systemd-network
        getent group systemd-journal >/dev/null || groupadd -r systemd-journal
}

align_changelog_with_control() {
        # Avoid: "source package has two conflicting values"
        if [[ -f "$SOURCE_DIR/debian/control" && -f "$SOURCE_DIR/debian/changelog" ]]; then
            local src
            src="$(sed -n 's/^Source:[[:space:]]*//p' "$SOURCE_DIR/debian/control" | head -1 || true)"
            if [[ -n "$src" ]]; then
                sed -E -i "1s/^[^ ]+/${src}/" "$SOURCE_DIR/debian/changelog" || true
            fi
        fi
}

build_and_install_pkg() {
        echo "[*] Building and installing ${PKG_NAME} from local source..."

        [[ -d "$SOURCE_DIR" ]] || error_exit "Source directory $SOURCE_DIR not found."

        pushd "$SOURCE_DIR" >/dev/null

        # Ensure cargo is available AND set default toolchain
        ensure_rust_env

        # Critical: Set rustup default to ensure cargo works in subprocesses
        echo "[*] Configuring rustup default toolchain..."
        rustup default stable || error_exit "Failed to set rustup default toolchain"

        # Verify cargo works before building
        cargo --version || error_exit "Cargo not working after rustup configuration"

        # Regenerate Cargo.lock if it exists to ensure compatibility with current Cargo version
        if [[ -f "Cargo.lock" ]]; then
            echo "[*] Regenerating Cargo.lock for current Cargo version..."
            rm -f "Cargo.lock"
            cargo generate-lockfile || cargo build --release --dry-run > /dev/null 2>&1 || true
        fi

        echo "[*] Building Debian package in: $SOURCE_DIR"
        align_changelog_with_control

        # Set environment for dpkg-buildpackage subprocesses
        export RUSTUP_HOME CARGO_HOME
        export PATH="${CARGO_HOME}/bin:${PATH}"

        dpkg-buildpackage -us -uc -b || error_exit "dpkg-buildpackage failed"
        popd >/dev/null

        # Find the freshly built .deb (version-agnostic discovery)
        deb_file="$(find "${SOURCE_DIR}/.." "${SOURCE_DIR}" -maxdepth 1 -name "${PKG_NAME}_*.deb" -type f 2>/dev/null | head -n 1 || true)"
        [[ -f "$deb_file" ]] || error_exit "Built .deb file not found for ${PKG_NAME}. Expected pattern: ${PKG_NAME}_*.deb"

        echo "[*] Installing package: $deb_file"
        dpkg -i "$deb_file" || apt-get install -f -y
}

ensure_runtime_layout() {
        echo "[*] Ensuring runtime layout under ${RUNTIME_ROOT} ..."

        mkdir -p "${MODULE_DIR}" "${TOOL_DIR}" "${TEMPLATE_DIR}"

        # If legacy locations exist, prefer copying into new canonical path
        if [[ -d "${LEGACY_MODULE_DIR}" ]]; then
            echo "    - Syncing modules from legacy: ${LEGACY_MODULE_DIR}"
            cp -a "${LEGACY_MODULE_DIR}/." "${MODULE_DIR}/" || true
        fi

        if [[ -d "${LEGACY_TOOL_DIR}" ]]; then
            echo "    - Syncing tools from legacy: ${LEGACY_TOOL_DIR}"
            cp -a "${LEGACY_TOOL_DIR}/." "${TOOL_DIR}/" || true
        fi

        # If modules/tools still empty but legacy exists, create symlinks as fallback
        if [[ -d "${LEGACY_MODULE_DIR}" && ! $(ls -A "${MODULE_DIR}" 2>/dev/null) ]]; then
            echo "    - Creating symlink fallback for modules"
            rm -f "${MODULE_DIR}" && ln -s "${LEGACY_MODULE_DIR}" "${MODULE_DIR}"
        fi

        if [[ -d "${LEGACY_TOOL_DIR}" && ! $(ls -A "${TOOL_DIR}" 2>/dev/null) ]]; then
            echo "    - Creating symlink fallback for tools"
            rm -f "${TOOL_DIR}" && ln -s "${LEGACY_TOOL_DIR}" "${TOOL_DIR}"
        fi

        # Permissions for scripts
        chmod +x "${MODULE_DIR}"/*.sh 2>/dev/null || true
        chmod +x "${TOOL_DIR}"/*.sh 2>/dev/null || true
}

verify_install() {
        echo "[*] Verifying CLI is available..."
        if ! command -v "${BIN_NAME}" >/dev/null; then
            error_exit "CLI '${BIN_NAME}' not found after installation"
        fi

        echo "[*] Verifying module/tool roots visible to binary..."
        if [[ -d "${MODULE_DIR}" ]]; then
            echo "    - Modules in: ${MODULE_DIR}"
            ls -1 "${MODULE_DIR}" 2>/dev/null | head -n 10 || true
        else
            echo "    - WARNING: ${MODULE_DIR} does not exist"
        fi

        if [[ -d "${TOOL_DIR}" ]]; then
            echo "    - Tools in:   ${TOOL_DIR}"
            ls -1 "${TOOL_DIR}" 2>/dev/null | head -n 10 || true
        else
            echo "    - WARNING: ${TOOL_DIR} does not exist"
        fi
}

show_completion() {
    cat << EOF

[✓] ${PKG_NAME} Installation Complete

Next steps:
1) Run with auto-discovery:
   sudo ${BIN_NAME}

2) Run a single module (name or name.sh):
   sudo ${BIN_NAME} run-module debsums

3) Override search paths (optional):
   sudo HARDN_MODULE_PATH="${MODULE_DIR}:${LEGACY_MODULE_DIR}" ${BIN_NAME}

Docs:
https://github.com/Security-International-Group/HARDN-XDR

WARNING: HARDN-XDR makes significant system changes.
         Always test in a non-production environment first.

EOF
}

main() {
        echo
        echo "HARDN-XDR v${HARDN_VERSION} Local Installer"
        echo "==========================================="

        check_root
        check_system
        update_system
        install_dependencies
        # Build-deps auto-resolver (enable with HARDN_RESOLVE_BUILD_DEPS=1 in CI)
        resolve_build_deps
        install_rust_toolchain
        create_system_groups

        # Only stub systemd actions in containers/CI
        maybe_stub_systemd "${HARDN_SKIP_SYSTEMD}"

        build_and_install_pkg
        cleanup_stubs

        ensure_runtime_layout
        verify_install
        show_completion
}

main "$@"
