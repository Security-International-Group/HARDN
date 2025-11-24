# HARDN Makefile
# Made detailed notes for easier navigation
#   - Build (Rust + C auditor)
#   - Binary install layout
#   - systemd unit install + enable
#   - Native "sudo make hardn" installs
#   - Packaging 
# ---------------------------------------------------------------------------
BINARY_NAME      = hardn
BUILD_TARGET     = target/release/$(BINARY_NAME)

# GUI bin
GUI_BINARY_NAME  = hardn-gui
GUI_BUILD_TARGET = target/release/$(GUI_BINARY_NAME)

DEB_DIR          = debian
BIN_INSTALL_PATH = usr/bin  # (legacy; not used anymore, kept for reference)

# Detect host if not set
ARCH    ?= $(shell dpkg --print-architecture)
PREFIX  ?= /usr
DESTDIR ?=

# Canonical install layout (single source)
LIBDIR      ?= $(PREFIX)/lib/hardn
BINDIR      ?= $(PREFIX)/bin
SYSTEMD_DIR ?= /lib/systemd/system

# Systemd unit files in the repo
# NOTE: Update paths below if your units live elsewhere (e.g. packaging/systemd/...)
UNIT_FILES := systemd/hardn.service \
              systemd/legion-daemon.service

# ---------------------------------------------------------------------------
# Rust Stuff 
# ---------------------------------------------------------------------------
HOME_DIR      := $(shell echo $$HOME)
RUST_BIN_DIR  := $(HOME_DIR)/.cargo/bin
RUST_ENV_FILE := $(HOME_DIR)/.cargo/env

# Export Rust environment
export PATH := $(RUST_BIN_DIR):$(PATH)
export CARGO_TERM_PROGRESS_WHEN := never

SHELL     := /bin/bash
MAKEFLAGS += --no-print-directory
# ---------------------------------------------------------------------------
ifeq ($(NO_COLOR),1)
COLOR_RESET    :=
COLOR_STAGE    :=
COLOR_SUCCESS  :=
COLOR_WARN     :=
COLOR_MUTED    :=
COLOR_PRIMARY  :=
COLOR_SECONDARY :=
SUBSTEP_PREFIX :=     ->
else
COLOR_RESET     := \033[0m
COLOR_STAGE     := \033[1;32m
COLOR_SUCCESS   := \033[1;32m
COLOR_WARN      := \033[1;32m
COLOR_MUTED     := \033[0;32m
COLOR_PRIMARY   := \033[1;32m
COLOR_SECONDARY := \033[1;32m
SUBSTEP_PREFIX  := \033[0;32m    ↳\033[0m
endif

CASTLE_NAME   := $(COLOR_PRIMARY)H$(COLOR_SECONDARY)A$(COLOR_PRIMARY)R$(COLOR_SECONDARY)D$(COLOR_PRIMARY)N$(COLOR_RESET)
CASTLE_PREFIX := $(COLOR_PRIMARY)  $(CASTLE_NAME)
# Tunable / Deb packaging flags
# ---------------------------------------------------------------------------
CARGO_FLAGS       ?= --release --quiet
DEB_PARALLEL      ?= $(shell nproc 2>/dev/null || echo 1)
CLEAN_AFTER_BUILD ?= 0  # 0 = keep artifacts, 1 = clean after build

# Ensure dpkg-buildpackage skips DWZ 
DEB_BUILD_OPTIONS ?= parallel=$(DEB_PARALLEL)
ifeq ($(findstring parallel=,$(DEB_BUILD_OPTIONS)),)
DEB_BUILD_OPTIONS += parallel=$(DEB_PARALLEL)
endif
ifeq ($(findstring nodwz,$(DEB_BUILD_OPTIONS)),)
DEB_BUILD_OPTIONS += nodwz
endif

# targets
.PHONY: all build build-internal hardn hardn-internal install-core \
        install-deb-internal clean

# ---------------------------------------------------------------------------
all: build-internal
# ---------------------------------------------------------------------------
build:
	@if [ "$$EUID" -eq 0 ]; then \
		$(MAKE) build-internal; \
	else \
		echo "ERROR: This target requires sudo privileges."; \
		echo "Please run: sudo make build"; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# pipeline for patch
#   - Ensure build dependencies are installed
#   - Ensure Rust toolchain is present
#   - Build Rust core
#   - Build C auditor
#   - Build Debian package (.deb)
# ---------------------------------------------------------------------------
build-internal:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Recon: supply scan$(COLOR_RESET)\n'
	@MISSING_DEPS=""; \
	for pkg in build-essential pkg-config libssl-dev libsqlite3-dev debhelper lintian python3-all python3-requests python3-setuptools curl wget whiptail libgtk-4-dev libglib2.0-dev libvte-2.91-gtk4-dev cargo rustc; do \
		if ! dpkg -l "$$pkg" 2>/dev/null | grep -q "^ii"; then \
			MISSING_DEPS="$$MISSING_DEPS $$pkg"; \
		fi; \
	done; \
	if [ -n "$$MISSING_DEPS" ]; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Missing ops gear identified:$(COLOR_RESET)\n'; \
		for pkg in $$MISSING_DEPS; do \
			[ -z "$$pkg" ] && continue; \
			printf '$(SUBSTEP_PREFIX)   $(COLOR_MUTED)- %s$(COLOR_RESET)\n' "$$pkg"; \
		done; \
		INSTALL_LOG=$$(mktemp); \
		printf '$(SUBSTEP_PREFIX) $(COLOR_STAGE)Securing supply drop…$(COLOR_RESET)'; \
		set -o pipefail; \
		( DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $$MISSING_DEPS ) > "$$INSTALL_LOG" 2>&1 & \
		APT_PID=$$!; \
		FRAMES=('|' '/' '-' '\\'); \
		INDEX=0; \
		while kill -0 $$APT_PID 2>/dev/null; do \
			printf '\r$(SUBSTEP_PREFIX) $(COLOR_STAGE)Securing supply drop %s$(COLOR_RESET)' "$${FRAMES[$$INDEX]}"; \
			INDEX=$$(( (INDEX + 1) % $${#FRAMES[@]} )); \
			sleep 0.15; \
		done; \
		wait $$APT_PID; \
		APT_STATUS=$$?; \
		if [ $$APT_STATUS -ne 0 ]; then \
			printf '\r$(SUBSTEP_PREFIX) $(COLOR_WARN)Supply drop failed; review %s$(COLOR_RESET)\033[K\n' "$$INSTALL_LOG"; \
			tail -n 40 "$$INSTALL_LOG" || true; \
			rm -f "$$INSTALL_LOG"; \
			exit $$APT_STATUS; \
		else \
			printf '\r$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Supply drop secured.$(COLOR_RESET)\033[K\n'; \
			rm -f "$$INSTALL_LOG"; \
		fi; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)All gear already online.$(COLOR_RESET)\n'; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Supply chain locked.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Spooling up the Rust forge$(COLOR_RESET)\n'
	@if ! command -v rustup >/dev/null 2>&1; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Deploying rustup agents (minimal)…$(COLOR_RESET)\n'; \
		INSTALL_STATUS=0; \
		{ \
			set -o pipefail; \
			( curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable >/tmp/hardn-rustup.log 2>&1 ) & \
			RUSTUP_PID=$$!; \
			BAR=''; \
			while kill -0 $$RUSTUP_PID 2>/dev/null; do \
				BAR="$${BAR}▰"; \
				if [ $${#BAR} -gt 20 ]; then BAR='▰'; fi; \
				printf '\r$(SUBSTEP_PREFIX) $(COLOR_PRIMARY)Deploying rust agents $(COLOR_STAGE)%s$(COLOR_RESET)' "$$BAR"; \
				sleep 0.18; \
			done; \
			wait $$RUSTUP_PID; \
			INSTALL_STATUS=$$?; \
		}; \
		if [ $$INSTALL_STATUS -ne 0 ]; then \
			printf '\r$(SUBSTEP_PREFIX) $(COLOR_WARN)Rust deploy failed; see /tmp/hardn-rustup.log$(COLOR_RESET)\033[K\n'; \
			exit $$INSTALL_STATUS; \
		else \
			printf '\r$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Rust agents deployed successfully.$(COLOR_RESET)\033[K\n'; \
		fi; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)rust already stationed.$(COLOR_RESET)\n'; \
	fi
	@{ \
		if [ -f "$(RUST_ENV_FILE)" ]; then \
			. "$(RUST_ENV_FILE)"; \
		fi; \
		if command -v rustup >/dev/null 2>&1; then \
			if ! rustup toolchain list | grep -q '^stable'; then \
				printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Pulling stable toolchain payload…$(COLOR_RESET)\n'; \
				rustup toolchain install stable --profile minimal --quiet >/dev/null 2>&1; \
			else \
				printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Stable toolchain already armed.$(COLOR_RESET)\n'; \
			fi; \
			rustup default stable >/dev/null 2>&1; \
		fi; \
	}
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)core build in progress.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Compiling HARDN core$(COLOR_RESET)\n'
	@BUILD_STATUS=0; \
	{ \
		set -o pipefail; \
		( cargo build $(CARGO_FLAGS) >/tmp/hardn-cargo-build.log 2>&1 ) & \
		BUILD_PID=$$!; \
		FRAMES=("▘" "▝" "▗" "▖"); \
		FRAME_COUNT=$${#FRAMES[@]}; \
		INDEX=0; \
		while kill -0 $$BUILD_PID 2>/dev/null; do \
			FRAME=$${FRAMES[$$INDEX]}; \
			printf '\r$(SUBSTEP_PREFIX) $(COLOR_PRIMARY)Compiling core $(COLOR_STAGE)%s$(COLOR_RESET)' "$$FRAME"; \
			INDEX=$$(( (INDEX + 1) % FRAME_COUNT )); \
			sleep 0.14; \
		done; \
		wait $$BUILD_PID; \
		BUILD_STATUS=$$?; \
	}; \
	if [ $$BUILD_STATUS -ne 0 ]; then \
		printf '\r$(SUBSTEP_PREFIX) $(COLOR_WARN)Cargo build failed; see /tmp/hardn-cargo-build.log$(COLOR_RESET)\033[K\n'; \
		tail -n 25 /tmp/hardn-cargo-build.log || true; \
		exit $$BUILD_STATUS; \
	else \
		printf '\r$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Core compile complete.$(COLOR_RESET)\033[K\n'; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Compiling compliance auditor$(COLOR_RESET)\n'
	@mkdir -p target/release
	@if ! cc -std=c11 -O2 -Wall -Wextra -pedantic src/audit/hardn_audit.c -o target/release/hardn-audit; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)C auditor build failed.$(COLOR_RESET)\n'; \
		exit 1; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Compliance auditor built.$(COLOR_RESET)\n'; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Assembling Debian bunker$(COLOR_RESET)\n'
	@TMP_LOG=$$(mktemp); \
	if dpkg-buildpackage -us -uc -b --no-pre-clean -j$(DEB_PARALLEL) > $$TMP_LOG 2>&1; then \
		WARNINGS=$$(grep -i "warning" $$TMP_LOG || true); \
		if [ -n "$$WARNINGS" ]; then \
			printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Intel: build warnings detected.$(COLOR_RESET)\n'; \
			printf "%s\n" "$$WARNINGS" | while IFS= read -r warn; do \
				[ -z "$$warn" ] && continue; \
				printf '$(COLOR_WARN)   ⚠  %s$(COLOR_RESET)\n' "$$warn"; \
			done; \
		else \
			printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Build logs Sanitized.$(COLOR_RESET)\n'; \
		fi; \
	else \
		cat $$TMP_LOG; \
		rm -f $$TMP_LOG; \
		exit 1; \
	fi; \
	rm -f $$TMP_LOG
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Debian bunker sealed.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Staging the payload$(COLOR_RESET)\n'
	@DEB_FILE=$$(find .. -name "hardn_*.deb" -newer target/release/hardn 2>/dev/null | head -n1); \
	if [ -n "$$DEB_FILE" ]; then \
		cp "$$DEB_FILE" . && printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Payload staged: %s$(COLOR_RESET)\n' "$$DEB_FILE"; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)No fresh .deb located upstream.$(COLOR_RESET)\n'; \
	fi
ifneq ($(CLEAN_AFTER_BUILD),1)
	@printf '$(CASTLE_PREFIX) $(COLOR_MUTED)Skipping post-build clean (CLEAN_AFTER_BUILD=0).$(COLOR_RESET)\n'
else
	$(MAKE) clean
endif
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)HARDN battle-ready.$(COLOR_RESET)\n'

# ---------------------------------------------------------------------------
# Core install logic 
#   - Uses PREFIX/LIBDIR/BINDIR/SYSTEMD_DIR
#   - Honors DESTDIR:
#       * DESTDIR empty >>>> real system install + systemctl enable --now
#       * DESTDIR set  >>>>> packaging install, no systemctl
# ---------------------------------------------------------------------------
install-core:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Installing HARDN core$(COLOR_RESET)\n'

	@if [ ! -f "$(BUILD_TARGET)" ] || [ ! -f "$(GUI_BUILD_TARGET)" ] || [ ! -f "target/release/hardn-monitor" ]; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Binaries missing. Run: sudo make build$(COLOR_RESET)\n'; \
		exit 1; \
	fi

	@printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Installing binaries to $(LIBDIR) and wiring symlinks$(COLOR_RESET)\n'
	@mkdir -p "$(DESTDIR)$(LIBDIR)" "$(DESTDIR)$(BINDIR)"
	@install -m 755 "$(BUILD_TARGET)"            "$(DESTDIR)$(LIBDIR)/hardn"
	@install -m 755 target/release/hardn-monitor "$(DESTDIR)$(LIBDIR)/hardn-monitor"
	@install -m 755 "$(GUI_BUILD_TARGET)"        "$(DESTDIR)$(LIBDIR)/hardn-gui"

	@if [ -f "usr/share/hardn/scripts/hardn-service-manager.sh" ]; then \
		install -m 755 usr/share/hardn/scripts/hardn-service-manager.sh "$(DESTDIR)$(LIBDIR)/hardn-service-manager"; \
	fi

	@ln -sf "$(LIBDIR)/hardn"           "$(DESTDIR)$(BINDIR)/hardn"
	@ln -sf "$(LIBDIR)/hardn-monitor"   "$(DESTDIR)$(BINDIR)/hardn-monitor"
	@ln -sf "$(LIBDIR)/hardn-gui"       "$(DESTDIR)$(BINDIR)/hardn-gui"
	@if [ -f "$(DESTDIR)$(LIBDIR)/hardn-service-manager" ]; then \
		ln -sf "$(LIBDIR)/hardn-service-manager" "$(DESTDIR)$(BINDIR)/hardn-service-manager"; \
	fi

	@mkdir -p "$(DESTDIR)/usr/share/hardn" \
	         "$(DESTDIR)/var/log/hardn" \
	         "$(DESTDIR)/var/lib/hardn/legion"
	@chmod 755 "$(DESTDIR)/usr/share/hardn" \
	           "$(DESTDIR)/var/log/hardn" \
	           "$(DESTDIR)/var/lib/hardn" \
	           "$(DESTDIR)/var/lib/hardn/legion" 2>/dev/null || true

	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Installing systemd units$(COLOR_RESET)\n'
	@mkdir -p "$(DESTDIR)$(SYSTEMD_DIR)"
	@for unit in $(UNIT_FILES); do \
		if [ -f "$$unit" ]; then \
			install -m 644 "$$unit" "$(DESTDIR)$(SYSTEMD_DIR)/$$(basename $$unit)"; \
		else \
			printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Missing unit file: %s$(COLOR_RESET)\n' "$$unit"; \
		fi; \
	done

	@if [ -z "$(DESTDIR)" ]; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_STAGE)Reloading systemd and enabling services$(COLOR_RESET)\n'; \
		systemctl daemon-reload || true; \
		systemctl enable --now hardn.service legion-daemon.service || true; \
	fi

	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Core + services installed.$(COLOR_RESET)\n'

# ---------------------------------------------------------------------------
# Native install same way 
#   - sudo make hardn
#   - Builds (via build) then calls install-core on the real system
#   - Adds invoking user to "hardn" group (if it exists)
#   - Launches GUI as invoking user
# ---------------------------------------------------------------------------
hardn: build
	@if [ "$$EUID" -eq 0 ]; then \
		$(MAKE) hardn-internal; \
	else \
		echo "ERROR: This target requires sudo privileges."; \
		echo "Please run: sudo make hardn"; \
		exit 1; \
	fi

hardn-internal:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Setting up HARDN (native install)$(COLOR_RESET)\n'
	@$(MAKE) install-core DESTDIR=
	@if [ -n "$$SUDO_USER" ]; then \
		usermod -aG hardn "$$SUDO_USER" 2>/dev/null || true; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Launching HARDN GUI$(COLOR_RESET)\n'
	@if [ -n "$$SUDO_USER" ]; then \
		runuser -u "$$SUDO_USER" -- nohup "$(BINDIR)/hardn-gui" >/dev/null 2>&1 & \
	else \
		nohup "$(BINDIR)/hardn-gui" >/dev/null 2>&1 & \
	fi
	@printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)GUI launched$(COLOR_RESET)\n'
	@printf '$(COLOR_SUCCESS)HARDN ready$(COLOR_RESET)\n'

# ---------------------------------------------------------------------------
# Internal .deb installer helper (option)
#   - Attempts to locate a built .deb and install it w/ apt
#   - Not used by hardn / install-core, but kept for tooling/scripts
# ---------------------------------------------------------------------------
install-deb-internal:
	@DEB_FILE=$$(find . -name "hardn_*.deb" | head -n1); \
	if [ -z "$$DEB_FILE" ]; then \
		DEB_FILE=$$(find .. -name "hardn_*_$(ARCH).deb" | head -n1); \
	fi; \
	if [ -n "$$DEB_FILE" ]; then \
		apt-get update -qq > /dev/null 2>&1; \
		apt-get install -y -qq "$$DEB_FILE" > /dev/null 2>&1; \
	else \
		printf '$(CASTLE_PREFIX) $(COLOR_WARN)No .deb file found!$(COLOR_RESET)\n'; exit 1; \
	fi
# Cleanup
# ---------------------------------------------------------------------------
clean:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Purging forge residue$(COLOR_RESET)\n'
	@{ \
		if [ -f "$(RUST_ENV_FILE)" ]; then \
			. "$(RUST_ENV_FILE)"; \
		fi; \
		cargo clean >/dev/null 2>&1 || true; \
	}
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Forge embers extinguished.$(COLOR_RESET)\n'
