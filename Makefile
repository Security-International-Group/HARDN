# Binary and paths
BINARY_NAME=hardn
BUILD_TARGET=target/release/$(BINARY_NAME)
DEB_DIR=debian
BIN_INSTALL_PATH=usr/bin

# Detect host architecture if not set
ARCH ?= $(shell dpkg --print-architecture)
PREFIX ?= /usr
DESTDIR ?=

# Rust environment
HOME_DIR := $(shell echo $$HOME)
RUST_BIN_DIR := $(HOME_DIR)/.cargo/bin
RUST_ENV_FILE := $(HOME_DIR)/.cargo/env

# Export Rust environment
export PATH := $(RUST_BIN_DIR):$(PATH)
export CARGO_TERM_PROGRESS_WHEN := never

SHELL := /bin/bash
MAKEFLAGS += --no-print-directory

# Branding and color palette (disable with NO_COLOR=1)
ifeq ($(NO_COLOR),1)
COLOR_RESET :=
COLOR_STAGE :=
COLOR_SUCCESS :=
COLOR_WARN :=
COLOR_MUTED :=
COLOR_PRIMARY :=
COLOR_SECONDARY :=
SUBSTEP_PREFIX :=     ->
else
COLOR_RESET := \033[0m
COLOR_STAGE := \033[1;38;5;81m
COLOR_SUCCESS := \033[1;38;5;82m
COLOR_WARN := \033[1;38;5;214m
COLOR_MUTED := \033[2;38;5;244m
COLOR_PRIMARY := \033[1;38;5;45m
COLOR_SECONDARY := \033[1;38;5;123m
SUBSTEP_PREFIX := \033[2;38;5;244m    ↳\033[0m
endif

CASTLE_NAME := $(COLOR_PRIMARY)H$(COLOR_SECONDARY)A$(COLOR_PRIMARY)R$(COLOR_SECONDARY)D$(COLOR_PRIMARY)N$(COLOR_RESET)
CASTLE_PREFIX := $(COLOR_PRIMARY)  $(CASTLE_NAME)

# Tunable build flags
CARGO_FLAGS ?= --release --quiet
DEB_PARALLEL ?= $(shell nproc 2>/dev/null || echo 1)

# Ensure dpkg-buildpackage skips DWZ (avoids noisy warnings) while retaining caller options
DEB_BUILD_OPTIONS ?= parallel=$(DEB_PARALLEL)
ifeq ($(findstring parallel=,$(DEB_BUILD_OPTIONS)),)
DEB_BUILD_OPTIONS += parallel=$(DEB_PARALLEL)
endif
ifeq ($(findstring nodwz,$(DEB_BUILD_OPTIONS)),)
DEB_BUILD_OPTIONS += nodwz
endif
export DEB_BUILD_OPTIONS

# Default target
all: build-internal

# Build the Debian package + install Rust
build:
	@if [ "$$EUID" -eq 0 ]; then \
		$(MAKE) build-internal; \
	else \
		echo "ERROR: This target requires sudo privileges."; \
		echo "Please run: sudo make build"; \
		exit 1; \
	fi

# Internal target that does the actual build work (called by sudo)
build-internal:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Surveying the outer walls for required provisions$(COLOR_RESET)\n'
	@MISSING_DEPS=""; \
	for pkg in build-essential pkg-config libssl-dev debhelper lintian python3-all python3-requests python3-setuptools curl wget whiptail libgtk-4-dev libglib2.0-dev; do \
		if ! dpkg -l "$$pkg" 2>/dev/null | grep -q "^ii"; then \
			MISSING_DEPS="$$MISSING_DEPS $$pkg"; \
		fi; \
	done; \
	if [ -n "$$MISSING_DEPS" ]; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Reinforcing the armoury with:%s$(COLOR_RESET)\n' "$$MISSING_DEPS"; \
		DEBIAN_FRONTEND=noninteractive apt-get update -qq; \
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $$MISSING_DEPS; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)All defensive packages standing guard.$(COLOR_RESET)\n'; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Logistics secured.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Tempering the Rust forge$(COLOR_RESET)\n'
	@if ! command -v rustup >/dev/null 2>&1; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Installing rustup sentries (minimal profile)…$(COLOR_RESET)\n'; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable >/tmp/hardn-rustup.log 2>&1; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Rustup ... standing watch.$(COLOR_RESET)\n'; \
	fi
	@{ \
		if [ -f "$(RUST_ENV_FILE)" ]; then \
			. "$(RUST_ENV_FILE)"; \
		fi; \
		if command -v rustup >/dev/null 2>&1; then \
			if ! rustup toolchain list | grep -q '^stable'; then \
				printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Installing the stable toolchain…$(COLOR_RESET)\n'; \
				rustup toolchain install stable --profile minimal --quiet >/dev/null 2>&1; \
			else \
				printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Stable toolchain already tempered.$(COLOR_RESET)\n'; \
			fi; \
			rustup default stable >/dev/null 2>&1; \
		fi; \
	}
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Forge ready for crafting.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Forging the HARDN core binary$(COLOR_RESET)\n'
	@cargo build $(CARGO_FLAGS)
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Core forging complete.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Raising the fortress walls into a Debian stronghold$(COLOR_RESET)\n'
	@TMP_LOG=$$(mktemp); \
	if dpkg-buildpackage -us -uc -b --no-pre-clean -j$(DEB_PARALLEL) > $$TMP_LOG 2>&1; then \
		WARNINGS=$$(grep -i "warning" $$TMP_LOG || true); \
		if [ -n "$$WARNINGS" ]; then \
			printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Scouts report warnings from the build logs.$(COLOR_RESET)\n'; \
			printf "%s\n" "$$WARNINGS" | while IFS= read -r warn; do \
				[ -z "$$warn" ] && continue; \
				printf '$(COLOR_WARN)   ⚠  %s$(COLOR_RESET)\n' "$$warn"; \
			done; \
		else \
			printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Fortress walls inspected with no warnings.$(COLOR_RESET)\n'; \
		fi; \
	else \
		cat $$TMP_LOG; \
		rm -f $$TMP_LOG; \
		exit 1; \
	fi; \
	rm -f $$TMP_LOG
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Fortress walls assembled.$(COLOR_RESET)\n'
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Escorting the freshly forged package to the armory$(COLOR_RESET)\n'
	@DEB_FILE=$$(find .. -name "hardn_*.deb" -newer target/release/hardn 2>/dev/null | head -n1); \
	if [ -n "$$DEB_FILE" ]; then \
		cp "$$DEB_FILE" . && printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Copied %s to the staging grounds.$(COLOR_RESET)\n' "$$DEB_FILE"; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)No new stronghold package located in parent directory.$(COLOR_RESET)\n'; \
	fi
	$(MAKE) clean
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)HARDN fortress ready for deployment.$(COLOR_RESET)\n'

# Install HARDN as a service and start everything
hardn:
	@if [ "$$EUID" -eq 0 ]; then \
		$(MAKE) hardn-internal; \
	else \
		echo "ERROR: This target requires sudo privileges."; \
		echo "Please run: sudo make hardn"; \
		exit 1; \
	fi

# Internal target that does the actual work (called by sudo)
hardn-internal:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Unfurling the HARDN banner atop the ramparts$(COLOR_RESET)\n'
	@bash scripts/print-banner.sh "$(BUILD_TARGET)"
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Deploying the HARDN stronghold package$(COLOR_RESET)\n'
	@$(MAKE) install-deb-internal
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Welcoming trusted sentries to the HARDN watch$(COLOR_RESET)\n'
	@if [ -n "$$SUDO_USER" ]; then \
		usermod -aG hardn "$$SUDO_USER" || true; \
		printf '$(SUBSTEP_PREFIX) $(COLOR_SUCCESS)Added %s to the hardn garrison (re-login required).$(COLOR_RESET)\n' "$$SUDO_USER"; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)No SUDO_USER detected; skipping garrison update.$(COLOR_RESET)\n'; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Lighting the watchfires (services)$(COLOR_RESET)\n'
	@systemctl enable hardn-api.service >/dev/null 2>&1 || true
	@systemctl start hardn-api.service >/dev/null 2>&1 || true
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Engaging the hardening rituals$(COLOR_RESET)\n'
	@if [ -f "hardening.sh" ]; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Running local hardening.sh$(COLOR_RESET)\n'; \
		bash hardening.sh; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Invoking installed hardening module$(COLOR_RESET)\n'; \
		bash /usr/share/hardn/modules/hardening.sh; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Opening the command bastion (service manager)$(COLOR_RESET)\n'
	@if [ "$$HARDN_NO_AUTO_GUI" = "1" ]; then \
		if [ -e /dev/tty ] && [ -w /dev/tty ]; then \
			hardn-service-manager < /dev/tty > /dev/tty 2>&1; \
		else \
			printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Interactive terminal not detected; run sudo hardn-service-manager manually.$(COLOR_RESET)\n'; \
		fi; \
	else \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Attempting to launch HARDN read-only GUI (if available).$(COLOR_RESET)\n'; \
		if command -v hardn-gui >/dev/null 2>&1; then \
			if [ -n "$$SUDO_USER" ]; then \
				runuser -u "$$SUDO_USER" -- nohup hardn-gui >/dev/null 2>&1 & \
			else \
				nohup hardn-gui >/dev/null 2>&1 & \
			fi; \
		fi; \
		if [ -e /dev/tty ] && [ -w /dev/tty ]; then \
			hardn-service-manager < /dev/tty > /dev/tty 2>&1; \
		else \
			printf '$(SUBSTEP_PREFIX) $(COLOR_WARN)Interactive terminal not detected; run sudo hardn-service-manager manually.$(COLOR_RESET)\n'; \
		fi; \
	fi
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)HARDN Install complete.$(COLOR_RESET)\n'

# Internal target that does the actual installation work
install-deb-internal:
	@DEB_FILE=$$(find . -name "hardn_*.deb" | head -n1); \
	if [ -z "$$DEB_FILE" ]; then \
		DEB_FILE=$$(find .. -name "hardn_*_$(ARCH).deb" | head -n1); \
	fi; \
	if [ -n "$$DEB_FILE" ]; then \
		printf '$(SUBSTEP_PREFIX) $(COLOR_MUTED)Installing %s$(COLOR_RESET)\n' "$$DEB_FILE"; \
		dpkg -i "$$DEB_FILE"; \
	else \
		printf '$(CASTLE_PREFIX) $(COLOR_WARN)No .deb file found for installation!$(COLOR_RESET)\n'; exit 1; \
	fi

clean:
	@printf '$(CASTLE_PREFIX) $(COLOR_STAGE)Scouring the forge for embers$(COLOR_RESET)\n'
	@{ \
		if [ -f "$(RUST_ENV_FILE)" ]; then \
			. "$(RUST_ENV_FILE)"; \
		fi; \
		cargo clean >/dev/null 2>&1 || true; \
	}
	@printf '$(CASTLE_PREFIX) $(COLOR_SUCCESS)Forge embers extinguished.$(COLOR_RESET)\n'
