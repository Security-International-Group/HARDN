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
SHELL := /bin/bash

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
	@MISSING_DEPS=""; \
	for pkg in build-essential pkg-config libssl-dev debhelper lintian python3-all python3-requests python3-setuptools curl wget whiptail libgtk-4-dev libglib2.0-dev; do \
		if ! dpkg -l "$$pkg" 2>/dev/null | grep -q "^ii"; then \
			MISSING_DEPS="$$MISSING_DEPS $$pkg"; \
		fi; \
	done; \
	if [ -n "$$MISSING_DEPS" ]; then \
		echo "Installing missing dependencies:$$MISSING_DEPS"; \
		apt update && apt install -y $$MISSING_DEPS; \
	else \
		echo "All required dependencies are already installed."; \
	fi
	@echo "Checking Rust installation..."
	@if ! command -v rustup >/dev/null 2>&1; then \
		echo "Rustup not found. Installing Rust..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		echo "Rust installation completed."; \
	else \
		echo "Rustup found, updating toolchain..."; \
	fi
	@. $(RUST_ENV_FILE) && rustup update stable && rustup default stable
	@echo "Setting up Rust environment..."
	@HOME=$(HOME_DIR) . $(RUST_ENV_FILE) && rustup default stable
	@echo "Building Rust binary (CLI only)..."
	cargo build --release
	@echo "Building .deb package..."
	dpkg-buildpackage -us -uc -b --no-pre-clean
	# Move .deb file to current directory for easier CI access
	@echo "Moving .deb file to current directory..."
	@DEB_FILE=$$(find .. -name "hardn_*.deb" -newer target/release/hardn 2>/dev/null | head -n1); \
	if [ -n "$$DEB_FILE" ]; then \
		cp "$$DEB_FILE" . && echo "Copied $$DEB_FILE to current directory"; \
	else \
		echo "No new .deb file found in parent directory"; \
	fi
	@echo "Cleaning up build artifacts..."
	$(MAKE) clean
	@echo "Build process completed successfully."

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
	@echo "Displaying HARDN banner..."
	@rustc banner.rs -o banner_temp && ./banner_temp && rm banner_temp
	@echo "Checking required Python dependencies..."
	@MISSING_PY_DEPS=""; \
	for pkg in python3-fastapi python3-uvicorn python3-psutil; do \
		if ! dpkg -l "$$pkg" 2>/dev/null | grep -q "^ii"; then \
			MISSING_PY_DEPS="$$MISSING_PY_DEPS $$pkg"; \
		fi; \
	done; \
	if [ -n "$$MISSING_PY_DEPS" ]; then \
		echo "Installing missing Python dependencies:$$MISSING_PY_DEPS"; \
		apt update && apt install -y $$MISSING_PY_DEPS; \
	else \
		echo "All required Python dependencies are already installed."; \
	fi
	@echo "Installing HARDN package..."
	@$(MAKE) install-deb-internal
	@echo "Granting GUI log access to invoking user (hardn group)..."
	@if [ -n "$$SUDO_USER" ]; then \
		usermod -aG hardn "$$SUDO_USER" || true; \
		echo "Added $$SUDO_USER to group 'hardn' (re-login required for access)."; \
	else \
		echo "No SUDO_USER detected; skip group grant."; \
	fi
	@echo "Enabling and starting HARDN API server..."
	@systemctl enable hardn-api.service || true
	@systemctl start hardn-api.service || true
	@echo "Running hardening script..."
	@if [ -f "hardening.sh" ]; then \
		bash hardening.sh; \
	else \
		echo "Running installed HARDN hardening module..."; \
		bash /usr/share/hardn/modules/hardening.sh; \
	fi
	@echo "Launching HARDN service manager..."
	@if [ "$$HARDN_NO_AUTO_GUI" = "1" ]; then \
		hardn-service-manager; \
	else \
		echo "Attempting to launch HARDN read-only GUI (if available)..."; \
		if command -v hardn-gui >/dev/null 2>&1; then \
			if [ -n "$$SUDO_USER" ]; then \
				runuser -u "$$SUDO_USER" -- nohup hardn-gui >/dev/null 2>&1 & \
			else \
				nohup hardn-gui >/dev/null 2>&1 & \
			fi; \
		fi; \
		hardn-service-manager; \
	fi

# Internal target that does the actual installation work
install-deb-internal:
	@DEB_FILE=$$(find . -name "hardn_*.deb" | head -n1); \
	if [ -z "$$DEB_FILE" ]; then \
		DEB_FILE=$$(find .. -name "hardn_*_$(ARCH).deb" | head -n1); \
	fi; \
	if [ -n "$$DEB_FILE" ]; then \
		dpkg -i "$$DEB_FILE"; \
	else \
		echo "No .deb file found"; exit 1; \
	fi

clean:
	@echo "Setting up Rust environment for cleaning..."
	@HOME=$(HOME_DIR) . $(RUST_ENV_FILE) && rustup default stable
	@echo "Cleaning build artifacts..."
	cargo clean
