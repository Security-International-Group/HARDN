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
all: build

# Ensure Rust toolchain is installed and updated
rust-setup:
	@echo "Checking Rust installation..."
	@if ! command -v rustup >/dev/null 2>&1; then \
		echo "Rustup not found. Installing Rust..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		echo "Rust installation completed."; \
	else \
		echo "Rustup found, updating toolchain..."; \
	fi
	@. $(RUST_ENV_FILE) && rustup update stable && rustup default stable

# target: build the Debian package
build: rust-setup package
	@echo "Build process completed successfully."

# HARDN target: build and install HARDN as a service
hardn:
	@echo "Displaying HARDN banner..."
	@rustc banner.rs -o banner_temp && ./banner_temp && rm banner_temp
	@echo "Installing required dependencies..."
	@sudo apt update
	@sudo apt install -y python3-fastapi python3-uvicorn python3-psutil || (sudo apt --fix-broken install -y && sudo apt install -y python3-fastapi python3-uvicorn python3-psutil)
	@echo "Proceeding with installation..."
	@$(MAKE) install-deb
	@echo "Enabling and starting HARDN API server..."
	@sudo systemctl enable hardn-api.service || true
	@sudo systemctl start hardn-api.service || true
	@echo "Running all security modules..."
	@sudo hardn --run-all-modules

package:
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

install-deb:
	@DEB_FILE=$$(find . -name "hardn_*.deb" | head -n1); \
	if [ -z "$$DEB_FILE" ]; then \
		DEB_FILE=$$(find .. -name "hardn_*_$(ARCH).deb" | head -n1); \
	fi; \
	if [ -n "$$DEB_FILE" ]; then \
		sudo dpkg -i "$$DEB_FILE"; \
	else \
		echo "No .deb file found"; exit 1; \
	fi

clean:
	@echo "Setting up Rust environment for cleaning..."
	@HOME=$(HOME_DIR) . $(RUST_ENV_FILE) && rustup default stable
	@echo "Cleaning build artifacts..."
	cargo clean