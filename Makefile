# Binary and paths
BINARY_NAME=hardn-xdr
BUILD_TARGET=target/release/$(BINARY_NAME)
DEB_DIR=debian
BIN_INSTALL_PATH=usr/bin

# Detect host architecture if not set
ARCH ?= $(shell dpkg --print-architecture)
PREFIX ?= /usr
DESTDIR ?=

# Default target
all: build

build:
	@echo "Building Rust binary (CLI only)..."
	@# Handle Cargo.lock version compatibility issues
	@if [ -f Cargo.lock ] && ! cargo check --locked >/dev/null 2>&1; then \
		echo "[*] Regenerating Cargo.lock for current Cargo version..."; \
		rm -f Cargo.lock; \
	fi
	cargo build --release

run:
	sudo $(BUILD_TARGET)

install-binary:
	mkdir -p $(BIN_INSTALL_PATH)
	cp $(BUILD_TARGET) $(BIN_INSTALL_PATH)/$(BINARY_NAME)
	chmod +x $(BIN_INSTALL_PATH)/$(BINARY_NAME)

install:
	# Binary
	install -D -m 755 $(BUILD_TARGET) $(DESTDIR)$(PREFIX)/bin/$(BINARY_NAME)

	# hardn-api CLI wrapper (if exists)
	@if [ -f usr/bin/hardn-api ]; then \
		install -D -m 755 usr/bin/hardn-api $(DESTDIR)$(PREFIX)/bin/hardn-api; \
	fi

	# Man page (if exists)
	@if [ -f hardn.1 ]; then \
		install -D -m 644 hardn.1 $(DESTDIR)$(PREFIX)/share/man/man1/hardn-xdr.1; \
	fi

	# Modules (if exists)
	@if [ -d usr/share/hardn/modules ]; then \
		install -d $(DESTDIR)$(PREFIX)/share/hardn/modules; \
		install -m 644 usr/share/hardn/modules/*.sh $(DESTDIR)$(PREFIX)/share/hardn/modules/; \
	fi

	# Templates (if exists)
	@if [ -d usr/share/hardn/templates ]; then \
		install -d $(DESTDIR)$(PREFIX)/share/hardn/templates; \
		install -m 644 usr/share/hardn/templates/* $(DESTDIR)$(PREFIX)/share/hardn/templates/; \
	fi

	# Backend API (if exists)
	@if [ -f usr/share/hardn/hardn-api.py ]; then \
		install -D -m 755 usr/share/hardn/hardn-api.py $(DESTDIR)$(PREFIX)/share/hardn/hardn-api.py; \
	fi

	# Tools (if exists)
	@if [ -d usr/share/hardn/tools ]; then \
		cp -a usr/share/hardn/tools $(DESTDIR)$(PREFIX)/share/hardn/; \
		find $(DESTDIR)$(PREFIX)/share/hardn/tools -name "*.sh" -exec chmod 755 {} \;; \
	fi

	# Docs (if exists)
	@if [ -f README.md ]; then \
		install -d $(DESTDIR)$(PREFIX)/share/doc/hardn-xdr; \
		install -m 644 README.md $(DESTDIR)$(PREFIX)/share/doc/hardn-xdr/; \
	fi
	@if [ -d docs ]; then \
		install -d $(DESTDIR)$(PREFIX)/share/doc/hardn-xdr; \
		install -m 644 docs/*.md $(DESTDIR)$(PREFIX)/share/doc/hardn-xdr/ 2>/dev/null || true; \
	fi

	# Systemd (if exists)
	@if [ -d systemd ]; then \
		install -d $(DESTDIR)/lib/systemd/system; \
		install -m 644 systemd/*.service $(DESTDIR)/lib/systemd/system/; \
	fi

	# Config and runtime directories
	install -d $(DESTDIR)/etc/hardn
	install -d $(DESTDIR)/var/log/hardn
	install -d $(DESTDIR)/var/lib/hardn/backups

package: build
	@echo "Building .deb package..."
	dpkg-buildpackage -us -uc -b
	# Move .deb file to current directory for easier CI access
	@echo "Moving .deb file to current directory..."
	@DEB_FILE=$$(find .. -name "hardn-xdr_*.deb" | head -n1); \
	if [ -n "$$DEB_FILE" ]; then \
		mv "$$DEB_FILE" . && echo "Moved $$DEB_FILE to current directory"; \
	else \
		echo "Warning: No .deb file found to move"; \
	fi

install-deb:
	@DEB_FILE=$$(find . -name "hardn-xdr_*.deb" | head -n1); \
	if [ -z "$$DEB_FILE" ]; then \
		DEB_FILE=$$(find .. -name "hardn-xdr_*_$(ARCH).deb" | head -n1); \
	fi; \
	if [ -n "$$DEB_FILE" ]; then \
		sudo dpkg -i "$$DEB_FILE"; \
	else \
		echo "No .deb file found"; exit 1; \
	fi

lint:
	@DEB_FILE=$$(find . -name "hardn-xdr_*.deb" | head -n1); \
	if [ -z "$$DEB_FILE" ]; then \
		DEB_FILE=$$(find .. -name "hardn-xdr_*_$(ARCH).deb" | head -n1); \
	fi; \
	if [ -n "$$DEB_FILE" ]; then \
		lintian "$$DEB_FILE" || true; \
	else \
		echo "No .deb file found for linting"; \
	fi

clean:
	cargo clean
	rm -f hardn-xdr_*_*.deb
	rm -f ../hardn-xdr_*_*.deb

# Test the build
test-build:
	@echo "Testing Cargo build..."
	cargo check
	cargo build --release

.PHONY: all build run install-binary install package install-deb lint clean test-build
