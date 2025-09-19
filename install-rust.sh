#!/bin/bash
set -e

echo "Installing Rust..."

# Create a temporary file to export environment variables back to the Makefile
ENV_FILE=$(mktemp)
echo "# Temporary environment file for Rust" > "$ENV_FILE"
echo "ENV_FILE=$ENV_FILE" >> "$ENV_FILE"

# Install Rust using rustup
echo "Installing Rust for current user..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y --no-modify-path --profile minimal

# Source the file if it exists - use absolute path to avoid relative path issues
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
else
    # If the file doesn't exist yet, we'll manually set up the environment
    echo "Cargo env file not found, setting up environment manually"
    export PATH="$HOME/.cargo/bin:$PATH"
    export RUSTUP_HOME="$HOME/.rustup"
    export CARGO_HOME="$HOME/.cargo"
fi

# Use a grouped command with a single redirect for multiple echo commands
{
    echo "export PATH=$HOME/.cargo/bin:\$PATH"
    echo "export RUSTUP_HOME=$HOME/.rustup"
    echo "export CARGO_HOME=$HOME/.cargo"
} >> "$ENV_FILE"

echo "Rust installed successfully."

# Export the PATH for the current session
export PATH="$HOME/.cargo/bin:$PATH"

# Verify installation
if command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    rustc --version
    cargo --version
    echo "Rust installation complete and verified."

    # Print the path to the environment file so the Makefile can find it
    echo "RUST_ENV_FILE=$ENV_FILE"
else
    echo "Error: Rust verification failed after installation."
    exit 1
fi
