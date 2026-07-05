#!/bin/bash
# Pre-push regression guard: the Rust toolchain is pinned and CI honors it.
#
# main went red twice from the same root cause: GitHub runners track the
# latest stable Rust, so a new clippy/rustc release flags code that was
# green on an older compiler, with no code change on our side. The fix
# was rust-toolchain.toml pinning an exact channel. This guard keeps the
# pin in place AND keeps every Rust-building workflow honoring it instead
# of hardcoding a floating 'stable'.
#
# Invariants:
#
#   P1  rust-toolchain.toml exists and pins an exact channel
#       (channel = "X.Y.Z"), not a floating stream like "stable".
#
#   P2  It declares the rustfmt and clippy components, so the pinned
#       toolchain can run 'cargo fmt --check' and 'cargo clippy'.
#
#   P3  No workflow passes 'toolchain: stable' (or any floating stream)
#       to a rust-toolchain setup action. A floating toolchain input
#       overrides rust-toolchain.toml and reintroduces the drift.

set -u

HARDN_TEST_NAME="static/toolchain-pin"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

TOOLCHAIN_TOML="$REPO_ROOT/rust-toolchain.toml"
WORKFLOWS_DIR="$REPO_ROOT/.github/workflows"

assert_file_exists "$TOOLCHAIN_TOML" "rust-toolchain.toml ships"

tap_plan 4

# P1: exact channel pin.
channel=$(grep -oE 'channel[[:space:]]*=[[:space:]]*"[^"]+"' "$TOOLCHAIN_TOML" 2>/dev/null \
    | sed -E 's/.*"([^"]+)".*/\1/')
if printf '%s' "$channel" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    tap_ok "rust-toolchain.toml pins an exact channel ($channel)"
else
    tap_not_ok "rust-toolchain.toml must pin an exact channel like \"1.96.0\""
    tap_diag "channel found: '${channel:-<none>}'"
fi

# P2: rustfmt + clippy components declared.
if grep -q 'rustfmt' "$TOOLCHAIN_TOML" && grep -q 'clippy' "$TOOLCHAIN_TOML"; then
    tap_ok "rust-toolchain.toml declares rustfmt and clippy components"
else
    tap_not_ok "rust-toolchain.toml must list rustfmt and clippy in components"
fi

# P3: no workflow hardcodes a floating toolchain input.
# Match 'toolchain: stable|beta|nightly' (with optional quotes) on a
# workflow line. An exact version pin as a toolchain input is allowed
# (it does not drift), so we only flag the floating streams.
floating=$(grep -RnE 'toolchain:[[:space:]]*["'\'']?(stable|beta|nightly)["'\'']?[[:space:]]*$' "$WORKFLOWS_DIR" 2>/dev/null || true)
if [ -z "$floating" ]; then
    tap_ok "no workflow passes a floating 'toolchain: stable/beta/nightly' input"
else
    tap_not_ok "a workflow hardcodes a floating toolchain, overriding the pin"
    printf '%s\n' "$floating" | sed 's/^/# /'
fi

# P3b: at least one workflow builds Rust honoring the pin (setup action
# with no toolchain input, or a version-pinned one). We assert the
# setup-rust-toolchain action appears at least once, since that is the
# action that reads rust-toolchain.toml.
if grep -RqE 'actions-rust-lang/setup-rust-toolchain' "$WORKFLOWS_DIR" 2>/dev/null; then
    tap_ok "a workflow uses setup-rust-toolchain (honors rust-toolchain.toml)"
else
    tap_not_ok "expected setup-rust-toolchain in at least one workflow"
fi

tap_summary
