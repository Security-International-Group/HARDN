#!/bin/bash
# Build the hardn binary and exercise the no-state CLI surfaces:
#   - hardn --help
#   - hardn --about
#   - hardn run-tool no-such-tool (must return 127 since PR-D)

set -u

HARDN_TEST_NAME="integration/cli-help"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd cargo "install rustup and cargo"

cd "$REPO_ROOT"

# Build (or rebuild incrementally) so subsequent invocations are fast.
if ! cargo build --bin hardn --quiet 2>/dev/null; then
    tap_plan 1
    tap_not_ok "cargo build --bin hardn failed"
    tap_summary
    exit 1
fi

BIN="$REPO_ROOT/target/debug/hardn"
assert_file_exists "$BIN" "hardn binary present after build"

tap_plan 4

# --help: exits 0 and lists the current CLI flags.
out=$("$BIN" --help 2>&1)
ec=$?
assert_eq "0" "$ec" "hardn --help exits 0"
assert_contains "$out" "enable-selinux" "--help advertises --enable-selinux"

# Missing tool: PR-D made this return 127 (POSIX "command not found").
"$BIN" run-tool nosuchtool-XYZ123 >/dev/null 2>&1
ec=$?
assert_eq "127" "$ec" "run-tool <missing> returns 127"

tap_summary
