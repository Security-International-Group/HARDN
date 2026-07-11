#!/bin/bash
# Wraps `cargo test` so its results flow into the same markdown report
# as the rest of the harness. Tests stay where they are (in-file
# #[cfg(test)] modules); this just rolls the totals up.

set -u

HARDN_TEST_NAME="cargo/cargo-test"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd cargo "install rustup and cargo"

cd "$REPO_ROOT"

# Run each binary's tests. cargo doesn't expose JSON output reliably
# across versions, so we parse the human-readable summary.
binaries=(hardn)
tap_plan "${#binaries[@]}"

for bin in "${binaries[@]}"; do
    out=$(cargo test --bin "$bin" --quiet 2>&1)
    ec=$?
    summary=$(printf '%s\n' "$out" | grep -E '^test result:' | tail -1)
    if [ "$ec" -eq 0 ] && printf '%s' "$summary" | grep -q '0 failed'; then
        tap_ok "cargo test --bin $bin: $summary"
    else
        tap_not_ok "cargo test --bin $bin"
        while IFS= read -r line; do tap_diag "$line"; done <<< "$out"
    fi
done

tap_summary
