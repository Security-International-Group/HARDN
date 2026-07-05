#!/bin/bash
# Pre-push regression guards for supply-chain scanning in CI.
#
# The senior-engineer audit flagged that nothing in CI checks the
# dependency tree for known CVEs (cargo audit) or for banned crates,
# license violations, and untrusted sources (cargo deny). Dependabot
# opens update PRs but never blocks a merge that carries a
# known-vulnerable crate. For a security hardening product that gap
# is below the bar. This suite locks the scanning in.
#
# Invariants:
#
#   S1  At least one workflow runs 'cargo audit'.
#
#   S2  At least one workflow runs 'cargo deny check'.
#
#   S3  deny.toml exists at the repo root and configures the four
#       cargo-deny check families: advisories, bans, licenses,
#       sources.
#
#   S4  Neither scanner is silenced: no 'cargo audit ... || true',
#       no 'cargo deny ... || true', and no continue-on-error in the
#       supply-chain workflow.

set -u

HARDN_TEST_NAME="static/supply-chain-ci"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

WORKFLOWS_DIR="$REPO_ROOT/.github/workflows"
DENY_TOML="$REPO_ROOT/deny.toml"

assert_file_exists "$WORKFLOWS_DIR" ".github/workflows/ exists"

tap_plan 8

# S1: cargo audit wired into a workflow.
if grep -RnE 'cargo[[:space:]]+audit' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_ok "a workflow runs 'cargo audit'"
else
    tap_not_ok "at least one workflow must run 'cargo audit'"
fi

# S2: cargo deny wired into a workflow.
if grep -RnE 'cargo[[:space:]]+deny[[:space:]]+check' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_ok "a workflow runs 'cargo deny check'"
else
    tap_not_ok "at least one workflow must run 'cargo deny check'"
fi

# S3: deny.toml present with the four check families.
if [ -f "$DENY_TOML" ]; then
    tap_ok "deny.toml exists at the repo root"
else
    tap_not_ok "deny.toml must exist at the repo root"
fi

for section in advisories bans licenses sources; do
    if [ -f "$DENY_TOML" ] && grep -qE "^\[$section\]" "$DENY_TOML"; then
        tap_ok "deny.toml configures [$section]"
    else
        tap_not_ok "deny.toml must configure [$section]"
    fi
done

# S4: scanners are not silenced.
silenced=$(grep -RnE 'cargo[[:space:]]+(audit|deny)[^#]*\|\|[[:space:]]+true' "$WORKFLOWS_DIR" 2>/dev/null || true)
if [ -z "$silenced" ]; then
    tap_ok "no workflow silences cargo audit / cargo deny with '|| true'"
else
    tap_not_ok "cargo audit / cargo deny must not be silenced with '|| true'"
    printf '%s\n' "$silenced" | sed 's/^/# /'
fi

tap_summary
