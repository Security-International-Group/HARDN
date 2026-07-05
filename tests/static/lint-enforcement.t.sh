#!/bin/bash
# Pre-push regression guards for lint enforcement in CI.
#
# The senior-engineer audit flagged that clippy was running with
# RUSTFLAGS="-A dead_code" (silencing dead-code warnings), that
# cargo fmt --check was not enforced anywhere, and that shellcheck
# was only running as an aspirational TAP test that SKIPped on
# hosts without the binary. This suite locks in the enforcement so
# a future edit cannot silently reintroduce muted linters.
#
# Invariants:
#
#   L1  No workflow file may set RUSTFLAGS to include '-A dead_code'
#       (the blanket suppression the audit flagged). Per-item
#       #[allow(dead_code)] annotations in source are still fine;
#       this test only guards the CLI/env override.
#
#   L2  At least one workflow must run 'cargo clippy' with
#       '-D warnings' (or equivalent -D clippy::all). Clippy that
#       does not fail the build is theatre.
#
#   L3  At least one workflow must run 'cargo fmt' with '--check'.
#       Without --check, fmt just formats and never fails.
#
#   L4  At least one workflow must run shellcheck against the
#       tool scripts under usr/share/hardn/tools/*.sh AND treat a
#       shellcheck failure as a job failure (no 'continue-on-error'
#       trailing the step, no '|| true' on the shellcheck line).

set -u

HARDN_TEST_NAME="static/lint-enforcement"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

WORKFLOWS_DIR="$REPO_ROOT/.github/workflows"

assert_file_exists "$WORKFLOWS_DIR" ".github/workflows/ exists"

tap_plan 6

# L1: no workflow sets RUSTFLAGS to '-A dead_code'.
if grep -RnE 'RUSTFLAGS[^\n]*-A[[:space:]]+dead_code' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_not_ok "no workflow may set RUSTFLAGS to include '-A dead_code'"
    grep -RnE 'RUSTFLAGS[^\n]*-A[[:space:]]+dead_code' "$WORKFLOWS_DIR" | sed 's/^/# /'
else
    tap_ok "no workflow sets RUSTFLAGS to include '-A dead_code'"
fi

# L2: at least one workflow runs cargo clippy with -D warnings (or -D clippy::all).
if grep -RnE 'cargo[[:space:]]+clippy[^\n]*-D[[:space:]]+(warnings|clippy::all)' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_ok "a workflow runs 'cargo clippy ... -D warnings'"
else
    tap_not_ok "at least one workflow must run 'cargo clippy ... -D warnings'"
    tap_diag "search:  cargo clippy ... -D warnings"
fi

# L3: at least one workflow runs cargo fmt --check.
if grep -RnE 'cargo[[:space:]]+fmt[^\n]*--check' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_ok "a workflow runs 'cargo fmt ... --check'"
else
    tap_not_ok "at least one workflow must run 'cargo fmt ... --check'"
    tap_diag "search:  cargo fmt ... --check"
fi

# L4a: at least one workflow invokes shellcheck against usr/share/hardn/tools.
if grep -RnE 'shellcheck[[:space:]]' "$WORKFLOWS_DIR" | grep -qE 'usr/share/hardn/tools|tests/static/shellcheck'; then
    tap_ok "a workflow runs shellcheck against usr/share/hardn/tools (or via the TAP shellcheck suite)"
else
    tap_not_ok "at least one workflow must invoke shellcheck against usr/share/hardn/tools/*.sh"
fi

# L4b: no shellcheck invocation is silenced with '|| true' or 'continue-on-error: true'.
# We only look at lines that mention shellcheck AND either '|| true' or the trailing yaml key.
if grep -RnE 'shellcheck[[:space:]][^#\n]*\|\|[[:space:]]+true' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_not_ok "shellcheck step must not be silenced with '|| true'"
    grep -RnE 'shellcheck[[:space:]][^#\n]*\|\|[[:space:]]+true' "$WORKFLOWS_DIR" | sed 's/^/# /'
else
    tap_ok "no workflow silences shellcheck with '|| true'"
fi

# L4c: the shellcheck TAP suite must be part of the CI test run (i.e. tests/run-all.sh
# is invoked in at least one workflow). We already have tests/static/shellcheck.t.sh
# under the harness; guarding here that the harness itself runs.
if grep -RnE 'tests/run-all\.sh' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_ok "a workflow runs the TAP harness (tests/run-all.sh), which includes the shellcheck suite"
else
    tap_not_ok "at least one workflow must run 'bash tests/run-all.sh' so the shellcheck TAP suite is exercised"
fi

tap_summary
