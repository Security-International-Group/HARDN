#!/bin/bash
# Pre-push regression guard: the Metrics workflow stays removed.
#
# History: .github/workflows/metrics.yml ran lowlighter/metrics on a
# daily cron. The action authenticates against the GitHub GraphQL API
# and fine-grained PATs cannot satisfy those queries, and the org
# cannot mint a usable classic PAT for this. Result: the workflow
# failed every scheduled run and painted a red X on main daily. The
# removal commit was lost once before when the branch carrying it was
# deleted ahead of merge, so this guard makes the removal an invariant
# the harness enforces.
#
# Invariants:
#
#   R1  .github/workflows/ contains no metrics workflow file.
#
#   R2  No workflow file references lowlighter/metrics or the
#       METRICS_TOKEN secret.
#
#   R3  README.md does not reference .github/metrics.svg (the image
#       the removed workflow used to generate; a dangling reference
#       renders as a broken image on the repo page).

set -u

HARDN_TEST_NAME="static/no-metrics-workflow"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

WORKFLOWS_DIR="$REPO_ROOT/.github/workflows"
README="$REPO_ROOT/README.md"

assert_file_exists "$WORKFLOWS_DIR" ".github/workflows/ exists"
assert_file_exists "$README"        "README.md exists"

tap_plan 4

# R1: no metrics workflow file.
if compgen -G "$WORKFLOWS_DIR/metrics*" >/dev/null 2>&1; then
    tap_not_ok ".github/workflows/ must not contain a metrics workflow"
    ls "$WORKFLOWS_DIR"/metrics* | sed 's/^/# /'
else
    tap_ok ".github/workflows/ contains no metrics workflow file"
fi

# R2a: no workflow references lowlighter/metrics.
if grep -RnE 'lowlighter/metrics' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_not_ok "no workflow may reference lowlighter/metrics"
    grep -RnE 'lowlighter/metrics' "$WORKFLOWS_DIR" | sed 's/^/# /'
else
    tap_ok "no workflow references lowlighter/metrics"
fi

# R2b: no workflow references the METRICS_TOKEN secret.
if grep -RnE 'METRICS_TOKEN' "$WORKFLOWS_DIR" >/dev/null 2>&1; then
    tap_not_ok "no workflow may reference the METRICS_TOKEN secret"
    grep -RnE 'METRICS_TOKEN' "$WORKFLOWS_DIR" | sed 's/^/# /'
else
    tap_ok "no workflow references METRICS_TOKEN"
fi

# R3: README has no dangling metrics.svg reference.
if grep -nE 'metrics\.svg' "$README" >/dev/null 2>&1; then
    tap_not_ok "README.md must not reference metrics.svg"
    grep -nE 'metrics\.svg' "$README" | sed 's/^/# /'
else
    tap_ok "README.md does not reference metrics.svg"
fi

tap_summary
