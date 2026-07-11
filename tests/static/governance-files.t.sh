#!/bin/bash
# Pre-push regression guards for repository governance files.
#
# The audit flagged a one-line CODEOWNERS (single owner for the whole
# tree, no subsystem accountability) and no PR template. This suite
# locks in subsystem-level ownership and the template so a reviewer
# trail exists for each area of the codebase.
#
# Invariants:
#
#   G1  .github/CODEOWNERS assigns an owner to each first-party
#       subsystem: the tool scripts, debian packaging, and the CI
#       workflows. A single catch-all line is not enough.
#
#   G2  A PR template exists at one of the standard locations and
#       carries the sections a reviewer needs (Summary, testing).

set -u

HARDN_TEST_NAME="static/governance-files"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

CODEOWNERS="$REPO_ROOT/.github/CODEOWNERS"

assert_file_exists "$CODEOWNERS" ".github/CODEOWNERS ships"

tap_plan 6

# G1: each subsystem path must appear as a CODEOWNERS pattern with an
# @owner on the same line. We match the leading path token, then require
# an @ later on the line.
owner_for() {
    local pat="$1"
    grep -E "^[[:space:]]*${pat}[[:space:]].*@" "$CODEOWNERS" >/dev/null 2>&1
}

for entry in \
    "usr/share/hardn/tools/:tool scripts" \
    "debian/:packaging" \
    ".github/:CI workflows" \
; do
    pat="${entry%%:*}"
    label="${entry##*:}"
    # Escape regex metacharacters in the path for grep -E.
    esc=$(printf '%s' "$pat" | sed -E 's/[.[\*^$()+?{}|]/\\&/g')
    if owner_for "$esc"; then
        tap_ok "CODEOWNERS assigns an owner to $label ($pat)"
    else
        tap_not_ok "CODEOWNERS must assign an owner to $label ($pat)"
    fi
done

# G1b: a catch-all default line must still exist as a backstop.
if grep -E '^\*[[:space:]].*@' "$CODEOWNERS" >/dev/null 2>&1; then
    tap_ok "CODEOWNERS keeps a catch-all default owner line"
else
    tap_not_ok "CODEOWNERS must keep a catch-all '*' default owner line"
fi

# G2: PR template exists at a standard location.
pr_template=""
for cand in \
    "$REPO_ROOT/.github/PULL_REQUEST_TEMPLATE.md" \
    "$REPO_ROOT/.github/pull_request_template.md" \
    "$REPO_ROOT/PULL_REQUEST_TEMPLATE.md" \
    "$REPO_ROOT/docs/PULL_REQUEST_TEMPLATE.md" \
; do
    if [ -f "$cand" ]; then
        pr_template="$cand"
        break
    fi
done

if [ -n "$pr_template" ]; then
    tap_ok "a PR template exists (${pr_template#"$REPO_ROOT"/})"
else
    tap_not_ok "a PR template must exist at .github/PULL_REQUEST_TEMPLATE.md"
fi

# G2b: template carries a Summary and a testing section.
if [ -n "$pr_template" ] \
   && grep -qiE '## +summary' "$pr_template" \
   && grep -qiE 'test' "$pr_template"; then
    tap_ok "PR template has a Summary section and asks about testing"
else
    tap_not_ok "PR template must include a Summary section and a testing prompt"
fi

tap_summary
