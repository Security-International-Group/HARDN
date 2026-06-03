#!/bin/bash
# Enforces the docs hygiene rules established in PR-174 and PR-H:
#   * No em-dashes (—) in README, CHANGELOG, or any docs/*.md
#   * No "AI-tell" adjectives (comprehensive, seamless, robust, delve,
#     leverage, holist*, streamlin*, furthermore, moreover, whilst,
#     "it's worth noting") in any documentation
#   * No AI-vendor strings (claude, anthropic, copilot, openai) anywhere
#     under README / CHANGELOG / docs

set -u

HARDN_TEST_NAME="static/doc-hygiene"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

# Tester-authored bug-report fixtures under docs/tests/ are intentionally
# excluded -- they're field notes, not maintainer prose, and they
# legitimately contain words like "seamless" when describing a tester's
# actual experience.
mapfile -t docs < <(find "$REPO_ROOT/README.md" "$REPO_ROOT/CHANGELOG.md" \
    "$REPO_ROOT/docs" -maxdepth 2 -type f -name '*.md' \
    -not -path "*/docs/tests/*" \
    2>/dev/null | sort)

if [ "${#docs[@]}" -eq 0 ]; then
    tap_plan 1
    tap_skip "no markdown docs found"
    tap_summary
    exit 0
fi

tap_plan 3

# 1) Em-dashes
hits=$(grep -lE '—' "${docs[@]}" 2>/dev/null || true)
if [ -z "$hits" ]; then
    tap_ok "no em-dashes in docs"
else
    tap_not_ok "em-dashes found in docs"
    while IFS= read -r f; do tap_diag "$f"; done <<< "$hits"
fi

# 2) AI-tell adjectives
ai_tells_pattern='\b(comprehensive|seamless|robust|delve|leverage|holist|streamlin|furthermore|moreover|whilst|it.s worth noting)\b'
hits=$(grep -liE "$ai_tells_pattern" "${docs[@]}" 2>/dev/null || true)
if [ -z "$hits" ]; then
    tap_ok "no AI-tell adjectives in docs"
else
    tap_not_ok "AI-tell adjectives found in docs"
    while IFS= read -r f; do
        tap_diag "$f"
        grep -iEn "$ai_tells_pattern" "$f" | head -3 | while IFS= read -r line; do
            tap_diag "  $line"
        done
    done <<< "$hits"
fi

# 3) AI-vendor strings
vendor_pattern='claude|anthropic|copilot|openai'
hits=$(grep -liE "$vendor_pattern" "${docs[@]}" 2>/dev/null || true)
if [ -z "$hits" ]; then
    tap_ok "no AI-vendor strings in docs"
else
    tap_not_ok "AI-vendor strings found in docs"
    while IFS= read -r f; do tap_diag "$f"; done <<< "$hits"
fi

tap_summary
