#!/bin/bash
# Pre-push regression guard: the .deb package must not ship tests/.
#
# The current debian/rules only installs explicitly-listed paths under
# debian/hardn/, so tests/ is implicitly excluded. This suite locks
# that in so a future "just glob everything" edit cannot regress it.
#
# Invariants:
#
#   D1  debian/rules must contain NO mention of the tests/ directory
#       (no 'install tests/...', 'cp -r tests', 'cp tests/').
#
#   D2  debian/rules' override_dh_auto_install target must not use
#       the catch-all './*' or top-level wildcard install patterns
#       that would sweep tests/ in.
#
#   D3  If debian/install or debian/hardn.install ever exists, it
#       must not list tests/ either.
#
#   D4  No .install file under debian/ may reference tests.

set -u

HARDN_TEST_NAME="static/deb-excludes-tests"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

RULES="$REPO_ROOT/debian/rules"
DEB_DIR="$REPO_ROOT/debian"

assert_file_exists "$RULES" "debian/rules ships"

tap_plan 5

# D1: no install command in debian/rules touches tests/.
if grep -nE '(install|cp|rsync)[[:space:]]+[^#]*\btests(/|\b)' "$RULES" | grep -v '^[[:space:]]*#' | head -1 > /tmp/hardn-test-deb-rules-hits.$$; then
    if [ -s /tmp/hardn-test-deb-rules-hits.$$ ]; then
        tap_not_ok "debian/rules must not install or copy tests/"
        sed 's/^/# /' /tmp/hardn-test-deb-rules-hits.$$
    else
        tap_ok "debian/rules has no install or copy command targeting tests/"
    fi
else
    tap_ok "debian/rules has no install or copy command targeting tests/"
fi
rm -f /tmp/hardn-test-deb-rules-hits.$$

# D2: no top-level glob install pattern that would inadvertently include tests/.
if grep -nE '(install|cp)[[:space:]]+[^#]*[[:space:]]\./?\*' "$RULES" | grep -v '^[[:space:]]*#' | head -1 > /tmp/hardn-test-deb-glob-hits.$$; then
    if [ -s /tmp/hardn-test-deb-glob-hits.$$ ]; then
        tap_not_ok "debian/rules has a catch-all './*' install that would include tests/"
        sed 's/^/# /' /tmp/hardn-test-deb-glob-hits.$$
    else
        tap_ok "debian/rules has no catch-all './*' install pattern"
    fi
else
    tap_ok "debian/rules has no catch-all './*' install pattern"
fi
rm -f /tmp/hardn-test-deb-glob-hits.$$

# D3: optional debian/install / debian/hardn.install files must not list tests/.
install_lists_tests=0
for cand in "$DEB_DIR/install" "$DEB_DIR/hardn.install"; do
    if [ -f "$cand" ]; then
        if grep -qE '(^|[[:space:]])tests(/|[[:space:]]|$)' "$cand"; then
            install_lists_tests=1
            tap_diag "$cand lists tests/"
        fi
    fi
done
if [ "$install_lists_tests" -eq 0 ]; then
    tap_ok "no debian/*.install file lists tests/"
else
    tap_not_ok "debian/*.install files must not list tests/"
fi

# D4: any .install file under debian/ must not reference tests.
broad_install_hit=$(grep -lE 'tests' "$DEB_DIR"/*.install 2>/dev/null || true)
if [ -z "$broad_install_hit" ]; then
    tap_ok "no debian/*.install file mentions 'tests'"
else
    tap_not_ok "debian/*.install file(s) mention 'tests': $broad_install_hit"
fi

tap_summary
