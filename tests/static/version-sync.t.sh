#!/bin/bash
# Pre-push regression guard: version numbers must agree.
#
# The audit found Cargo.toml at 1.2.92 while debian/changelog's head
# entry was 1.1.0-1. Those are the project's two version sources and
# they feed different surfaces:
#
#   - Cargo.toml drives 'hardn --version' (env!("CARGO_PKG_VERSION"))
#   - debian/changelog drives the .deb Version field, which ci.yml
#     reads with 'dpkg-deb -f' to mint the release tag
#
# When they disagree, 'dpkg -l' and 'hardn --version' report
# different numbers on the same box and release tags stop matching
# the binary. This guard fails the harness whenever they drift.
#
# Invariants:
#
#   V1  debian/changelog's head entry parses as
#       'hardn (<version>) <dist>; urgency=<level>'
#
#   V2  The upstream part of that version (before the last '-')
#       equals the [package] version in Cargo.toml.

set -u

HARDN_TEST_NAME="static/version-sync"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

CARGO_TOML="$REPO_ROOT/Cargo.toml"
DEB_CHANGELOG="$REPO_ROOT/debian/changelog"

assert_file_exists "$CARGO_TOML"    "Cargo.toml ships"
assert_file_exists "$DEB_CHANGELOG" "debian/changelog ships"

tap_plan 3

cargo_version=$(grep -m1 -E '^version[[:space:]]*=' "$CARGO_TOML" \
    | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')

head_line=$(head -n1 "$DEB_CHANGELOG")

# V1: head entry parses.
if printf '%s\n' "$head_line" | grep -qE '^hardn \([0-9][^)]*\) [a-z]+; urgency='; then
    tap_ok "debian/changelog head entry parses: $head_line"
else
    tap_not_ok "debian/changelog head entry must parse as 'hardn (<version>) <dist>; urgency=...'"
    tap_diag "got: $head_line"
fi

deb_version=$(printf '%s\n' "$head_line" | sed -E 's/^hardn \(([^)]+)\).*/\1/')
deb_upstream="${deb_version%-*}"

# V2: upstream part matches Cargo.toml.
if [ -n "$cargo_version" ] && [ "$cargo_version" = "$deb_upstream" ]; then
    tap_ok "Cargo.toml ($cargo_version) matches debian/changelog upstream ($deb_upstream)"
else
    tap_not_ok "Cargo.toml version must match debian/changelog upstream version"
    tap_diag "Cargo.toml:        $cargo_version"
    tap_diag "debian/changelog:  $deb_version (upstream part: $deb_upstream)"
    tap_diag "Fix: add a new debian/changelog entry for $cargo_version-1, or bump Cargo.toml."
fi

# V3: the debian revision is present (a bare upstream version in the
# changelog builds a .deb whose Version field has no revision, which
# breaks upgrade ordering between rebuilds of the same upstream).
if printf '%s\n' "$deb_version" | grep -qE -- '-[0-9]+$'; then
    tap_ok "debian/changelog version carries a debian revision ($deb_version)"
else
    tap_not_ok "debian/changelog version must carry a debian revision (e.g. ${cargo_version}-1)"
    tap_diag "got: $deb_version"
fi

tap_summary
