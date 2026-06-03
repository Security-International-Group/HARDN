#!/bin/bash
# End-to-end SENTRY flow:
#   1. Build hardn.
#   2. Point baseline + alert files at a tempdir.
#   3. First run: silently writes baseline, no alert.
#   4. Create a fake watched file under /etc/cron.d/.
#   5. Second run: emits a 'warning' alert into alerts.jsonl with
#      source=sentry/cron and verb=added in the key.
#
# Limitation: SENTRY's watch list is hard-coded to /etc/cron.d/* etc. so
# this test needs write access there. We skip cleanly when it's read-only
# (containers without --privileged).

set -u

HARDN_TEST_NAME="integration/sentry-flow"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd cargo "install rustup and cargo"

cd "$REPO_ROOT"

if ! cargo build --bin hardn --quiet 2>/dev/null; then
    tap_plan 1
    tap_not_ok "cargo build --bin hardn failed"
    tap_summary
    exit 1
fi

BIN="$REPO_ROOT/target/debug/hardn"

# Need write access to /etc/cron.d/ to create the drift target.
if ! touch /etc/cron.d/.hardn-test-write-probe 2>/dev/null; then
    tap_plan 1
    tap_skip "/etc/cron.d is not writable in this environment"
    tap_summary
    exit 0
fi
rm -f /etc/cron.d/.hardn-test-write-probe

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; rm -f /etc/cron.d/hardn-sentry-test-XYZ' EXIT

ALERTS="$TMP/alerts.jsonl"
SEEN="$TMP/seen.json"
# Override the alert sink + dedupe path so we read a known file.
export HARDN_ALERT_DEDUPE_PATH="$SEEN"

# SENTRY uses /var/lib/hardn/sentry/baseline.json by default. We can't
# easily redirect it without a code change, so we accept that the test
# writes there and clean up.
SENTRY_BASELINE="/var/lib/hardn/sentry/baseline.json"
mkdir -p "$(dirname "$SENTRY_BASELINE")"
# Snapshot any pre-existing baseline so we can restore it.
[ -f "$SENTRY_BASELINE" ] && cp "$SENTRY_BASELINE" "$TMP/baseline.before.json"
rm -f "$SENTRY_BASELINE"

tap_plan 4

# 1. First run: baseline created, no alert.
# Redirect alerts.jsonl by overriding the default path. We don't have an
# env knob for /var/log/hardn/alerts.jsonl in the Rust code, so instead
# snapshot the file size before/after.
HARDN_ALERTS="/var/log/hardn/alerts.jsonl"
mkdir -p /var/log/hardn
[ -f "$HARDN_ALERTS" ] || : > "$HARDN_ALERTS"
size_before=$(wc -c < "$HARDN_ALERTS")

out=$("$BIN" --sentry-check 2>&1)
ec=$?
assert_eq "0" "$ec" "first --sentry-check run exits 0"
assert_contains "$out" "baseline created" "first run announces baseline creation"

# 2. Mutate /etc/cron.d/ with a fake file.
DRIFT="/etc/cron.d/hardn-sentry-test-XYZ"
echo "* * * * * root /bin/true" > "$DRIFT"

# 3. Second run: should add an alert.
out=$("$BIN" --sentry-check 2>&1)
ec=$?
assert_eq "0" "$ec" "second --sentry-check run exits 0"

size_after=$(wc -c < "$HARDN_ALERTS")
# A new line should have been appended.
if [ "$size_after" -gt "$size_before" ]; then
    # Verify the new line(s) contain our path.
    new_lines=$(tail -c $((size_after - size_before)) "$HARDN_ALERTS")
    if printf '%s' "$new_lines" | grep -q "hardn-sentry-test-XYZ"; then
        tap_ok "drift produces an alert mentioning the new path"
    else
        tap_not_ok "drift produces an alert mentioning the new path"
        tap_diag "new alerts.jsonl content: $new_lines"
    fi
else
    tap_not_ok "drift produces an alert mentioning the new path"
    tap_diag "alerts.jsonl did not grow (size before/after: $size_before / $size_after)"
fi

# Restore pre-existing baseline if there was one.
if [ -f "$TMP/baseline.before.json" ]; then
    cp "$TMP/baseline.before.json" "$SENTRY_BASELINE"
else
    rm -f "$SENTRY_BASELINE"
fi

tap_summary
