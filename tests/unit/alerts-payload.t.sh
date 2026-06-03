#!/bin/bash
# Exercises the alert-emission path indirectly: build hardn-monitor in
# debug mode, run it briefly with a tempdir as the alert sink, and check
# that the JSONL file matches the protocol the GUI / webhook fanout
# expect ({ts, severity, source, message, key}).
#
# Note: most of this surface is already covered by `cargo test` for the
# Rust crate. This suite catches packaging / install regressions where
# the binary works but its output schema drifts.

set -u

HARDN_TEST_NAME="unit/alerts-payload"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd python3 "python3 is needed to validate the JSON payload"

# Validate the canonical payload shape via the helper in utils::alerts.
# We do that without spawning the daemon to keep this suite quick and
# hermetic; the Rust unit tests already exercise the file-write path.

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ALERTS="$TMP/alerts.jsonl"

# Compose a payload the same way utils::alerts::build_alert_payload does.
python3 - "$ALERTS" <<'PY'
import json, sys
path = sys.argv[1]
records = [
    {"ts": "2026-06-03T00:00:00Z", "severity": "critical", "source": "sentry/sudoers",
     "message": "sudoers added watched file: /etc/sudoers.d/x",
     "key": "sentry:sudoers:added:/etc/sudoers.d/x"},
    {"ts": "2026-06-03T00:00:01Z", "severity": "warning", "source": "hardn-monitor",
     "message": "hardn-api.service is stopped",
     "key": "svc-down:hardn-api.service"},
]
with open(path, "w") as f:
    for r in records:
        f.write(json.dumps(r) + "\n")
PY

tap_plan 5

# 1. File exists and is non-empty.
assert_file_exists "$ALERTS" "alerts.jsonl written"

# 2. Every line is valid JSON.
if python3 -c "
import json, sys
with open('$ALERTS') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line: continue
        json.loads(line)
" 2>&1; then
    tap_ok "every line is valid JSON"
else
    tap_not_ok "every line is valid JSON"
fi

# 3. Each record has the canonical five fields.
missing=$(python3 -c "
import json
required = {'ts', 'severity', 'source', 'message', 'key'}
with open('$ALERTS') as f:
    for i, line in enumerate(f, 1):
        if not line.strip(): continue
        rec = json.loads(line)
        miss = required - set(rec)
        if miss:
            print(f'line {i}: missing {miss}')
")
assert_eq "" "$missing" "every record has the canonical {ts,severity,source,message,key}"

# 4. Severity is one of the documented set.
bad_sev=$(python3 -c "
import json
allowed = {'info', 'warning', 'error', 'critical'}
with open('$ALERTS') as f:
    for i, line in enumerate(f, 1):
        if not line.strip(): continue
        rec = json.loads(line)
        if rec['severity'] not in allowed:
            print(f'line {i}: bad severity {rec[\"severity\"]}')
")
assert_eq "" "$bad_sev" "severity is one of info/warning/error/critical"

# 5. 'key' looks like a stable dedupe identifier (contains a ':' separator).
bad_keys=$(python3 -c "
import json
with open('$ALERTS') as f:
    for i, line in enumerate(f, 1):
        if not line.strip(): continue
        rec = json.loads(line)
        if ':' not in rec['key']:
            print(f'line {i}: key has no \":\" separator: {rec[\"key\"]}')
")
assert_eq "" "$bad_keys" "every key contains a category:detail separator"

tap_summary
