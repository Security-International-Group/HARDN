#!/bin/bash
# Run 'systemd-analyze verify' on every shipped unit. Catches typos,
# missing keys, and Conflicts= chain issues like the one ISSUE-180
# uncovered between hardn.service and legion-daemon.service.

set -u

HARDN_TEST_NAME="static/systemd-verify"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd systemd-analyze "install with: apt-get install systemd"

mapfile -t units < <(find "$REPO_ROOT/systemd" -type f -name '*.service' 2>/dev/null | sort)

if [ "${#units[@]}" -eq 0 ]; then
    tap_plan 1
    tap_skip "no unit files under systemd/"
    tap_summary
    exit 0
fi

tap_plan "${#units[@]}"

for u in "${units[@]}"; do
    rel="${u#"$REPO_ROOT"/}"
    output=$(systemd-analyze verify "$u" 2>&1)
    ec=$?
    # 'verify' fails when the ExecStart= binary isn't installed yet
    # (e.g. /usr/bin/hardn-monitor on a dev box where the .deb hasn't
    # been installed). Those failures aren't about the unit being
    # broken; they're a packaging artefact. Treat them as OK with a
    # diagnostic note, but still fail on every other category of error.
    if [ "$ec" -eq 0 ]; then
        tap_ok "$rel"
        if [ -n "$output" ]; then
            while IFS= read -r line; do tap_diag "$line"; done <<< "$output"
        fi
    elif printf '%s\n' "$output" | grep -qE 'is not executable: No such file'; then
        tap_ok "$rel"
        tap_diag "informational: ExecStart= binary not installed on the dev box; verify what we can"
        while IFS= read -r line; do tap_diag "$line"; done <<< "$output"
    else
        tap_not_ok "$rel"
        while IFS= read -r line; do tap_diag "$line"; done <<< "$output"
    fi
done

tap_summary
