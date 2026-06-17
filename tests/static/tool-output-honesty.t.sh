#!/bin/bash
# Pre-push regression guards for the tool-output-honesty fixes triggered
# by the dev_testing screenshots from Orinax on 2026-06-13.
#
# Three invariants this suite locks in:
#
#   T1  src/main.rs::get_security_tools() must not contain any obvious
#       service_name typos. We diff its service_name strings against the
#       known-good list in src/setup/main.rs (which has the same table).
#       If they drift, this fails fast at pre-push time.
#
#   T2  usr/share/hardn/tools/functions.sh::service_exists must use the
#       systemctl show / LoadState approach, not the brittle
#       'list-unit-files | grep' pattern that lags right after apt
#       install.
#
#   T3  Neither src/execution/runner.rs nor src/main.rs nor
#       src/setup/main.rs may print "completed successfully" as a Pass
#       message on a tool run, because exit 0 does not imply the tool
#       was warning-free.

set -u

HARDN_TEST_NAME="static/tool-output-honesty"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

MAIN_RS="$REPO_ROOT/src/main.rs"
SETUP_RS="$REPO_ROOT/src/setup/main.rs"
RUNNER_RS="$REPO_ROOT/src/execution/runner.rs"
FUNCTIONS_SH="$REPO_ROOT/usr/share/hardn/tools/functions.sh"

assert_file_exists "$MAIN_RS"      "src/main.rs ships"
assert_file_exists "$SETUP_RS"     "src/setup/main.rs ships"
assert_file_exists "$RUNNER_RS"    "src/execution/runner.rs ships"
assert_file_exists "$FUNCTIONS_SH" "tools/functions.sh ships"

tap_plan 11

# T1: extract service_name values from main.rs vs setup/main.rs and
# require both lists to agree. This catches typos like clamv-daemon
# vs clamav-daemon. We rely on POSIX grep -oE instead of GNU awk match()
# so the suite stays portable across the runners we ship to.
extract_service_names() {
    local file="$1"
    grep -oE 'service_name:[[:space:]]*"[^"]+"' "$file" \
        | sed -E 's/service_name:[[:space:]]*"([^"]+)"/\1/' \
        | sort -u
}

main_names=$(extract_service_names "$MAIN_RS")
setup_names=$(extract_service_names "$SETUP_RS")

if [ "$main_names" = "$setup_names" ]; then
    tap_ok "service_name lists agree across src/main.rs and src/setup/main.rs"
else
    tap_not_ok "service_name lists drifted between src/main.rs and src/setup/main.rs"
    tap_diag "Drift detected. Lines unique to one or the other below."
    diff <(printf '%s\n' "$main_names") <(printf '%s\n' "$setup_names") | while IFS= read -r line; do
        tap_diag "  $line"
    done
fi

# T1 sanity: known systemd unit names for the packages we ship.
#
# Every entry here MUST have a real systemd unit AND be installable on
# Debian/Ubuntu. We also include the units that ship via HARDN's own
# observability stack (grafana-server, prometheus, prometheus-node-exporter).
# When a future tool gets a sh script under usr/share/hardn/tools/ but
# its service does not land in this Status list, operators see "13 tools
# in Run menu but only 9 in Status" drift and lose visibility into what
# is and isn't running. Caught here at pre-push time.
for needle in \
    "clamav-daemon" \
    "fail2ban" \
    "ufw" \
    "auditd" \
    "suricata" \
    "grafana-server" \
    "prometheus" \
    "prometheus-node-exporter" \
; do
    if printf '%s\n' "$main_names" | grep -qxF "$needle"; then
        tap_ok "src/main.rs lists $needle as a security tool service_name"
    else
        tap_not_ok "src/main.rs lists $needle as a security tool service_name"
        tap_diag "Saw service_names: $main_names"
    fi
done

# T2: service_exists must use the LoadState approach. The pre-fix code
# pattern was 'list-unit-files | grep'; new code uses
# 'systemctl show ... --property=LoadState'.
if grep -qE 'systemctl[[:space:]]+show.*LoadState' "$FUNCTIONS_SH"; then
    tap_ok "service_exists uses systemctl show LoadState (robust)"
else
    tap_not_ok "service_exists must use 'systemctl show ... LoadState'"
    tap_diag "Old pattern grepped list-unit-files which lags after apt install."
fi

# T3: no "completed successfully" Pass message on tool runs.
found_pattern=$(
    grep -nE 'completed successfully' "$RUNNER_RS" "$MAIN_RS" "$SETUP_RS" 2>/dev/null \
        | grep -iE 'tool|kind|LogLevel::Pass' || true
)
if [ -z "$found_pattern" ]; then
    tap_ok "no 'tool completed successfully' Pass messages on tool runs"
else
    tap_not_ok "found 'completed successfully' Pass message on a tool run"
    while IFS= read -r line; do tap_diag "$line"; done <<< "$found_pattern"
fi

tap_summary
