#!/bin/bash
# Pre-push regression guard for the P0 LEGION risk-score renormalization.
#
# Invariants this suite locks in:
#
#   W1  src/legion/modules/risk_scoring.rs:RiskWeights::default's
#       eight weight fields must sum to 1.0 (with a small floating
#       point epsilon). If a future edit adds or removes a weight
#       without renormalizing, the formula stops behaving like a
#       weighted average and the risk score becomes meaningless.
#
#   W2  network_weight AND file_integrity_weight must be 0.0. The
#       collectors that would feed those inputs are not wired yet
#       (src/legion/core/legion.rs hardcodes the inputs to 0.0).
#       If either weight goes non-zero before the collectors land
#       the formula goes back to diluting real signal.
#
#   W3  src/legion/core/legion.rs still pins network_score and
#       file_integrity_score to 0.0 so the W2 weight pin remains
#       the right call. If a future commit wires real collectors
#       it must update both files at once and W1/W2 break at that
#       point on purpose.

set -u

HARDN_TEST_NAME="static/risk-weights-sum-to-one"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

WEIGHTS_RS="$REPO_ROOT/src/legion/modules/risk_scoring.rs"
LEGION_RS="$REPO_ROOT/src/legion/core/legion.rs"

assert_file_exists "$WEIGHTS_RS" "risk_scoring.rs ships"
assert_file_exists "$LEGION_RS"  "legion.rs ships"

tap_plan 5

# Extract the Default for RiskWeights block. We grab everything between
# 'impl Default for RiskWeights' and the next bare '}' line that closes
# the impl, then pull out the *_weight: <number> rows.
extract_weight() {
    local name="$1"
    awk -v want="$name" '
        /impl[[:space:]]+Default[[:space:]]+for[[:space:]]+RiskWeights/ { in_block = 1 }
        in_block && $0 ~ ("^[[:space:]]*" want "[[:space:]]*:") {
            gsub(",", "", $0)
            split($0, a, ":")
            gsub(/[[:space:]]/, "", a[2])
            print a[2]
            exit
        }
        in_block && /^}/ { exit }
    ' "$WEIGHTS_RS"
}

anomaly=$(extract_weight "anomaly_weight")
threat_intel=$(extract_weight "threat_intel_weight")
behavioral=$(extract_weight "behavioral_weight")
network=$(extract_weight "network_weight")
process=$(extract_weight "process_weight")
file_integrity=$(extract_weight "file_integrity_weight")
system_health=$(extract_weight "system_health_weight")
temporal=$(extract_weight "temporal_weight")

missing=""
for var in anomaly threat_intel behavioral network process file_integrity system_health temporal; do
    if [ -z "${!var}" ]; then
        missing="$missing $var"
    fi
done

if [ -n "$missing" ]; then
    tap_not_ok "could not extract every weight from RiskWeights::default"
    tap_diag "missing weights:$missing"
    tap_summary
    exit 1
fi

# W1: weights sum to 1.0 within 0.0001.
sum=$(python3 -c "print(${anomaly}+${threat_intel}+${behavioral}+${network}+${process}+${file_integrity}+${system_health}+${temporal})")
ok_sum=$(python3 -c "print(abs(${sum} - 1.0) < 0.0001)")
if [ "$ok_sum" = "True" ]; then
    tap_ok "RiskWeights::default sums to 1.0 (got ${sum})"
else
    tap_not_ok "RiskWeights::default must sum to 1.0"
    tap_diag "got: $sum"
    tap_diag "anomaly=$anomaly threat_intel=$threat_intel behavioral=$behavioral"
    tap_diag "network=$network process=$process file_integrity=$file_integrity"
    tap_diag "system_health=$system_health temporal=$temporal"
fi

# W2a: network_weight pinned to 0.0
ok_net=$(python3 -c "print(float(${network}) == 0.0)")
if [ "$ok_net" = "True" ]; then
    tap_ok "network_weight is pinned to 0.0 (network_score collector not wired)"
else
    tap_not_ok "network_weight must be 0.0 until the network_score collector is wired"
    tap_diag "got: $network"
fi

# W2b: file_integrity_weight pinned to 0.0
ok_fi=$(python3 -c "print(float(${file_integrity}) == 0.0)")
if [ "$ok_fi" = "True" ]; then
    tap_ok "file_integrity_weight is pinned to 0.0 (file_integrity_score collector not wired)"
else
    tap_not_ok "file_integrity_weight must be 0.0 until the file_integrity_score collector is wired"
    tap_diag "got: $file_integrity"
fi

# W3a: legion.rs still pins network_score to 0.0.
if grep -qE 'network_score:[[:space:]]*0\.0' "$LEGION_RS"; then
    tap_ok "legion.rs still pins network_score to 0.0 (matches W2a)"
else
    tap_not_ok "legion.rs network_score pin and W2a are out of sync"
    tap_diag "If you wired real network telemetry, restore network_weight in risk_scoring.rs and renormalize."
fi

# W3b: legion.rs still pins file_integrity_score to 0.0.
if grep -qE 'file_integrity_score:[[:space:]]*0\.0' "$LEGION_RS"; then
    tap_ok "legion.rs still pins file_integrity_score to 0.0 (matches W2b)"
else
    tap_not_ok "legion.rs file_integrity_score pin and W2b are out of sync"
    tap_diag "If you wired real file integrity telemetry, restore file_integrity_weight in risk_scoring.rs and renormalize."
fi

tap_summary
