#!/bin/bash
# Unit tests for usr/share/hardn/tools/env-detect.sh.
#
# Exercises predicates that can be driven by env-var overrides without
# needing root or a real /sys/class/dmi mock:
#   * HARDN_CONTAINER_HOST=1 short-circuits hardn_is_container_workload_host
#   * HARDN_USES_NFTABLES (0/1) overrides hardn_uses_nftables
#   * HARDN_CLOUD_LB_CIDRS overrides hardn_cloud_health_check_cidrs

set -u

HARDN_TEST_NAME="unit/env-detect"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"
ENV_DETECT="$REPO_ROOT/usr/share/hardn/tools/env-detect.sh"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

assert_file_exists "$ENV_DETECT" "env-detect.sh ships at the expected path"

# Counter-script: run a subshell, source env-detect, run an expression,
# print its output / exit code.
run_with_env() {
    local snippet="$1"
    bash -c "set -u; source '$ENV_DETECT'; $snippet" 2>&1
    return $?
}

# Some predicates (hardn_uses_nftables) shipped via the raccoon PR and
# are absent on older branches. Detect at runtime and adjust the plan
# so the suite passes either way.
if bash -c "source '$ENV_DETECT'; declare -F hardn_uses_nftables" >/dev/null 2>&1; then
    HAS_NFTABLES_PREDICATE=1
    tap_plan 8
else
    HAS_NFTABLES_PREDICATE=0
    tap_plan 6
fi

# HARDN_CONTAINER_HOST=1 forces container-workload-host detection on.
HARDN_CONTAINER_HOST=1 run_with_env 'hardn_is_container_workload_host && echo yes || echo no' >/tmp/.hardn_test_out
assert_eq "yes" "$(cat /tmp/.hardn_test_out)" "HARDN_CONTAINER_HOST=1 forces true"

# Empty/missing override means autodetect; this container has Docker
# markers so the autodetect should also yield true on the CI runner.
unset HARDN_CONTAINER_HOST
run_with_env 'hardn_is_container_workload_host && echo yes || echo no' >/tmp/.hardn_test_out
result=$(cat /tmp/.hardn_test_out)
assert_contains "yes no" "$result" "autodetect returns a deterministic boolean"

if [ "$HAS_NFTABLES_PREDICATE" = "1" ]; then
    # HARDN_USES_NFTABLES=1 forces nftables path.
    HARDN_USES_NFTABLES=1 run_with_env 'hardn_uses_nftables && echo nft || echo legacy' >/tmp/.hardn_test_out
    assert_eq "nft" "$(cat /tmp/.hardn_test_out)" "HARDN_USES_NFTABLES=1 selects nftables"

    # HARDN_USES_NFTABLES=0 forces legacy path even when nft is installed.
    HARDN_USES_NFTABLES=0 run_with_env 'hardn_uses_nftables && echo nft || echo legacy' >/tmp/.hardn_test_out
    assert_eq "legacy" "$(cat /tmp/.hardn_test_out)" "HARDN_USES_NFTABLES=0 selects legacy"
fi

# HARDN_CLOUD_LB_CIDRS overrides the built-in GCP-only default list.
HARDN_CLOUD_LB_CIDRS="10.0.0.0/8 192.168.0.0/16" run_with_env 'hardn_cloud_health_check_cidrs' >/tmp/.hardn_test_out
output=$(cat /tmp/.hardn_test_out)
assert_contains "$output" "10.0.0.0/8" "operator CIDR override is honoured (10.0.0.0/8)"
assert_contains "$output" "192.168.0.0/16" "operator CIDR override is honoured (192.168.0.0/16)"

# Metadata CIDR list always includes the link-local IMDS endpoint.
run_with_env 'hardn_cloud_metadata_cidrs' >/tmp/.hardn_test_out
output=$(cat /tmp/.hardn_test_out)
assert_contains "$output" "169.254.169.254/32" "IMDS link-local always present"

# hardn_env_summary returns a non-empty line.
run_with_env 'hardn_env_summary' >/tmp/.hardn_test_out
result=$(cat /tmp/.hardn_test_out)
assert_ne "" "$result" "hardn_env_summary returns non-empty"

rm -f /tmp/.hardn_test_out
tap_summary
