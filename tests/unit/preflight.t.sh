#!/bin/bash
# Unit tests for tools/preflight.sh.
#
# Mocks `apt-cache` so we can drive the exit-code logic without depending
# on what's actually installed on the runner.

set -u

HARDN_TEST_NAME="unit/preflight"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"
PREFLIGHT="$REPO_ROOT/usr/share/hardn/tools/preflight.sh"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

if [ ! -f "$PREFLIGHT" ]; then
    tap_plan 1
    tap_skip "preflight.sh not on this branch (lands with the raccoon / Ubuntu 26.04 PR)"
    tap_summary
    exit 0
fi
assert_file_exists "$PREFLIGHT" "preflight.sh ships at the expected path"

# Create a temporary PATH override with a fake apt-cache. We control its
# exit code + output by checking the package name passed in.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

write_fake_apt_cache() {
    local fail_required="$1"  # 1 to make 'auditd' return (none)
    cat > "$TMP/apt-cache" <<EOF
#!/bin/bash
# Fake apt-cache policy <pkg>. Returns either an "installable" stanza or
# nothing, depending on the package name we're driving the test with.
case "\$1" in
    policy)
        case "\$2" in
            auditd)
                if [ "${fail_required}" = "1" ]; then
                    # Simulate a release where auditd disappeared / renamed.
                    printf 'auditd:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n'
                else
                    printf 'auditd:\n  Installed: (none)\n  Candidate: 1:3.1.2-2.1build1.1\n  Version table:\n     1:3.1.2-2.1build1.1 500\n        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n'
                fi
                ;;
            grafana)
                # Grafana is in the optional list and is NEVER expected to be
                # available in vanilla apt sources. Return nothing.
                exit 0
                ;;
            *)
                # Every other package: pretend it resolves cleanly.
                printf '%s:\n  Installed: (none)\n  Candidate: 1.0-0\n  Version table:\n     1.0-0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n' "\$2"
                ;;
        esac
        ;;
esac
EOF
    chmod +x "$TMP/apt-cache"
}

tap_plan 4

# Happy path: every required package resolves.
write_fake_apt_cache 0
out=$(PATH="$TMP:$PATH" bash "$PREFLIGHT" 2>&1; echo "EXIT=$?")
exit_code=$(printf '%s' "$out" | awk -F= '/^EXIT=/{print $2; exit}')
assert_eq "0" "$exit_code" "exit 0 when every required package resolves"

# grafana shows up in the report but does NOT change exit code.
assert_contains "$out" "optional	miss	grafana" "grafana reported as optional miss"

# Sad path: required package missing (simulate auditd renamed away).
write_fake_apt_cache 1
out=$(PATH="$TMP:$PATH" bash "$PREFLIGHT" 2>&1; echo "EXIT=$?")
exit_code=$(printf '%s' "$out" | awk -F= '/^EXIT=/{print $2; exit}')
assert_eq "1" "$exit_code" "exit 1 when a required package has no candidate"

assert_contains "$out" "required	nocand	auditd" "auditd reported as required/nocand"

tap_summary
