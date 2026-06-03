#!/bin/bash
# yaml.safe_load every .github/workflows YAML and any HARDN-shipped YAML
# under templates/ or systemd/.

set -u

HARDN_TEST_NAME="static/yaml-lint"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd python3 "install python3"
if ! python3 -c 'import yaml' 2>/dev/null; then
    tap_plan 1
    tap_skip "python3 yaml module not available (apt-get install python3-yaml)"
    tap_summary
    exit 0
fi

mapfile -t yamls < <(find "$REPO_ROOT/.github" "$REPO_ROOT/usr/share/hardn/templates" \
    -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)

if [ "${#yamls[@]}" -eq 0 ]; then
    tap_plan 1
    tap_skip "no YAML files to check"
    tap_summary
    exit 0
fi

tap_plan "${#yamls[@]}"

for y in "${yamls[@]}"; do
    rel="${y#"$REPO_ROOT"/}"
    if output=$(python3 -c "import sys, yaml; list(yaml.safe_load_all(open('$y')))" 2>&1); then
        tap_ok "$rel"
    else
        tap_not_ok "$rel"
        while IFS= read -r line; do tap_diag "$line"; done <<< "$output"
    fi
done

tap_summary
