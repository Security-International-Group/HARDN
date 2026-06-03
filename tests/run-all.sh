#!/bin/bash
# HARDN test-harness orchestrator.
#
# Walks tests/{static,unit,integration,cargo}/*.t.{sh,py}, runs each in
# isolation, captures stdout, and writes one Markdown report into
# tests/reports/test-report-<UTC timestamp>.md.
#
# Each suite is expected to:
#   * emit TAP-style 'ok N - desc' / 'not ok N - desc' lines
#   * end with a comment of the shape:
#     '# <suite-name> totals: total=X pass=Y fail=Z skip=W'
#
# Exit code: number of suites with any 'not ok' or non-zero exit.
# (Suites that exit non-zero with all 'ok / # SKIP' still get reported
# as SKIP, not FAIL, by virtue of their totals line.)

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
REPORTS_DIR="$TESTS_DIR/reports"
REPORT="$REPORTS_DIR/test-report-${TIMESTAMP}.md"
mkdir -p "$REPORTS_DIR"

# Collect suites in a stable, predictable order.
mapfile -t SUITES < <(
    find "$TESTS_DIR/static" "$TESTS_DIR/unit" "$TESTS_DIR/integration" \
         "$TESTS_DIR/cargo" \
        -maxdepth 1 -type f \( -name '*.t.sh' -o -name '*.t.py' \) 2>/dev/null | sort
)

total_suites=${#SUITES[@]}
fail_suites=0
total_assertions=0
pass_assertions=0
fail_assertions=0
skip_assertions=0

# Build the report progressively.
{
    printf '# HARDN test report\n\n'
    printf '* generated: %s UTC\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
    printf '* commit:    `%s`\n' "$(git -C "$REPO_ROOT" log --format='%h %s' -1 2>/dev/null || echo 'unknown')"
    printf '* host:      `%s`\n' "$(uname -s -r -m 2>/dev/null || echo 'unknown')"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        os_line=$( . /etc/os-release && printf '%s %s (%s)' "${ID:-?}" "${VERSION_ID:-?}" "${VERSION_CODENAME:-?}" )
        printf '* os:        %s\n' "$os_line"
    fi
    printf '\n'

    printf '## Suites\n\n'
    printf '| Suite | Total | Pass | Fail | Skip | Exit | Duration |\n'
    printf '|---|---:|---:|---:|---:|---:|---:|\n'
} > "$REPORT"

# Per-suite logs for the "Details" appendix.
DETAILS_TMP=$(mktemp)
trap 'rm -f "$DETAILS_TMP"' EXIT

for suite_path in "${SUITES[@]}"; do
    rel="${suite_path#"$TESTS_DIR/"}"
    suite_name="${rel%.t.sh}"; suite_name="${suite_name%.t.py}"

    start_ns=$(date +%s%N)
    if [[ "$suite_path" == *.t.py ]]; then
        out=$(python3 "$suite_path" 2>&1)
    else
        out=$(bash "$suite_path" 2>&1)
    fi
    ec=$?
    end_ns=$(date +%s%N)
    dur_ms=$(( (end_ns - start_ns) / 1000000 ))

    totals_line=$(printf '%s\n' "$out" | grep -E "# .* totals: total=" | tail -1)
    suite_total=0; suite_pass=0; suite_fail=0; suite_skip=0
    if [ -n "$totals_line" ]; then
        suite_total=$(printf '%s' "$totals_line" | grep -oE 'total=[0-9]+' | head -1 | cut -d= -f2)
        suite_pass=$(printf '%s' "$totals_line" | grep -oE 'pass=[0-9]+' | head -1 | cut -d= -f2)
        suite_fail=$(printf '%s' "$totals_line" | grep -oE 'fail=[0-9]+' | head -1 | cut -d= -f2)
        suite_skip=$(printf '%s' "$totals_line" | grep -oE 'skip=[0-9]+' | head -1 | cut -d= -f2)
    fi

    total_assertions=$((total_assertions + suite_total))
    pass_assertions=$((pass_assertions + suite_pass))
    fail_assertions=$((fail_assertions + suite_fail))
    skip_assertions=$((skip_assertions + suite_skip))

    if [ "$suite_fail" -gt 0 ] || { [ "$ec" -ne 0 ] && [ "$suite_total" -eq 0 ]; }; then
        fail_suites=$((fail_suites + 1))
    fi

    printf '| %s | %d | %d | %d | %d | %d | %dms |\n' \
        "$rel" "$suite_total" "$suite_pass" "$suite_fail" "$suite_skip" "$ec" "$dur_ms" \
        >> "$REPORT"

    {
        printf '\n### %s\n\n' "$rel"
        printf '\`\`\`\n'
        printf '%s\n' "$out"
        printf '\`\`\`\n'
    } >> "$DETAILS_TMP"
done

{
    printf '\n## Totals\n\n'
    printf '| Metric | Count |\n'
    printf '|---|---:|\n'
    printf '| Suites run        | %d |\n' "$total_suites"
    printf '| Suites with fails | %d |\n' "$fail_suites"
    printf '| Assertions        | %d |\n' "$total_assertions"
    printf '| Pass              | %d |\n' "$pass_assertions"
    printf '| Fail              | %d |\n' "$fail_assertions"
    printf '| Skip              | %d |\n' "$skip_assertions"
    printf '\n'

    if [ "$fail_suites" -eq 0 ] && [ "$fail_assertions" -eq 0 ]; then
        printf '**Result: PASS**\n'
    else
        printf '**Result: FAIL**\n'
    fi

    printf '\n## Details\n'
    cat "$DETAILS_TMP"
} >> "$REPORT"

# Console summary so a CI tail can pick it up.
echo
echo "Wrote report: $REPORT"
echo "Suites: $total_suites total, $fail_suites with fails"
echo "Assertions: $total_assertions total, $pass_assertions pass, $fail_assertions fail, $skip_assertions skip"

if [ "$fail_suites" -ne 0 ] || [ "$fail_assertions" -ne 0 ]; then
    exit 1
fi
exit 0
