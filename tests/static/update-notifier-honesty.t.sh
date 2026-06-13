#!/bin/bash
# Pre-push regression guards for the update notifier (src/utils/updates.rs
# and the GUI banner). Each test pins one invariant we have already shipped
# the desired behaviour for, so a future change that drifts back into the
# wrong posture fails CI fast.
#
#   U1  The opt-out env var (HARDN_NO_UPDATE_CHECK) is checked BEFORE any
#       network call. Air-gapped operators must never see a curl invocation.
#
#   U2  The HTTP shell-out sets a non-empty User-Agent (GitHub rate-limits
#       aggressively without one).
#
#   U3  The default cache TTL sits inside the documented safety bounds
#       (>= 1 hour, <= 30 days).
#
#   U4  The default releases URL points at the real Security-International
#       repository on api.github.com.
#
#   U5  No vendor strings introduced into the new module.

set -u

HARDN_TEST_NAME="static/update-notifier-honesty"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

UPDATES_RS="$REPO_ROOT/src/utils/updates.rs"
GUI_RS="$REPO_ROOT/src/hardn-gui.rs"

assert_file_exists "$UPDATES_RS" "src/utils/updates.rs ships"
assert_file_exists "$GUI_RS"     "src/hardn-gui.rs ships"

tap_plan 6

# U1: opt_out() is the FIRST thing check_for_update does.
opt_out_line=$(grep -nE 'if opt_out\(\)' "$UPDATES_RS" | head -1 | cut -d: -f1)
fetch_line=$(grep -nE 'fn fetch_latest_release' "$UPDATES_RS" | head -1 | cut -d: -f1)
if [ -n "$opt_out_line" ] && [ -n "$fetch_line" ] && [ "$opt_out_line" -lt "$fetch_line" ]; then
    tap_ok "check_for_update consults opt_out() before fetch_latest_release"
else
    tap_not_ok "check_for_update must call opt_out() before any network call"
    tap_diag "opt_out_line=$opt_out_line fetch_line=$fetch_line"
fi

# U2: curl invocation sets a User-Agent.
if grep -qE '"-A",[[:space:]]*&user_agent\(\)|"-A",[[:space:]]*"hardn' "$UPDATES_RS"; then
    tap_ok "curl call sets a User-Agent"
else
    tap_not_ok "curl call must set a User-Agent so GitHub does not rate-limit us"
    grep -nE 'Command::new\("curl"\)' "$UPDATES_RS" | while IFS= read -r line; do
        tap_diag "  $line"
    done
fi

# U3: default TTL sits inside the safety bounds (1h..30d).
if grep -qE 'const DEFAULT_TTL_SEC:[[:space:]]*u64[[:space:]]*=[[:space:]]*6[[:space:]]*\*[[:space:]]*3600' "$UPDATES_RS"; then
    tap_ok "DEFAULT_TTL_SEC stays at 6h (within 1h..30d bounds)"
else
    tap_not_ok "DEFAULT_TTL_SEC must equal 6 * 3600 seconds"
fi

# U4: releases URL points at the right repo.
if grep -qE 'api\.github\.com/repos/Security-International-Group/HARDN/releases' "$UPDATES_RS"; then
    tap_ok "default releases URL points at api.github.com/repos/Security-International-Group/HARDN"
else
    tap_not_ok "default releases URL must point at the Security-International-Group HARDN repo"
fi

# U5: vendor strings.
if grep -qiE 'claude|anthropic|copilot|openai' "$UPDATES_RS" "$GUI_RS"; then
    tap_not_ok "no AI-vendor strings in updates.rs or hardn-gui.rs"
    grep -niE 'claude|anthropic|copilot|openai' "$UPDATES_RS" "$GUI_RS" | head -5 | while IFS= read -r line; do
        tap_diag "  $line"
    done
else
    tap_ok "no AI-vendor strings in updates.rs or hardn-gui.rs"
fi

tap_summary
