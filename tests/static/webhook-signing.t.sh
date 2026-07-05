#!/bin/bash
# Pre-push regression guard: webhook alerts are signable and there is a
# reference verifier.
#
# The audit noted the webhook fanout POSTs unsigned JSON, so a receiver
# cannot prove an alert came from HARDN. PR-M adds optional HMAC-SHA256
# signing keyed on HARDN_ALERT_WEBHOOK_SECRET, sent as an
# X-HARDN-Signature header, and ships a reference verifier.
#
# Invariants:
#
#   W1  src/utils/alerts.rs reads HARDN_ALERT_WEBHOOK_SECRET.
#
#   W2  src/utils/alerts.rs sends an X-HARDN-Signature header.
#
#   W3  A reference receiver/verifier exists under contrib/.
#
#   W4  The reference verifier uses a constant-time comparison
#       (hmac.compare_digest / secrets.compare_digest), not ==.
#
# The cryptographic correctness of the HMAC itself is proven by a Rust
# known-answer test against the RFC 4231 vector (see the #[cfg(test)]
# module in alerts.rs); this suite only locks in the wiring.

set -u

HARDN_TEST_NAME="static/webhook-signing"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

ALERTS="$REPO_ROOT/src/utils/alerts.rs"

assert_file_exists "$ALERTS" "src/utils/alerts.rs ships"

tap_plan 5

# W1: reads the secret env var.
if grep -qE 'HARDN_ALERT_WEBHOOK_SECRET' "$ALERTS"; then
    tap_ok "alerts.rs reads HARDN_ALERT_WEBHOOK_SECRET"
else
    tap_not_ok "alerts.rs must read HARDN_ALERT_WEBHOOK_SECRET"
fi

# W2: sets the signature header.
if grep -qE 'X-HARDN-Signature' "$ALERTS"; then
    tap_ok "alerts.rs sends an X-HARDN-Signature header"
else
    tap_not_ok "alerts.rs must send an X-HARDN-Signature header"
fi

# W2b: the signature is an HMAC-SHA256 (sha256= prefix, hmac helper).
if grep -qE 'sha256=' "$ALERTS" && grep -qiE 'hmac' "$ALERTS"; then
    tap_ok "alerts.rs computes an HMAC and prefixes the signature with sha256="
else
    tap_not_ok "alerts.rs signature must be an HMAC-SHA256 tagged 'sha256='"
fi

# W3: reference verifier ships under contrib/.
verifier=""
for cand in \
    "$REPO_ROOT/contrib/webhook-receiver/verify.py" \
    "$REPO_ROOT/contrib/webhook-receiver/verify.sh" \
; do
    if [ -f "$cand" ]; then
        verifier="$cand"
        break
    fi
done
if [ -z "$verifier" ]; then
    # Fall back to any file under contrib/webhook-receiver/.
    if [ -d "$REPO_ROOT/contrib/webhook-receiver" ]; then
        verifier=$(find "$REPO_ROOT/contrib/webhook-receiver" -type f | head -1)
    fi
fi
if [ -n "$verifier" ]; then
    tap_ok "a reference verifier ships under contrib/webhook-receiver/"
else
    tap_not_ok "a reference verifier must ship under contrib/webhook-receiver/"
fi

# W4: verifier uses constant-time comparison.
if [ -n "$verifier" ] && grep -qE 'compare_digest' "$verifier"; then
    tap_ok "reference verifier uses a constant-time comparison"
else
    tap_not_ok "reference verifier must use compare_digest (constant-time), not =="
fi

tap_summary
