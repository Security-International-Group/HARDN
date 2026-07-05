#!/bin/bash
# Pre-push regression guard: failed webhook deliveries are not lost.
#
# The audit noted the webhook fanout made a single curl attempt and
# dropped the alert on any failure (slow receiver, transient network,
# receiver restart). PR-N adds a durable spill queue with exponential
# backoff: a failed POST is appended to a queue file and retried on
# later forwards, so an alert survives a receiver outage.
#
# Invariants:
#
#   R1  alerts.rs references a queue file path (queue.jsonl) and reads
#       HARDN_ALERT_QUEUE_PATH.
#
#   R2  alerts.rs has an exponential-backoff helper (a function whose
#       name contains 'backoff').
#
#   R3  alerts.rs spills to the queue on delivery failure and drains it
#       (functions whose names contain 'spill'/'queue'/'drain').
#
# The scheduling and backoff math are proven by Rust unit tests using an
# injectable sender (no live server); this suite locks in the wiring.

set -u

HARDN_TEST_NAME="static/webhook-retry"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

ALERTS="$REPO_ROOT/src/utils/alerts.rs"

assert_file_exists "$ALERTS" "src/utils/alerts.rs ships"

tap_plan 4

# R1: queue path + env override.
if grep -qE 'queue\.jsonl' "$ALERTS" && grep -qE 'HARDN_ALERT_QUEUE_PATH' "$ALERTS"; then
    tap_ok "alerts.rs defines a queue file and reads HARDN_ALERT_QUEUE_PATH"
else
    tap_not_ok "alerts.rs must define a queue.jsonl path and read HARDN_ALERT_QUEUE_PATH"
fi

# R2: backoff helper.
if grep -qiE 'fn +[a-z_]*backoff' "$ALERTS"; then
    tap_ok "alerts.rs has an exponential-backoff helper"
else
    tap_not_ok "alerts.rs must have a backoff helper function"
fi

# R3a: spill on failure.
if grep -qiE 'fn +[a-z_]*spill' "$ALERTS" || grep -qiE 'spill' "$ALERTS"; then
    tap_ok "alerts.rs spills failed deliveries to the queue"
else
    tap_not_ok "alerts.rs must spill failed deliveries to the queue"
fi

# R3b: drain.
if grep -qiE 'fn +[a-z_]*drain' "$ALERTS"; then
    tap_ok "alerts.rs drains the queue on later forwards"
else
    tap_not_ok "alerts.rs must have a drain function for the queue"
fi

tap_summary
