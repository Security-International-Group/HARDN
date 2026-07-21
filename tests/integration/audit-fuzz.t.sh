#!/bin/bash
# Sanitizer-replay guard for the hardn-audit C parsers.
#
# The audit engine is hand-written C that parses host config files; malformed
# input is where a memory-safety bug would hide. This builds the fuzz harness
# (tests/fuzz/audit_parser_harness.c) under AddressSanitizer + UBSan with
# -fno-sanitize-recover=all (so any fault aborts non-zero) and replays:
#   - the committed adversarial seed corpus (tests/fuzz/corpus/*), and
#   - a batch of freshly generated random inputs.
# Any out-of-bounds access, use-after-free, or undefined behavior fails CI.
#
# For coverage-guided fuzzing, the same harness builds with
#   clang -fsanitize=fuzzer,address,undefined
# where a libFuzzer runtime is available.

set -u

HARDN_TEST_NAME="integration/audit-fuzz"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd cc "install a C compiler"

HARNESS="$REPO_ROOT/tests/fuzz/audit_parser_harness.c"
CORPUS_DIR="$REPO_ROOT/tests/fuzz/corpus"
if [ ! -f "$HARNESS" ]; then
    tap_plan 1
    tap_not_ok "fuzz harness missing: $HARNESS"
    tap_summary
    exit 1
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

BIN_PLAIN="$WORK/harness-plain"
BIN_SAN="$WORK/harness-san"

# First a plain compile: this distinguishes a real harness/source error (fail)
# from a missing-sanitizer-runtime environment (skip).
if ! cc -std=c11 -O1 -w "$HARNESS" -o "$BIN_PLAIN" 2>"$WORK/plain.log"; then
    tap_plan 1
    tap_not_ok "fuzz harness does not compile"
    sed 's/^/# /' "$WORK/plain.log" | head -20
    tap_summary
    exit 1
fi

# Sanitized build. If this specific build fails, assume the sanitizer runtime
# is unavailable and skip rather than red the whole harness.
if ! cc -std=c11 -O1 -g -w -fsanitize=address,undefined -fno-sanitize-recover=all \
        -fno-omit-frame-pointer "$HARNESS" -o "$BIN_SAN" 2>"$WORK/san.log"; then
    tap_skip "${HARDN_TEST_NAME}: sanitizer build unavailable (asan/ubsan runtime?)"
    sed 's/^/# /' "$WORK/san.log" | head -10
    tap_summary
    exit 0
fi

# Generate a batch of random inputs (portable; no python required).
RAND_DIR="$WORK/rand"
mkdir -p "$RAND_DIR"
if [ -r /dev/urandom ]; then
    for i in $(seq 1 300); do
        head -c "$(( (i * 7) % 512 ))" /dev/urandom > "$RAND_DIR/r$i" 2>/dev/null || true
    done
fi

tap_plan 3

# 1) seed corpus
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1"
export UBSAN_OPTIONS="print_stacktrace=1"
if "$BIN_SAN" "$CORPUS_DIR"/* >/dev/null 2>"$WORK/seed.err"; then
    tap_ok "audit parsers survive the seed corpus under ASAN+UBSan"
else
    tap_not_ok "sanitizer fault replaying the seed corpus"
    sed 's/^/# /' "$WORK/seed.err" | head -25
fi

# 2) random batch
if "$BIN_SAN" "$RAND_DIR"/* >/dev/null 2>"$WORK/rand.err"; then
    tap_ok "audit parsers survive 300 random inputs under ASAN+UBSan"
else
    tap_not_ok "sanitizer fault replaying random inputs"
    sed 's/^/# /' "$WORK/rand.err" | head -25
fi

# 3) the engine still builds and runs normally (guard did not break main)
if cc -std=c11 -O2 -w "$REPO_ROOT/src/audit/hardn_audit.c" -o "$WORK/hardn-audit" 2>/dev/null \
   && "$WORK/hardn-audit" >/dev/null 2>&1; then
    tap_ok "hardn-audit still builds and runs with main() intact"
else
    tap_not_ok "hardn-audit failed to build/run after the HARDN_NO_MAIN guard"
fi

tap_summary
