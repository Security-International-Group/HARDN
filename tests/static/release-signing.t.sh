#!/bin/bash
# Pre-push regression guard: releases are signed and checksummed.
#
# The audit flagged that releases shipped an unsigned .deb (softprops
# upload, no signature, no cosign, no GPG). Anyone who obtains write
# access to the release, or MITMs the download, can swap the package.
# PR-D adds sigstore cosign keyless signing (GitHub OIDC, no long-lived
# key) plus a SHA256SUMS file, and publishes both as release assets.
#
# Invariants (all in the ci.yml release job):
#
#   S1  cosign is installed via sigstore/cosign-installer.
#
#   S2  A SHA256SUMS file is generated over the release artifact(s).
#
#   S3  cosign sign-blob runs against the .deb and emits a detached
#       signature and certificate.
#
#   S4  The release job grants 'id-token: write' (required for keyless
#       OIDC signing) alongside the existing 'contents: write'.
#
#   S5  The signature, certificate, and SHA256SUMS are added to the
#       release upload file list.
#
#   S6  The signing step is not silenced with '|| true'.

set -u

HARDN_TEST_NAME="static/release-signing"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

CI="$REPO_ROOT/.github/workflows/ci.yml"

assert_file_exists "$CI" ".github/workflows/ci.yml ships"

tap_plan 6

# S1: cosign installer present.
if grep -qE 'sigstore/cosign-installer' "$CI"; then
    tap_ok "ci.yml installs cosign via sigstore/cosign-installer"
else
    tap_not_ok "ci.yml must install cosign (sigstore/cosign-installer)"
fi

# S2: SHA256SUMS generation.
if grep -qE 'sha256sum.*(SHA256SUMS|> *SHA256SUMS)' "$CI" || grep -qE 'SHA256SUMS' "$CI"; then
    tap_ok "ci.yml generates a SHA256SUMS file"
else
    tap_not_ok "ci.yml must generate a SHA256SUMS file over the release artifacts"
fi

# S3: cosign sign-blob invocation.
if grep -qE 'cosign[[:space:]]+sign-blob' "$CI"; then
    tap_ok "ci.yml runs 'cosign sign-blob' on the release artifact"
else
    tap_not_ok "ci.yml must run 'cosign sign-blob' to sign the .deb"
fi

# S4: id-token: write permission on the release job. We check the file
# contains the permission; the workflow only needs it in the release
# job, which is the sole OIDC consumer.
if grep -qE 'id-token:[[:space:]]*write' "$CI"; then
    tap_ok "ci.yml grants 'id-token: write' for keyless OIDC signing"
else
    tap_not_ok "the release job must grant 'id-token: write'"
fi

# S5: signature/cert/checksums added to the release upload list.
# cosign emits <name>.sig and <name>.pem (or .crt); require the release
# 'files:' block to reference .sig and SHA256SUMS.
if grep -qE '\.sig' "$CI" && grep -qE 'SHA256SUMS' "$CI"; then
    tap_ok "release uploads the signature and SHA256SUMS"
else
    tap_not_ok "release 'files:' must include the .sig signature and SHA256SUMS"
fi

# S6: signing not silenced.
if grep -qE 'cosign[[:space:]]+sign-blob[^#]*\|\|[[:space:]]+true' "$CI"; then
    tap_not_ok "cosign sign-blob must not be silenced with '|| true'"
    grep -nE 'cosign[[:space:]]+sign-blob[^#]*\|\|[[:space:]]+true' "$CI" | sed 's/^/# /'
else
    tap_ok "cosign sign-blob is not silenced with '|| true'"
fi

tap_summary
