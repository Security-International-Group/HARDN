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

tap_plan 10

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

# S7: the checksum line must not name IMG_1233.jpeg. The release job only
# downloads the .deb artifact; the imagery is added by a different job and
# is absent here, so 'sha256sum ... IMG_1233.jpeg' fails the step under
# 'set -e'. This regression bit a real release build (v1.2.134).
if grep -nE 'sha256sum[^#]*IMG_1233\.jpeg' "$CI" >/dev/null 2>&1; then
    tap_not_ok "sha256sum must not reference IMG_1233.jpeg (absent from the release job)"
    grep -nE 'sha256sum[^#]*IMG_1233\.jpeg' "$CI" | sed 's/^/# /'
else
    tap_ok "sha256sum does not reference the release-job-absent IMG_1233.jpeg"
fi

# S8: no manual git-tag push. The tag used to be pushed BEFORE signing, so a
# failed sign orphaned a tag and bumped the version counter. Tag creation is
# now delegated to the release action, which runs only after signing. A
# 'git push ... "$NEW_TAG"' anywhere reintroduces the orphan-tag hazard.
if grep -nE 'git[[:space:]]+push[^#\n]*NEW_TAG' "$CI" >/dev/null 2>&1; then
    tap_not_ok "release job must not manually push the tag before signing"
    grep -nE 'git[[:space:]]+push[^#\n]*NEW_TAG' "$CI" | sed 's/^/# /'
else
    tap_ok "release tag is not manually pushed (created atomically by the release step)"
fi

# S9: signing must come BEFORE the GitHub Release publish step, so a signing
# failure prevents any release from being created.
sign_line=$(grep -nE 'cosign[[:space:]]+sign-blob' "$CI" | head -1 | cut -d: -f1)
release_line=$(grep -nE 'softprops/action-gh-release' "$CI" | head -1 | cut -d: -f1)
if [ -n "$sign_line" ] && [ -n "$release_line" ] && [ "$sign_line" -lt "$release_line" ]; then
    tap_ok "cosign signing runs before the GitHub Release publish step"
else
    tap_not_ok "cosign signing must run before the release publish step"
    tap_diag "sign at line ${sign_line:-none}, release at line ${release_line:-none}"
fi

# S10: the release upload must fail on a missing asset rather than publish a
# partial set. Every listed file is produced by the sign step and must exist.
if grep -qE 'fail_on_unmatched_files:[[:space:]]*true' "$CI"; then
    tap_ok "release upload fails on an unmatched (missing) asset"
else
    tap_not_ok "release must set fail_on_unmatched_files: true so a partial asset set fails"
fi

tap_summary
