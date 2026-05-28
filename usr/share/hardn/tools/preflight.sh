#!/bin/bash
# HARDN preflight: check that every package HARDN would install is
# available on this distro release.
#
# Two lists:
#   REQUIRED_PACKAGES  - hard fail when missing
#   OPTIONAL_PACKAGES  - reported as info but do not fail the run
#                        (third-party repos, distro-variant alternates,
#                         or nice-to-haves)
#
# Output: one row per package as TSV with columns:
#   status  package  candidate  source-list-entry
# where status is one of:
#   ok      package has an installable candidate
#   miss    package not found in any configured apt source
#   nocand  package known but no candidate (e.g. blocked by pin)
#
# Exit code:
#   0  if every REQUIRED package resolves
#   1  if any REQUIRED package is missing or has no candidate
# Optional packages never affect the exit code.
#
# Designed to run in CI on each OS/release matrix entry so a package
# rename or drop in the REQUIRED set trips the build instead of silently
# degrading the install at runtime.

set -uo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

# Packages we genuinely cannot live without. Renames here = real bug.
REQUIRED_PACKAGES=(
    # core auditing + monitoring
    auditd
    chrony
    sysstat

    # firewall (at least one of these must exist; the install logic in
    # modules/hardening.sh handles missing ufw vs iptables)
    ufw
    iptables

    # integrity + signature scanning
    aide
    clamav
    clamav-daemon
    rkhunter

    # mandatory access control
    apparmor
    apparmor-profiles
    apparmor-utils

    # network intrusion
    fail2ban
)

# Packages that are nice-to-have, distro-variant, or installed via an
# extra repo HARDN configures at runtime. Reported but never fail.
OPTIONAL_PACKAGES=(
    # audispd-plugins was folded into auditd on some newer releases
    audispd-plugins

    # entropy daemons; the modern kernel RNG covers most cases
    haveged
    rng-tools

    # iptables vs nftables persistence varies by release
    iptables-persistent
    nftables
    nftables-persistent
    netfilter-persistent

    # AV signature updater (sometimes separate, sometimes part of clamav)
    clamav-freshclam

    # process accounting + checksum verification (nice-to-have)
    acct
    debsums

    # sandboxing
    firejail

    # IDS / NIDS (suricata-update is sometimes a separate package)
    suricata
    suricata-update

    # observability (prometheus + node-exporter are in Debian main since
    # bookworm; grafana lives at apt.grafana.com which tools/grafana.sh
    # adds at install time, so it is NOT expected in vanilla apt sources)
    prometheus
    prometheus-node-exporter
    grafana
)

apt_update_if_needed() {
    if [ ! -d /var/lib/apt/lists ] || [ -z "$(ls -A /var/lib/apt/lists 2>/dev/null)" ]; then
        apt-get update >/dev/null 2>&1 || true
    fi
}

check_package() {
    local pkg="$1" tier="$2"
    local policy cand src
    policy=$(apt-cache policy "$pkg" 2>/dev/null)
    if [ -z "$policy" ]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$tier" miss "$pkg" "-" "-"
        return 1
    fi
    cand=$(printf '%s\n' "$policy" | awk '/Candidate:/ {print $2; exit}')
    src=$(printf '%s\n' "$policy" | awk '/^[ \t]+[0-9]+ /{print; exit}' | tr -s ' ')
    if [ -z "$cand" ] || [ "$cand" = "(none)" ]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$tier" nocand "$pkg" "${cand:--}" "${src:--}"
        return 1
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$tier" ok "$pkg" "$cand" "${src:--}"
    return 0
}

apt_update_if_needed

# Surface the OS identity first so CI logs are self-describing.
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    ( . /etc/os-release && printf '# host: %s %s (%s)\n' "${ID:-?}" "${VERSION_ID:-?}" "${VERSION_CODENAME:-?}" )
fi

printf '%s\t%s\t%s\t%s\t%s\n' tier status package candidate source

required_fail=0
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    check_package "$pkg" required || required_fail=1
done

# Optional packages never fail the script; their exit status is captured
# but discarded.
for pkg in "${OPTIONAL_PACKAGES[@]}"; do
    check_package "$pkg" optional || true
done

if [ "$required_fail" -ne 0 ]; then
    printf '# preflight: at least one REQUIRED package is unavailable on this release\n' >&2
    exit 1
fi

printf '# preflight: all required packages resolve\n'
exit 0
