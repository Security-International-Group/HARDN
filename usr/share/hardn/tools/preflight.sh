#!/bin/bash
# HARDN preflight: check that every package HARDN would install is
# available on this distro release.
#
# Output: one row per package as TSV with columns:
#   status  package  candidate  source-list-entry
# where status is one of:
#   ok      package has an installable candidate
#   miss    package not found in any configured apt source
#   nocand  package known but no candidate (e.g. blocked by pin)
#
# Exit code: 0 if every package resolves; 1 otherwise.
#
# Designed to run in CI on each OS/release matrix entry so a package
# rename or drop (audispd-plugins folded into auditd, iptables-persistent
# replaced by nftables-persistent, ...) trips the build instead of silently
# degrading the install at runtime.

set -uo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

# Single source of truth for the list. Update when modules/hardening.sh or
# any tools/*.sh adds a new install line.
PACKAGES=(
    # core
    auditd
    audispd-plugins
    chrony
    sysstat
    acct
    haveged
    rng-tools

    # firewall / network
    ufw
    iptables
    iptables-persistent
    nftables
    nftables-persistent
    netfilter-persistent
    fail2ban

    # integrity / AV / rootkit
    aide
    clamav
    clamav-daemon
    clamav-freshclam
    rkhunter
    debsums

    # mandatory access control
    apparmor
    apparmor-profiles
    apparmor-utils
    firejail

    # IDS / NIDS
    suricata
    suricata-update

    # observability
    prometheus
    prometheus-node-exporter
    grafana
)

apt_update_if_needed() {
    # Refresh once if the apt cache is empty/stale; cheap on CI containers.
    if [ ! -d /var/lib/apt/lists ] || [ -z "$(ls -A /var/lib/apt/lists 2>/dev/null)" ]; then
        apt-get update >/dev/null 2>&1 || true
    fi
}

apt_update_if_needed

fail=0
printf '%s\t%s\t%s\t%s\n' status package candidate source
for pkg in "${PACKAGES[@]}"; do
    policy=$(apt-cache policy "$pkg" 2>/dev/null)
    if [ -z "$policy" ]; then
        printf '%s\t%s\t%s\t%s\n' miss "$pkg" "-" "-"
        fail=1
        continue
    fi
    cand=$(printf '%s\n' "$policy" | awk '/Candidate:/ {print $2; exit}')
    src=$(printf '%s\n' "$policy" | awk '/^[ \t]+[0-9]+ /{print; exit}' | tr -s ' ')
    if [ -z "$cand" ] || [ "$cand" = "(none)" ]; then
        printf '%s\t%s\t%s\t%s\n' nocand "$pkg" "${cand:--}" "${src:--}"
        fail=1
    else
        printf '%s\t%s\t%s\t%s\n' ok "$pkg" "$cand" "${src:--}"
    fi
done

# Surface the OS identity so CI logs are self-describing.
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    ( . /etc/os-release && printf '# host: %s %s (%s)\n' "${ID:-?}" "${VERSION_ID:-?}" "${VERSION_CODENAME:-?}" )
fi

exit "$fail"
