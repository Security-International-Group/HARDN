#!/bin/bash
# HARDN uninstall script
# Reverses HARDN's persistent system changes to return the host as close to
# its pre-install state as practical. Some changes cannot be reverted from
# userspace alone (auditd -e 2 immutable rules persist until reboot; an
# initramfs rebuild that blacklisted firewire requires a manual rebuild).
# Those are reported at the end so an operator can finish manually.
#
# Default behavior (interactive, no flags):
#   - stop and disable HARDN services
#   - remove HARDN-written drop-in config files (99-hardn-*.conf etc.)
#   - re-load sysctl defaults
#   - remove HARDN runtime data dirs
#   - dpkg -P the hardn package
#   - drop the hardn system user and group
#   - print a manual-recovery summary
#
# Optional flags (off by default — opt-in for destructive or context-specific
# actions):
#   --yes                 skip confirmation prompts (unattended)
#   --dry-run             print actions, don't execute
#   --keep-data           keep /var/log/hardn and /var/lib/hardn
#   --keep-keys           keep /etc/hardn/authorized_keys (for later reinstall)
#   --restore-ssh         systemctl unmask+enable+start ssh.service
#   --reset-firewall      ufw reset && ufw disable   (RISKY over remote SSH)
#   --purge-packages      apt-get purge HARDN-installed security packages
#
# Exit codes:
#   0  success (host returned to baseline as far as practical)
#   1  ran but encountered partial failures (printed to stderr)
#   2  bad invocation / aborted by user

set -uo pipefail

# Resolve functions.sh for HARDN_STATUS and helpers
FUNCTIONS_SH=""
for candidate in \
    "$(cd "$(dirname "$0")" && pwd)/../tools/functions.sh" \
    "/usr/share/hardn/tools/functions.sh" \
    "/usr/local/share/hardn/tools/functions.sh"; do
    if [ -f "$candidate" ]; then FUNCTIONS_SH="$candidate"; break; fi
done

if [ -n "$FUNCTIONS_SH" ]; then
    # shellcheck source=/dev/null
    source "$FUNCTIONS_SH"
else
    # Minimal fallback so the script still works after dpkg -P removed the libs
    HARDN_STATUS() {
        local level="${1:-info}"; local msg="${2:-}"
        if [ -z "$msg" ]; then msg="$level"; level="info"; fi
        printf '[%s] %s\n' "${level^^}" "$msg"
    }
fi

ASSUME_YES=0
DRY_RUN=0
KEEP_DATA=0
KEEP_KEYS=0
RESTORE_SSH=0
RESET_FIREWALL=0
PURGE_PACKAGES=0

usage() {
    sed -n '2,/^set -uo pipefail/{/^set -uo pipefail/q;p;}' "$0"
}

for arg in "$@"; do
    case "$arg" in
        --yes|-y)              ASSUME_YES=1 ;;
        --dry-run)             DRY_RUN=1 ;;
        --keep-data)           KEEP_DATA=1 ;;
        --keep-keys)           KEEP_KEYS=1 ;;
        --restore-ssh)         RESTORE_SSH=1 ;;
        --reset-firewall)      RESET_FIREWALL=1 ;;
        --purge-packages)      PURGE_PACKAGES=1 ;;
        --help|-h)             usage; exit 0 ;;
        *) HARDN_STATUS error "Unknown option: $arg"; usage; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    HARDN_STATUS error "Must run as root (use sudo)."
    exit 2
fi

# Confirmation
if [ "$ASSUME_YES" -ne 1 ] && [ "$DRY_RUN" -ne 1 ]; then
    cat <<'EOM'

═══════════════════════════════════════════════════════════════════
                    HARDN UNINSTALL
═══════════════════════════════════════════════════════════════════

This will:
  - Stop and disable hardn / legion-daemon / hardn-api / hardn-monitor
  - Remove HARDN-written drop-in config files
  - Remove HARDN runtime data (/var/log/hardn, /var/lib/hardn)
  - Remove the hardn system user and group
  - Purge the hardn Debian package

It will NOT (unless you pass the matching flag):
  - Re-enable SSH (--restore-ssh)
  - Reset the firewall (--reset-firewall — RISKY over remote SSH)
  - Purge installed security packages like aide/clamav/fail2ban
    (--purge-packages)

Some changes cannot be fully reverted from userspace and require a
reboot or manual action — these will be listed at the end.

EOM
    read -r -p "Type 'YES UNINSTALL' to proceed, anything else aborts: " confirm
    if [ "$confirm" != "YES UNINSTALL" ]; then
        HARDN_STATUS info "Aborted."
        exit 2
    fi
fi

run_cmd() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
    else
        # Use bash -c so callers can pass shell metacharacters (redirects, ||)
        # without us writing per-step error handling for every line.
        bash -c "$*"
    fi
}

# ---------- Step 1: stop & disable services ----------
HARDN_STATUS info "Stopping HARDN services"
for svc in hardn-monitor.service hardn-api.service hardn.service legion-daemon.service; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
        run_cmd "systemctl stop ${svc} 2>/dev/null || true"
        run_cmd "systemctl disable ${svc} 2>/dev/null || true"
    fi
done

# ---------- Step 2: remove HARDN-written drop-in config files ----------
HARDN_STATUS info "Removing HARDN drop-in config files"
HARDN_OWNED_FILES=(
    /etc/audit/rules.d/99-hardn-hardening.rules
    /etc/audit/auditd.conf.d/99-hardn.conf
    /etc/sysctl.d/99-hardn-hardening.conf
    /etc/sysctl.d/99-hardn-network-tuning.conf
    /etc/systemd/timesyncd.conf.d/99-hardn.conf
    /etc/systemd/journald.conf.d/99-hardn.conf
    /etc/systemd/coredump.conf.d/99-hardn-disable.conf
    /etc/rsyslog.d/99-hardn-remote.conf
    /etc/sudoers.d/99-hardn-logging
    /etc/ssh/sshd_config.d/99-hardn-hardened.conf
    /etc/fail2ban/jail.d/99-hardn.conf
    /etc/fail2ban/jail.local
    /etc/aide/aide.conf.d/99-hardn-fast.conf
    /etc/logrotate.d/hardn
    /etc/systemd/system/grafana-server.service.d/override.conf
    # HARDN-managed shell environment + system-wide desktop entry
    /etc/profile.d/hardn-paths.sh
    /usr/share/applications/hardn-gui.desktop
)
for f in "${HARDN_OWNED_FILES[@]}"; do
    if [ -f "$f" ]; then
        run_cmd "rm -f '$f'"
    fi
done

# Try to remove now-empty drop-in dirs we may have created
for d in /etc/systemd/system/grafana-server.service.d \
         /etc/aide/aide.conf.d \
         /etc/audit/auditd.conf.d; do
    run_cmd "rmdir '$d' 2>/dev/null || true"
done

# Per-user desktop launchers + icons installed by debian/postinst into
# $HOME/.local/share. We sweep every passwd entry with a valid home dir
# rather than relying on $SUDO_USER which is unset under apt+policykit.
HARDN_STATUS info "Removing per-user desktop launchers"
while IFS=: read -r _user _ uid _ _ home _; do
    [ "${uid:-0}" -ge 1000 ] || continue
    [ "${uid:-0}" -lt 65534 ] || continue
    [ -d "$home" ] || continue
    for f in \
        "$home/.local/share/applications/hardn-gui.desktop" \
        "$home/.local/share/icons/hardn-gui.jpeg"; do
        [ -e "$f" ] && run_cmd "rm -f '$f'"
    done
done < /etc/passwd

# ---------- Step 3: remove HARDN-added APT repos & keys ----------
HARDN_STATUS info "Removing HARDN-added APT repositories and keys"
for f in /etc/apt/sources.list.d/grafana.list \
         /etc/apt/sources.list.d/wazuh.list \
         /etc/apt/keyrings/grafana.gpg \
         /etc/apt/keyrings/wazuh.gpg; do
    [ -f "$f" ] && run_cmd "rm -f '$f'"
done

# ---------- Step 4: reload runtime defaults ----------
HARDN_STATUS info "Reloading sysctl, systemd, audit defaults"
run_cmd "systemctl daemon-reload 2>/dev/null || true"
run_cmd "sysctl --system >/dev/null 2>&1 || true"
# augenrules --load will fail if auditd ran -e 2 — that's expected, noted later
run_cmd "augenrules --load 2>/dev/null || true"

# ---------- Step 5: optional SSH restore ----------
if [ "$RESTORE_SSH" -eq 1 ]; then
    HARDN_STATUS info "Re-enabling SSH"
    if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
        run_cmd "systemctl unmask ssh.service 2>/dev/null || true"
        run_cmd "systemctl enable --now ssh.service 2>/dev/null || true"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.socket'; then
        run_cmd "systemctl unmask ssh.socket 2>/dev/null || true"
        run_cmd "systemctl enable --now ssh.socket 2>/dev/null || true"
    fi
else
    HARDN_STATUS info "Leaving SSH state as-is (pass --restore-ssh to unmask + enable)"
fi

# ---------- Step 6: optional firewall reset ----------
if [ "$RESET_FIREWALL" -eq 1 ]; then
    HARDN_STATUS warning "Resetting UFW (this can cut a remote SSH session if SSH isn't allowed in the new state)"
    if command -v ufw >/dev/null 2>&1; then
        run_cmd "ufw --force reset >/dev/null 2>&1 || true"
        run_cmd "ufw --force disable >/dev/null 2>&1 || true"
    fi
else
    HARDN_STATUS info "Leaving UFW state as-is (pass --reset-firewall to reset and disable)"
fi

# ---------- Step 7: optional purge of installed security packages ----------
if [ "$PURGE_PACKAGES" -eq 1 ]; then
    HARDN_STATUS info "Purging HARDN-installed security packages"
    SECURITY_PACKAGES=(
        aide apparmor-profiles auditd clamav clamav-daemon
        fail2ban firejail grafana suricata
        ossec-hids wazuh-agent
    )
    export DEBIAN_FRONTEND=noninteractive
    for pkg in "${SECURITY_PACKAGES[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            run_cmd "apt-get -y --purge remove '$pkg' >/dev/null 2>&1 || true"
        fi
    done
    run_cmd "apt-get -y autoremove --purge >/dev/null 2>&1 || true"
fi

# ---------- Step 8: remove the .deb (if installed) ----------
if dpkg -s hardn >/dev/null 2>&1; then
    HARDN_STATUS info "Purging the hardn package"
    run_cmd "DEBIAN_FRONTEND=noninteractive apt-get -y --purge remove hardn >/dev/null 2>&1 || dpkg -P hardn"
fi

# ---------- Step 9: remove runtime data ----------
HARDN_STATUS info "Removing HARDN runtime data directories"
# /etc/hardn — keep authorized_keys if requested, drop everything else
if [ "$KEEP_KEYS" -eq 1 ] && [ -f /etc/hardn/authorized_keys ]; then
    HARDN_STATUS info "Preserving /etc/hardn/authorized_keys"
    run_cmd "find /etc/hardn -mindepth 1 -not -name authorized_keys -delete 2>/dev/null || true"
else
    run_cmd "rm -rf /etc/hardn"
fi

if [ "$KEEP_DATA" -ne 1 ]; then
    # functions.sh' HARDN_STATUS appends to /var/log/hardn/hardn-tools.log on
    # every call and re-creates the parent dir. Redirect future logging to
    # /dev/null so the recovery-summary HARDN_STATUS calls below don't undo
    # the cleanup we're about to do.
    export HARDN_LOG_FILE=/dev/null
    # /var/lib/hardn covers everything below it: baselines, sentry/baseline.json,
    # alerts/seen.json, suricata-rules-staging, backups, etc.
    run_cmd "rm -rf /var/log/hardn /var/lib/hardn"
    # /run is tmpfs so the cron-locks dir disappears at reboot, but clean it
    # now so a running upgrade doesn't trip over stale entries.
    run_cmd "rm -rf /run/hardn 2>/dev/null || true"
else
    HARDN_STATUS info "Preserving /var/log/hardn and /var/lib/hardn (--keep-data)"
fi

# Remove the installed payload tree if dpkg -P left anything behind
run_cmd "rm -rf /usr/share/hardn /usr/lib/hardn 2>/dev/null || true"

# Refresh the desktop database so the system menu loses the HARDN entry
# without a logout. update-desktop-database isn't always present (it's in
# desktop-file-utils which isn't a HARDN dep) so we make it best-effort.
if command -v update-desktop-database >/dev/null 2>&1; then
    run_cmd "update-desktop-database -q /usr/share/applications 2>/dev/null || true"
fi

# ---------- Step 10: drop hardn user and group ----------
if getent passwd hardn >/dev/null 2>&1; then
    HARDN_STATUS info "Removing hardn system user"
    run_cmd "deluser --quiet hardn >/dev/null 2>&1 || true"
fi
if getent group hardn >/dev/null 2>&1; then
    HARDN_STATUS info "Removing hardn system group"
    run_cmd "delgroup --quiet --only-if-empty hardn >/dev/null 2>&1 || true"
fi

# ---------- Step 11: print manual-recovery summary ----------
cat <<'EOM'

═══════════════════════════════════════════════════════════════════
                  HARDN UNINSTALL COMPLETE
═══════════════════════════════════════════════════════════════════

Items that may need manual attention:

  1. auditd rules: if HARDN's audit ruleset was loaded with '-e 2'
     (immutable), the running kernel still has those rules until
     the next reboot. A reboot finishes the audit revert.

  2. /etc/login.defs and /etc/default/useradd: HARDN's hardening.sh
     overwrote PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE, UMASK,
     UID_MIN, ENCRYPT_METHOD, INACTIVE. These are not reverted by
     this script because the original values weren't snapshotted.
     Inspect those files and restore your site defaults if needed.

  3. /etc/ssh/sshd_config: HARDN may have created a timestamped
     backup at /etc/ssh/sshd_config.bak.YYYYMMDD. Restore it
     manually if the active config has unwanted settings.

  4. /etc/modprobe.d/blacklist-firewire.conf: if HARDN added this
     and you want firewire back, remove the file and run
     'sudo update-initramfs -u'.

  5. UFW persistent rules: if --reset-firewall was NOT passed,
     HARDN's strict UFW policy is still active and persists across
     reboot. Run 'sudo ufw reset && sudo ufw disable' to remove.

  6. SELinux: if 'hardn --enable-selinux' was run on this host,
     undo it by:
       - removing 'security=selinux selinux=1' from /etc/default/grub
       - 'sudo update-grub'
       - 'sudo apt install apparmor apparmor-profiles apparmor-utils'
       - 'sudo apt remove selinux-basics selinux-policy-default'
       - 'sudo rm -f /.autorelabel'
       - reboot

EOM

HARDN_STATUS pass "Uninstall complete."
exit 0
