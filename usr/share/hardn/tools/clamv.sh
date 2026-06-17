#!/bin/bash
# HARDN ClamAV Setup Script

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "clamv.sh"

HARDN_STATUS "info" "Ensuring ClamAV packages are installed"
if install_package clamav && install_package clamav-daemon; then
    HARDN_STATUS "pass" "ClamAV packages installed"
else
    HARDN_STATUS "error" "Failed to install ClamAV packages"
    exit 1
fi

# Returns 0 when ClamAV has at least one valid signature database file
# under /var/lib/clamav. After a first freshclam run the daily database
# is downloaded as .cvd; later incremental updates rename it to .cld.
# Either form counts.
clamav_have_signatures() {
    compgen -G '/var/lib/clamav/main.[cC][vV][dD]'    >/dev/null 2>&1 \
        || compgen -G '/var/lib/clamav/main.[cC][lL][dD]'    >/dev/null 2>&1 \
        || compgen -G '/var/lib/clamav/daily.[cC][vV][dD]'   >/dev/null 2>&1 \
        || compgen -G '/var/lib/clamav/daily.[cC][lL][dD]'   >/dev/null 2>&1
}

HARDN_STATUS "info" "Checking ClamAV virus definitions"
if clamav_have_signatures; then
    HARDN_STATUS "pass" "ClamAV virus definitions present on disk"
else
    # No signatures on disk. clamav-daemon refuses to start without them,
    # which is why the tool used to "succeed" but the daemon never came up.
    # Fetch a one-shot update inline. The freshclam.service expects to be
    # the sole writer of /var/lib/clamav, so stop it first if it's running,
    # do the download, then let the service take over.
    HARDN_STATUS "info" "No virus definitions found; fetching with freshclam (may take a minute)"
    if systemctl is-active --quiet clamav-freshclam.service; then
        systemctl stop clamav-freshclam.service 2>/dev/null || true
    fi
    if command_exists freshclam; then
        mkdir -p /var/lib/clamav /var/log/hardn
        # 5-minute timeout: freshclam downloads ~200MB of signatures over a
        # constrained mirror, so 60 seconds is too short on slow links.
        if timeout 300 freshclam --quiet >>/var/log/hardn/freshclam.log 2>&1; then
            HARDN_STATUS "pass" "freshclam completed; signatures downloaded"
        else
            HARDN_STATUS "warning" "freshclam exited non-zero; check /var/log/hardn/freshclam.log"
        fi
    else
        HARDN_STATUS "warning" "freshclam binary missing; cannot download signatures"
    fi
    if clamav_have_signatures; then
        HARDN_STATUS "pass" "ClamAV virus definitions now present"
    else
        HARDN_STATUS "warning" "ClamAV virus definitions still missing after freshclam attempt"
    fi
fi

HARDN_STATUS "info" "Enabling ClamAV services"
# Order matters: bring freshclam up first so it owns ongoing signature
# updates, then start the daemon. Without signatures the daemon refuses
# to start, which we already handled above.
freshclam_ok=0
daemon_ok=0
if enable_service clamav-freshclam; then
    freshclam_ok=1
fi
if clamav_have_signatures; then
    if enable_service clamav-daemon; then
        daemon_ok=1
    fi
else
    HARDN_STATUS "warning" "Skipping clamav-daemon start: no signature database on disk"
fi

if [ "$freshclam_ok" -eq 1 ] && [ "$daemon_ok" -eq 1 ]; then
    HARDN_STATUS "pass" "ClamAV services active (freshclam + daemon)"
elif [ "$freshclam_ok" -eq 1 ]; then
    HARDN_STATUS "warning" "clamav-freshclam is active but clamav-daemon is not"
else
    HARDN_STATUS "warning" "One or more ClamAV services could not be enabled"
fi

HARDN_STATUS "info" "ClamAV setup complete"
