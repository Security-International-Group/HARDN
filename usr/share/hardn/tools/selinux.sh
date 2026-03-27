#!/bin/bash
# HARDN SELinux configuration script
# Disables AppArmor, installs SELinux, sets permissive mode,
# schedules filesystem relabeling, and prompts for reboot.
# Pass --auto-reboot to reboot automatically (unattended deployments only).

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "selinux.sh"

# Parse optional --auto-reboot flag
AUTO_REBOOT=0
for arg in "$@"; do
    if [ "$arg" = "--auto-reboot" ]; then
        AUTO_REBOOT=1
    fi
done

HARDN_STATUS "info" "Disabling AppArmor..."
systemctl stop apparmor 2>/dev/null || true
systemctl disable apparmor 2>/dev/null || true
apt-get remove -y apparmor apparmor-utils 2>/dev/null || true
HARDN_STATUS "pass" "AppArmor disabled."
HARDN_STATUS "info" "Installing SELinux..."
if apt-get install -y selinux-basics selinux-policy-default auditd; then
    HARDN_STATUS "pass" "SELinux packages installed."
else
    HARDN_STATUS "error" "Failed to install SELinux packages. Aborting."
    exit 1
fi
HARDN_STATUS "info" "Enabling SELinux..."
if selinux-activate; then
    HARDN_STATUS "pass" "SELinux activated."
else
    HARDN_STATUS "error" "selinux-activate failed. Aborting."
    exit 1
fi
HARDN_STATUS "info" "Setting SELinux to permissive mode..."
setenforce 0 2>/dev/null || true
if [ -f /etc/selinux/config ]; then
    sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
fi
HARDN_STATUS "pass" "SELinux set to permissive mode."
HARDN_STATUS "info" "Scheduling filesystem relabeling on next boot..."
touch /.autorelabel
HARDN_STATUS "pass" "Filesystem relabeling scheduled (/.autorelabel created)."
HARDN_STATUS "warning" "A reboot is required to complete SELinux activation and trigger filesystem relabeling."
HARDN_STATUS "info"    "Filesystem relabeling may take 10-60 minutes on the next boot depending on disk size."

if [ "$AUTO_REBOOT" -eq 1 ]; then
    HARDN_STATUS "info" "Auto-reboot flag set — rebooting in 10 seconds. Press Ctrl+C to cancel."
    sleep 10
    reboot
else
    HARDN_STATUS "info" "Reboot manually when ready: sudo shutdown -r now"
fi