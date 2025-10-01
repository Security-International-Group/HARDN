#!/bin/bash
# HARDN Hardening Test Suite
# Performs in-depth validation after running the consolidated hardening module.

set -euo pipefail

TITLE="HARDN Hardening Test Suite"
TEST_USER=""
TEST_PW="HardnTest42!"
LYNIS_REPORT="/var/log/hardn/lynis-hardening-report.dat"
LYNIS_LOG=""
overall_rc=1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

failures=()
warnings=()
checks=()

cleanup_resources() {
    if [[ -n "$TEST_USER" ]] && id "$TEST_USER" >/dev/null 2>&1; then
        userdel -rf "$TEST_USER" >/dev/null 2>&1 || userdel "$TEST_USER" >/dev/null 2>&1 || true
    fi
    if [[ -n "$LYNIS_LOG" && -f "$LYNIS_LOG" ]]; then
        rm -f "$LYNIS_LOG"
    fi
}

finalized=0

undo_hardening_changes() {
    log_section "Undoing HARDN hardening changes"

    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^UMASK.*/UMASK           022/' /etc/login.defs 2>/dev/null || true
    fi

    if [[ -f /etc/ssh/sshd_config.d/99-hardn-hardened.conf ]]; then
        rm -f /etc/ssh/sshd_config.d/99-hardn-hardened.conf 2>/dev/null || true
    fi
    if [[ -f /etc/ssh/sshd_banner ]]; then
        rm -f /etc/ssh/sshd_banner 2>/dev/null || true
    fi
    local latest_bak
    latest_bak=$(ls -1t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -n1 || true)
    if [[ -n "$latest_bak" && -f "$latest_bak" ]]; then
        cp "$latest_bak" /etc/ssh/sshd_config 2>/dev/null || true
    fi
    systemctl reload sshd >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || true

    if [[ -f /etc/audit/rules.d/99-hardn-hardening.rules ]]; then
        rm -f /etc/audit/rules.d/99-hardn-hardening.rules 2>/dev/null || true
        augenrules --load >/dev/null 2>&1 || true
        systemctl restart auditd >/dev/null 2>&1 || true
    fi

    rm -f /etc/sysctl.d/99-hardn-hardening.conf 2>/dev/null || true
    rm -f /etc/sysctl.d/99-hardn-network-tuning.conf 2>/dev/null || true
    sed -i '/^fs\.suid_dumpable = 0$/d' /etc/sysctl.conf 2>/dev/null || true
    sysctl --system >/dev/null 2>&1 || true

    rm -f /etc/logrotate.d/hardn 2>/dev/null || true

    sed -i '/^\* hard core 0$/d' /etc/security/limits.conf 2>/dev/null || true

    if [[ -d /etc/systemd/coredump.conf.d ]]; then
        rm -f /etc/systemd/coredump.conf.d/99-hardn-disable.conf 2>/dev/null || true
    fi

    sed -i '/^[[:space:]]*umask[[:space:]]\+027[[:space:]]*$/d' /etc/bash.bashrc 2>/dev/null || true

    local compiler
    for compiler in /usr/bin/gcc /usr/bin/g++ /usr/bin/as /usr/bin/cc; do
        if [[ -f "$compiler" ]]; then
            chmod 755 "$compiler" 2>/dev/null || true
            chown root:root "$compiler" 2>/dev/null || true
        fi
    done

    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
        ufw --force disable >/dev/null 2>&1 || true
    fi
}

finalize() {
    if [[ $finalized -eq 1 ]]; then
        return
    fi
    finalized=1
    undo_hardening_changes
    cleanup_resources
}

trap finalize EXIT

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This test suite must be run as root." >&2
        exit 1
    fi
}

print_banner() {
    echo -e "${BLUE}${TITLE}${NC}"
    printf '%*s\n' "${#TITLE}" '' | tr ' ' '='
    echo
}

record_result() {
    local status="$1" message="$2"
    checks+=("${status}: ${message}")
    case "$status" in
        FAIL) failures+=("${message}") ;;
        WARN) warnings+=("${message}") ;;
    esac
}

log_section() {
    echo
    echo -e "${BLUE}== $1 ==${NC}"
}

expect_file_attrs() {
    local path="$1" perms="$2" owner="$3" group="$4" label="$5"
    if [[ ! -e "$path" ]]; then
        record_result "FAIL" "${label}: ${path} is missing"
        return
    fi
    local current
    if ! current=$(stat -c '%a %U %G' "$path" 2>/dev/null); then
        record_result "FAIL" "${label}: unable to stat ${path}"
        return
    fi
    local current_perms current_owner current_group
    read -r current_perms current_owner current_group <<<"${current}"
    if [[ "$current_perms" == "$perms" && "$current_owner" == "$owner" && "$current_group" == "$group" ]]; then
        record_result "PASS" "${label}: ${path} permissions ${perms} ${owner}:${group}"
    else
        record_result "FAIL" "${label}: expected ${perms} ${owner}:${group}, found ${current_perms} ${current_owner}:${current_group}"
    fi
}

expect_pattern_in_file() {
    local pattern="$1" file="$2" label="$3"
    if [[ ! -f "$file" ]]; then
        record_result "FAIL" "${label}: ${file} missing"
        return
    fi
    if grep -Eq "$pattern" "$file"; then
        record_result "PASS" "${label}: ${file} contains expected configuration"
    else
        record_result "FAIL" "${label}: expected pattern absent in ${file}"
    fi
}

expect_sysctl() {
    local key="$1" expected="$2" label="$3"
    local value
    if ! value=$(sysctl -n "$key" 2>/dev/null); then
        record_result "FAIL" "${label}: sysctl ${key} not readable"
        return
    fi
    if [[ "$value" == "$expected" ]]; then
        record_result "PASS" "${label}: ${key}=${value}"
    else
        record_result "FAIL" "${label}: expected ${key}=${expected}, found ${value}"
    fi
}

expect_mount_option() {
    local mount_point="$1" option="$2" label="$3"
    local opts
    if ! opts=$(findmnt -no OPTIONS "$mount_point" 2>/dev/null); then
        record_result "FAIL" "${label}: ${mount_point} not mounted"
        return
    fi
    if [[ ",${opts}," == *",${option},"* ]]; then
        record_result "PASS" "${label}: ${mount_point} includes ${option}"
    else
        record_result "FAIL" "${label}: ${mount_point} missing ${option} (options: ${opts})"
    fi
}

expect_mount_readwrite() {
    local mount_point="$1" label="$2"
    local opts
    if ! opts=$(findmnt -no OPTIONS "$mount_point" 2>/dev/null); then
        record_result "FAIL" "${label}: ${mount_point} not mounted"
        return
    fi
    if [[ ",${opts}," == *",rw,"* ]]; then
        record_result "PASS" "${label}: ${mount_point} mounted read/write"
    else
        record_result "FAIL" "${label}: ${mount_point} not mounted read/write (options: ${opts})"
    fi
}

create_test_user() {
    TEST_USER="hardn_test_${RANDOM}${RANDOM}"
    if id "$TEST_USER" >/dev/null 2>&1; then
        userdel -rf "$TEST_USER" >/dev/null 2>&1 || true
    fi
    if useradd --create-home --shell /bin/bash "$TEST_USER" >/dev/null 2>&1; then
        echo "$TEST_USER:$TEST_PW" | chpasswd >/dev/null 2>&1 || {
            record_result "FAIL" "AUTH-9328: unable to set password for ${TEST_USER}"
            return 1
        }
        record_result "PASS" "AUTH-9328: temporary test user ${TEST_USER} created"
        return 0
    fi
    record_result "FAIL" "AUTH-9328: unable to create temporary test user"
    TEST_USER=""
    return 1
}

remove_test_user() {
    if [[ -n "$TEST_USER" ]]; then
        if id "$TEST_USER" >/dev/null 2>&1; then
            userdel -rf "$TEST_USER" >/dev/null 2>&1 || userdel "$TEST_USER" >/dev/null 2>&1 || true
            record_result "PASS" "AUTH-9328: temporary test user ${TEST_USER} removed"
        fi
        TEST_USER=""
    fi
}

check_user_lockout() {
    log_section "Authentication & lockout"

    if ! create_test_user; then
        return
    fi

    local status_line
    if status_line=$(passwd -S "$TEST_USER" 2>/dev/null); then
        # passwd -S output: user STATUS ...; STATUS of L means locked, P means password set
        local state
        state=$(awk '{print $2}' <<<"${status_line}")
        if [[ "$state" == "P" ]]; then
            record_result "PASS" "AUTH-9328: ${TEST_USER} password status indicates usable account"
        else
            record_result "FAIL" "AUTH-9328: ${TEST_USER} password state is ${state} (expected P)"
        fi
    else
        record_result "WARN" "AUTH-9328: unable to query passwd status for ${TEST_USER}"
    fi

    if command -v pam_tally2 >/dev/null 2>&1; then
        local tally failcount
        tally=$(pam_tally2 --user "$TEST_USER" 2>/dev/null | awk 'NR==2 {print $2}')
        if [[ -n "$tally" ]]; then
            failcount=$tally
            if (( failcount < 5 )); then
                record_result "PASS" "AUTH-9328: ${TEST_USER} pam_tally2 failcount ${failcount} (<5)"
            else
                record_result "FAIL" "AUTH-9328: ${TEST_USER} pam_tally2 failcount ${failcount}"
            fi
        else
            record_result "WARN" "AUTH-9328: unable to parse pam_tally2 output for ${TEST_USER}"
        fi
    elif command -v faillock >/dev/null 2>&1; then
        # faillock output includes Failures field
        local failcount
        failcount=$(faillock --user "$TEST_USER" 2>/dev/null | awk -F': ' '/^Failures/ {print $2}')
        if [[ -n "$failcount" ]]; then
            if (( failcount == 0 )); then
                record_result "PASS" "AUTH-9328: ${TEST_USER} faillock shows 0 failures"
            else
                record_result "FAIL" "AUTH-9328: ${TEST_USER} faillock failure count ${failcount}"
            fi
        else
            record_result "WARN" "AUTH-9328: unable to parse faillock output for ${TEST_USER}"
        fi
    else
        record_result "WARN" "AUTH-9328: pam_tally2/faillock not available to verify counters"
    fi

    if runuser -l "$TEST_USER" -c 'id -u' >/dev/null 2>&1; then
        record_result "PASS" "AUTH-9328: ${TEST_USER} can spawn a session"
    else
        record_result "FAIL" "AUTH-9328: ${TEST_USER} failed to start a session"
    fi

    remove_test_user
}

check_login_controls() {
    log_section "Configuration checks"
    expect_pattern_in_file 'pam_tally2\.so.*deny=5' /etc/pam.d/common-auth "AUTH-9328 lockout policy"
    expect_pattern_in_file 'pam_wheel\.so.*group=sudo' /etc/pam.d/su "AUTH-9218 su restriction"
    expect_pattern_in_file '^ENCRYPT_METHOD\s+SHA512' /etc/login.defs "AUTH-9260 password hashing"
    expect_pattern_in_file '^[[:space:]]*umask[[:space:]]+027' /etc/profile "AUTH-9308 umask profile"
    expect_pattern_in_file 'session[[:space:]]+optional[[:space:]]+pam_umask\.so' /etc/pam.d/common-session "AUTH-9308 pam umask"
}

check_file_permissions() {
    log_section "Critical file permissions"
    expect_file_attrs /etc/passwd 644 root root "FILE-6310 passwd"
    expect_file_attrs /etc/shadow 640 root shadow "FILE-6310 shadow"
    expect_file_attrs /etc/group 644 root root "FILE-6310 group"
    expect_file_attrs /etc/gshadow 640 root shadow "FILE-6310 gshadow"
    expect_file_attrs /etc/crontab 600 root root "FILE-6430 crontab"
    expect_file_attrs /boot/grub/grub.cfg 400 root root "FILE-6430 grub.cfg"
    expect_file_attrs /etc/ssh/sshd_config 600 root root "SSH-7408 sshd_config"
}

check_mounts() {
    log_section "Mount sanity"
    expect_mount_option /tmp nodev "Mount /tmp nodev"
    expect_mount_option /tmp nosuid "Mount /tmp nosuid"
    expect_mount_option /tmp noexec "Mount /tmp noexec"
    expect_mount_option /home nodev "Mount /home nodev"
    expect_mount_readwrite / "Root filesystem"
}

check_kernel_settings() {
    log_section "Kernel parameters"
    expect_sysctl net.ipv4.ip_forward 0 "KRNL-6000 ip_forward"
    expect_sysctl net.ipv6.conf.all.forwarding 0 "KRNL-6000 ipv6 forwarding"
    expect_sysctl kernel.randomize_va_space 2 "KRNL-6000 ASLR"
    expect_sysctl fs.suid_dumpable 0 "KRNL-6000 suid_dumpable"
    expect_sysctl kernel.kptr_restrict 1 "KRNL-6010 kptr"
    expect_sysctl kernel.dmesg_restrict 1 "KRNL-6010 dmesg"
    expect_sysctl kernel.yama.ptrace_scope 1 "KRNL-6010 ptrace"
}

check_apparmor() {
    log_section "AppArmor posture"
    if ! systemctl list-unit-files | grep -q '^apparmor\.service'; then
        record_result "WARN" "MACF-6250: AppArmor service not available on this system"
        return
    fi
    if systemctl is-active --quiet apparmor; then
        record_result "PASS" "MACF-6250: AppArmor service active"
    else
        record_result "FAIL" "MACF-6250: AppArmor service not active"
    fi
    if command -v aa-status >/dev/null 2>&1; then
        local aa_output enforce complain
        aa_output=$(aa-status 2>/dev/null || true)
        enforce=$(grep -oE '[0-9]+ profiles are in enforce mode' <<<"${aa_output}" | awk '{print $1}')
        complain=$(grep -oE '[0-9]+ profiles are in complain mode' <<<"${aa_output}" | awk '{print $1}')
        if [[ -n "$enforce" ]]; then
            record_result "PASS" "MACF-6250: ${enforce} profiles currently enforced"
        fi
        if [[ -n "$complain" && "$complain" -ne 0 ]]; then
            record_result "PASS" "MACF-6250: ${complain} profiles remain in complain mode (non-strict)"
        else
            record_result "WARN" "MACF-6250: No profiles reported in complain mode; review AppArmor strictness"
        fi
    else
        record_result "WARN" "MACF-6250: aa-status unavailable; unable to confirm profile modes"
    fi
}

check_services() {
    log_section "Service health"
    if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
        if systemctl is-active --quiet fail2ban; then
            record_result "PASS" "AUTH-9328: Fail2Ban service active"
        if command -v fail2ban-client >/dev/null 2>&1; then
                if fail2ban-client status sshd >/dev/null 2>&1; then
                    record_result "PASS" "AUTH-9328: Fail2Ban sshd jail loaded"
                else
                    record_result "WARN" "AUTH-9328: Fail2Ban sshd jail not reported"
                fi
            else
                record_result "WARN" "AUTH-9328: fail2ban-client command unavailable"
            fi
        else
            record_result "FAIL" "AUTH-9328: Fail2Ban service not active"
        fi
    else
        record_result "WARN" "AUTH-9328: Fail2Ban service not installed"
    fi

    if systemctl list-unit-files | grep -q '^auditd\.service'; then
        if systemctl is-active --quiet auditd; then
            record_result "PASS" "AUDIT-9004: auditd service active"
        else
            record_result "FAIL" "AUDIT-9004: auditd service not active"
        fi
    else
        record_result "WARN" "AUDIT-9004: auditd service not installed"
    fi

    if command -v ufw >/dev/null 2>&1; then
        local ufw_status tmpfile
        tmpfile=$(mktemp /tmp/hardn-ufw-XXXX)
        if ufw status >"$tmpfile" 2>&1; then
            ufw_status=$(cat "$tmpfile")
            if grep -q "Status: active" <<<"${ufw_status}"; then
                record_result "PASS" "FIRE-4532: UFW status active"
            else
                record_result "FAIL" "FIRE-4532: UFW not active"
            fi
            if grep -q "Default: deny (incoming)" <<<"${ufw_status}" && grep -q "Default: allow (outgoing)" <<<"${ufw_status}"; then
                record_result "PASS" "FIRE-4532: UFW default policies as expected"
            else
                record_result "WARN" "FIRE-4532: UFW default policies differ from baseline"
            fi
        else
            record_result "WARN" "FIRE-4532: Unable to query UFW status"
        fi
        rm -f "$tmpfile"
    else
        record_result "WARN" "FIRE-4532: UFW command not available"
    fi
}

run_lynis_audit() {
    log_section "Lynis audit"
    if ! command -v lynis >/dev/null 2>&1; then
        record_result "WARN" "Lynis not installed; skipping full audit"
        return
    fi

    mkdir -p "$(dirname "$LYNIS_REPORT")"
    LYNIS_LOG=$(mktemp /tmp/hardn-lynis-XXXX.log)

    local audit_cmd
    audit_cmd=(lynis audit system --no-colors --quiet --report-file "$LYNIS_REPORT")
    if command -v timeout >/dev/null 2>&1; then
        audit_cmd=(timeout 300 "${audit_cmd[@]}")
    fi

    if "${audit_cmd[@]}" >"$LYNIS_LOG" 2>&1; then
        local hardening_index
        hardening_index=$(grep -i 'hardening index' "$LYNIS_LOG" | tail -n1 | awk -F': ' '{print $2}')
        if [[ -n "$hardening_index" ]]; then
            record_result "PASS" "Lynis hardening index: ${hardening_index}"
        else
            record_result "PASS" "Lynis audit completed (see ${LYNIS_REPORT})"
        fi
    else
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            record_result "WARN" "Lynis audit timed out after 5 minutes"
        else
            record_result "FAIL" "Lynis audit failed (exit code ${rc}); check ${LYNIS_LOG}"
        fi
    fi
}

summarise() {
    echo
    for entry in "${checks[@]}"; do
        echo "- ${entry}"
    done

    echo
    local pass_count=$(( ${#checks[@]} - ${#failures[@]} - ${#warnings[@]} ))
    echo -e "${GREEN}PASS${NC}: ${pass_count}"
    echo -e "${YELLOW}WARN${NC}: ${#warnings[@]}"
    echo -e "${RED}FAIL${NC}: ${#failures[@]}"

    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo
        echo "Warnings:" >&2
        for warning in "${warnings[@]}"; do
            echo "  * ${warning}" >&2
        done
    fi

    if [[ ${#failures[@]} -eq 0 ]]; then
        echo
        echo -e "${GREEN}Overall result: PASS${NC}"
        overall_rc=0
    else
        echo
        echo -e "${RED}Overall result: FAIL${NC}"
        for failure in "${failures[@]}"; do
            echo "  * ${failure}" >&2
        done
        overall_rc=1
    fi
}

main() {
    ensure_root
    print_banner
    check_user_lockout
    check_login_controls
    check_file_permissions
    check_mounts
    check_kernel_settings
    check_apparmor
    check_services
    run_lynis_audit
    summarise
}

main "$@"

exit $overall_rc
