# HARDN test report

* generated: 2026-06-03 12:22:11 UTC
* commit:    `7f4e0ab Autoformat Python code with Black [198f76aa1e920ebb477524e2b919e73921d13966]`
* host:      `Linux 6.18.5 x86_64`
* os:        ubuntu 24.04 (noble)

## Suites

| Suite | Total | Pass | Fail | Skip | Exit | Duration |
|---|---:|---:|---:|---:|---:|---:|
| cargo/cargo-test.t.sh | 2 | 2 | 0 | 0 | 0 | 807ms |
| integration/api-endpoints.t.py | 1 | 0 | 0 | 1 | 0 | 282ms |
| integration/cli-help.t.sh | 5 | 5 | 0 | 0 | 0 | 205ms |
| integration/sentry-flow.t.sh | 4 | 4 | 0 | 0 | 0 | 243ms |
| integration/uninstall-dryrun.t.sh | 11 | 11 | 0 | 0 | 0 | 1043ms |
| static/doc-hygiene.t.sh | 3 | 3 | 0 | 0 | 0 | 33ms |
| static/python-syntax.t.sh | 1 | 1 | 0 | 0 | 0 | 62ms |
| static/shellcheck.t.sh | 32 | 32 | 0 | 0 | 0 | 4104ms |
| static/systemd-verify.t.sh | 4 | 4 | 0 | 0 | 0 | 246ms |
| static/yaml-lint.t.sh | 8 | 8 | 0 | 0 | 0 | 425ms |
| unit/alerts-payload.t.sh | 5 | 5 | 0 | 0 | 0 | 137ms |
| unit/env-detect.t.sh | 7 | 7 | 0 | 0 | 0 | 68ms |
| unit/functions.t.sh | 6 | 6 | 0 | 0 | 0 | 77ms |
| unit/preflight.t.sh | 1 | 0 | 0 | 1 | 0 | 9ms |

## Totals

| Metric | Count |
|---|---:|
| Suites run        | 14 |
| Suites with fails | 0 |
| Assertions        | 90 |
| Pass              | 88 |
| Fail              | 0 |
| Skip              | 2 |

## Result: PASS (with 2 skipped)

## Details

### cargo/cargo-test.t.sh

\`\`\`
1..2
ok 1 - cargo test --bin hardn: test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
ok 2 - cargo test --bin hardn-monitor: test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
# cargo/cargo-test totals: total=2 pass=2 fail=0 skip=0
\`\`\`

### integration/api-endpoints.t.py

\`\`\`
1..1
ok 1 - # SKIP starlette TestClient unavailable: The starlette.testclient module requires the httpx package to be installed.
You can install this with:
    $ pip install httpx

# integration/api-endpoints totals: total=1 pass=0 fail=0 skip=1
\`\`\`

### integration/cli-help.t.sh

\`\`\`
ok 1 - hardn binary present after build
1..5
ok 2 - hardn --help exits 0
ok 3 - --help advertises --sentry-check
ok 4 - --help advertises --enable-selinux
ok 5 - run-tool <missing> returns 127
# integration/cli-help totals: total=5 pass=5 fail=0 skip=0
\`\`\`

### integration/sentry-flow.t.sh

\`\`\`
1..4
ok 1 - first --sentry-check run exits 0
ok 2 - first run announces baseline creation
ok 3 - second --sentry-check run exits 0
ok 4 - drift produces an alert mentioning the new path
# integration/sentry-flow totals: total=4 pass=4 fail=0 skip=0
\`\`\`

### integration/uninstall-dryrun.t.sh

\`\`\`
ok 1 - uninstall script ships at the expected path
1..10
ok 2 - uninstall.sh references /etc/profile.d/hardn-paths.sh
ok 3 - uninstall.sh references hardn-gui.desktop
ok 4 - uninstall.sh references /etc/audit/auditd.conf.d/99-hardn.conf
ok 5 - uninstall.sh references /etc/fail2ban/jail.local
ok 6 - uninstall.sh references /var/lib/hardn
ok 7 - uninstall.sh references /var/log/hardn
ok 8 - uninstall.sh references /etc/hardn
ok 9 - uninstall.sh references /run/hardn
ok 10 - uninstall.sh references 99-hardn-hardening
ok 11 - dry-run exits 0
# integration/uninstall-dryrun totals: total=11 pass=11 fail=0 skip=0
\`\`\`

### static/doc-hygiene.t.sh

\`\`\`
1..3
ok 1 - no em-dashes in docs
ok 2 - no AI-tell adjectives in docs
ok 3 - no AI-vendor strings in docs
# static/doc-hygiene totals: total=3 pass=3 fail=0 skip=0
\`\`\`

### static/python-syntax.t.sh

\`\`\`
1..1
ok 1 - src/hardn-api.py
# static/python-syntax totals: total=1 pass=1 fail=0 skip=0
\`\`\`

### static/shellcheck.t.sh

\`\`\`
1..32
ok 1 - tests/cargo/cargo-test.t.sh
ok 2 - tests/integration/cli-help.t.sh
ok 3 - tests/integration/sentry-flow.t.sh
ok 4 - tests/integration/uninstall-dryrun.t.sh
ok 5 - tests/lib/assert.sh
ok 6 - tests/lib/tap.sh
ok 7 - tests/run-all.sh
ok 8 - tests/static/doc-hygiene.t.sh
ok 9 - tests/static/python-syntax.t.sh
ok 10 - tests/static/shellcheck.t.sh
ok 11 - tests/static/systemd-verify.t.sh
ok 12 - tests/static/yaml-lint.t.sh
ok 13 - tests/unit/alerts-payload.t.sh
ok 14 - tests/unit/env-detect.t.sh
ok 15 - tests/unit/functions.t.sh
ok 16 - tests/unit/preflight.t.sh
ok 17 - usr/share/hardn/modules/hardening.sh
ok 18 - usr/share/hardn/scripts/hardn-service-manager.sh
ok 19 - usr/share/hardn/scripts/hardn-uninstall.sh
ok 20 - usr/share/hardn/tools/aide.sh
ok 21 - usr/share/hardn/tools/apparmor.sh
ok 22 - usr/share/hardn/tools/auditd.sh
ok 23 - usr/share/hardn/tools/clamv.sh
ok 24 - usr/share/hardn/tools/env-detect.sh
ok 25 - usr/share/hardn/tools/fail2ban.sh
ok 26 - usr/share/hardn/tools/firejail.sh
ok 27 - usr/share/hardn/tools/functions.sh
ok 28 - usr/share/hardn/tools/grafana.sh
ok 29 - usr/share/hardn/tools/ossec.sh
ok 30 - usr/share/hardn/tools/prometheus.sh
ok 31 - usr/share/hardn/tools/suricata.sh
ok 32 - usr/share/hardn/tools/ufw.sh
# static/shellcheck totals: total=32 pass=32 fail=0 skip=0
\`\`\`

### static/systemd-verify.t.sh

\`\`\`
1..4
ok 1 - systemd/hardn-api.service
ok 2 - systemd/hardn-monitor.service
# informational: ExecStart= binary not installed on the dev box; verify what we can
# hardn-monitor.service: Command /usr/bin/hardn-monitor is not executable: No such file or directory
ok 3 - systemd/hardn.service
ok 4 - systemd/legion-daemon.service
# static/systemd-verify totals: total=4 pass=4 fail=0 skip=0
\`\`\`

### static/yaml-lint.t.sh

\`\`\`
1..8
ok 1 - .github/FUNDING.yml
ok 2 - .github/ISSUE_TEMPLATE/bug-report.yml
ok 3 - .github/codeql-config.yml
ok 4 - .github/dependabot.yml
ok 5 - .github/workflows/black.yml
ok 6 - .github/workflows/ci.yml
ok 7 - .github/workflows/codeql.yml
ok 8 - .github/workflows/test.yml
# static/yaml-lint totals: total=8 pass=8 fail=0 skip=0
\`\`\`

### unit/alerts-payload.t.sh

\`\`\`
1..5
ok 1 - alerts.jsonl written
ok 2 - every line is valid JSON
ok 3 - every record has the canonical {ts,severity,source,message,key}
ok 4 - severity is one of info/warning/error/critical
ok 5 - every key contains a category:detail separator
# unit/alerts-payload totals: total=5 pass=5 fail=0 skip=0
\`\`\`

### unit/env-detect.t.sh

\`\`\`
ok 1 - env-detect.sh ships at the expected path
1..6
ok 2 - HARDN_CONTAINER_HOST=1 forces true
ok 3 - autodetect returns a deterministic boolean
ok 4 - operator CIDR override is honoured (10.0.0.0/8)
ok 5 - operator CIDR override is honoured (192.168.0.0/16)
ok 6 - IMDS link-local always present
ok 7 - hardn_env_summary returns non-empty
# unit/env-detect totals: total=7 pass=7 fail=0 skip=0
\`\`\`

### unit/functions.t.sh

\`\`\`
ok 1 - functions.sh ships at the expected path
1..5
ok 2 - log line written through HARDN_STATUS
ok 3 - log file is free of ANSI escape codes
ok 4 - detect_distro_id returns non-empty
ok 5 - detect_distro_version returns non-empty
ok 6 - is_package_installed correctly returns false for a missing package
# unit/functions totals: total=6 pass=6 fail=0 skip=0
\`\`\`

### unit/preflight.t.sh

\`\`\`
1..1
ok 1 - # SKIP preflight.sh not on this branch (lands with the raccoon / Ubuntu 26.04 PR)
# unit/preflight totals: total=1 pass=0 fail=0 skip=1
\`\`\`
