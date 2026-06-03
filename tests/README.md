# HARDN test harness

A flat, TAP-style test directory that covers the parts of HARDN we can
verify without root + a real VM. Every file under `tests/{static,unit,
integration,cargo}/*.t.{sh,py}` is independently executable; the
orchestrator at `tests/run-all.sh` runs them all, rolls up totals, and
writes a Markdown report into `tests/reports/`.

```
sudo apt-get install shellcheck systemd python3-yaml   # one-time prereqs
bash tests/run-all.sh
```

The report path is printed on the last line of stdout, e.g.
`tests/reports/test-report-20260603-120000.md`.

## What's covered

| Suite | What it checks | Needs |
|---|---|---|
| `static/shellcheck` | `shellcheck -S error` on every shell file | `shellcheck` |
| `static/python-syntax` | `py_compile` on every `src/*.py` | `python3` |
| `static/yaml-lint` | `yaml.safe_load` on every workflow YAML | `python3-yaml` |
| `static/systemd-verify` | `systemd-analyze verify` on every unit | `systemd-analyze` |
| `static/doc-hygiene` | no em-dashes / AI-tell adjectives / vendor strings in docs | -- |
| `unit/env-detect` | container-host / nftables / cloud-LB CIDR predicates | -- |
| `unit/preflight` | required-vs-optional exit-code logic via mocked `apt-cache` | -- |
| `unit/functions` | HARDN_STATUS no-color when not a TTY; distro detection | -- |
| `unit/alerts-payload` | canonical `{ts,severity,source,message,key}` shape | `python3` |
| `integration/cli-help` | `hardn --help` lists current flags; `run-tool <missing>` -> 127 | `cargo` |
| `integration/sentry-flow` | first-run baseline + drift detection + alert write | `cargo`, writable `/etc/cron.d` |
| `integration/uninstall-dryrun` | every PR-E cleanup path is mentioned in `--dry-run` output | root |
| `integration/api-endpoints` | FastAPI TestClient on every endpoint + bearer-auth contract + /metrics shape | `fastapi`, `psutil` |
| `cargo/cargo-test` | `cargo test --bin hardn` and `--bin hardn-monitor` | `cargo` |

## What this harness does *not* cover

Some HARDN behaviour can only be exercised against a real Debian/Ubuntu
host because it mutates kernel state, package state, or systemd state.
Those stay in the manual shakedown checklist in `docs/BUG_REPORT.md`:

* Actual `sysctl -w` applies and persistence across reboot.
* `auditctl -R` rule loading (kernel permissions).
* Real `ufw` / `iptables` / `nftables` rule writes.
* `apt install` of `suricata`, `clamav`, `aide` (network + root).
* `systemctl start hardn.service` and friends in a privileged systemd
  container (the harness runs in CI containers where pid 1 isn't systemd).

If you need to verify any of those, follow the steps in
`docs/supported-platforms.md` and re-run the harness on each target
release.

## Conventions

Each suite emits TAP. The trailing summary line is what the orchestrator
parses:

```
# unit/env-detect totals: total=8 pass=8 fail=0 skip=0
```

A suite that can't run (missing prereq) prints a single
`ok N - # SKIP <reason>` and exits 0. The orchestrator reports it as
skipped, not failed.

## Adding a new suite

1. Drop a file into `tests/{static,unit,integration,cargo}/<name>.t.sh`
   (or `.t.py`).
2. `source "$SUITE_DIR/lib/assert.sh"` near the top of a shell suite.
3. Call `tap_plan N` once, then your `assert_*` helpers, then
   `tap_summary` at the end. Exit code = `tap_summary`'s return.
4. Smoke it locally with `bash tests/run-all.sh`. The Markdown report
   under `tests/reports/` will pick it up automatically.

## Reports

`tests/reports/` is gitignored. Each run writes a fresh timestamped
file. Commit one only when attaching it to a bug report.
