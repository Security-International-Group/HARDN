![HARDN Logo](assets/IMG_1233.jpeg)
# Supported Platforms

HARDN targets Debian-family Linux. The table below reflects what the CI
matrix builds on every PR. "Required" rows must pass for a PR to land;
"advisory" rows are kept in the matrix so regressions are visible but do
not block merges.

| Distro / release | Codename | Status | Notes |
|---|---|---|---|
| Debian 13 | trixie | required | Current Debian stable. Reference target. |
| Debian 12 | bookworm | advisory | Previous stable, still widely deployed. |
| Ubuntu 24.04 LTS | noble | required | Reference Ubuntu LTS for hardening + LEGION. |
| Ubuntu 26.04 LTS | questing | required | New LTS as of April 2026. nftables-only persistence. |
| Ubuntu 22.04 LTS | jammy | advisory | Older LTS; package availability tracked by preflight. |

## What the CI matrix checks

For each entry in the table, the CI workflow runs:

1. `cargo build --release --bins`
2. `cargo test --bin hardn`
3. **Preflight (`bash usr/share/hardn/tools/preflight.sh`)**. Runs
   `apt-cache policy` against every package HARDN tries to install. Fails
   fast when a package rename or drop would silently degrade the install
   at runtime.

## Per-release caveats

### Ubuntu 26.04 (questing)

- **nftables-only persistence.** `iptables-persistent` still installs but
  emits deprecation warnings; the supported persistence package is
  `nftables-persistent`. `tools/env-detect.sh::hardn_uses_nftables`
  detects the backend and `modules/hardening.sh` installs the matching
  persistence package automatically.
- **Merged `/usr`.** Symlinked since 24.04; `auditd` rules using
  `-F exe=/bin/sh` resolve via canonicalization. No HARDN action needed.
- **`kernel.unprivileged_userns_clone`.** May be absent on newer kernels
  (the knob was a Debian/Ubuntu patch; mainline now keeps it permanently
  enabled). PR-F's container-host gate already skips the write on hosts
  that run container workloads; the INFO log line "host owns this
  parameter" covers the "key not present" case too.
- **systemd 256.** No behavioural changes HARDN currently depends on.
  `soft-reboot` integration is intentionally not added (would change
  operator expectations and deserves a separate RFC).

### Ubuntu 24.04 (noble)

- Reference target. All hardening modules and tools tested here first.
- `audispd-plugins` is still a separate package; this changes on 26.04.

### Debian 13 (trixie)

- Reference Debian target. `auditd`, `apparmor`, and the GTK4 stack all
  available in main.
- `prometheus` and `prometheus-node-exporter` ship in main; no third-party
  repo needed for `tools/prometheus.sh`.

### Ubuntu 22.04 (jammy) and Debian 12 (bookworm)

- Advisory. Most features work but the GTK4 GUI may require an updated
  GTK runtime. Hardening modules and LEGION daemon are fully functional.

## Adding a new release to the matrix

1. Add a row to the `include:` list in `.github/workflows/ci.yml` with
   `required: true` or `required: false`.
2. Run `bash usr/share/hardn/tools/preflight.sh` on a fresh install of
   the release locally; fix any `miss` or `nocand` packages by renaming
   in `modules/hardening.sh` or `tools/*.sh`.
3. Update this document.

## Environment overrides relevant to platform behaviour

| Variable | Effect |
|---|---|
| `HARDN_USES_NFTABLES` | `1` forces nftables persistence path; `0` forces iptables-legacy path. Default: autodetect via `iptables --version` output. |
| `HARDN_CONTAINER_HOST` | `1` forces the container-workload-host sysctl profile (skips `unprivileged_userns_clone=0` and the eBPF lockdown). Default: autodetect from `/var/lib/docker`, `/var/lib/containers`, `kubelet`, `firejail`, etc. |
| `HARDN_STRICT_USERNS` | `1` applies `kernel.unprivileged_userns_clone=0` even on container workload hosts. |
| `HARDN_STRICT_BPF` | `1` applies the eBPF lockdown sysctls even on container workload hosts. |

See `README.md` for the complete environment override table.
