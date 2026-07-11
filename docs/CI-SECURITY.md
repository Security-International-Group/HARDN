# CI Security Gates & Branch Protection

This documents the Sprint 0 DevSecOps gates (see `docs/SPRINT-PLAN.md`). The
workflows are in place; making them *required* needs a repo admin to run the
branch-protection step below (that part cannot be automated without admin
credentials).

## Gates in CI

| Workflow | Job | Enforces | Threat |
|----------|-----|----------|--------|
| `security.yml` | `cargo-audit` | No crate with a RUSTSEC advisory | T6 |
| `security.yml` | `cargo-deny` | Bans, license allow-list, trusted sources (`deny.toml`) | T6 |
| `security.yml` | `no-network-bind` | No `0.0.0.0` / bind-all pattern in `src/` | T1 |
| `security.yml` | `gitleaks` | No secrets in the repo history | T7 |
| `security.yml` | `dependency-review` | No new high-severity dep on PRs | T6 |
| `sbom.yml` | `cyclonedx` | CycloneDX SBOM produced per build, attached to releases | T6 / SOC2 |
| `ci.yml` | build/test | fmt, clippy `-D warnings`, tests, `.deb` build | — |
| `codeql.yml` | analyze | SAST | T5 |

## Make them required (repo admin, one time)

```bash
# Requires: gh auth login  (as an org/repo admin)
gh api -X PUT repos/Security-International-Group/HARDN/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[checks][][context]=cargo audit (RUSTSEC advisories)' \
  -f 'required_status_checks[checks][][context]=cargo deny (bans, licenses, sources)' \
  -f 'required_status_checks[checks][][context]=no 0.0.0.0 bind (T1 gate)' \
  -f 'required_status_checks[checks][][context]=gitleaks (secret scan)' \
  -f 'required_status_checks[checks][][context]=Generate CycloneDX SBOM' \
  -F 'enforce_admins=true' \
  -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -F 'required_pull_request_reviews[dismiss_stale_reviews]=true' \
  -F 'required_linear_history=true' \
  -F 'restrictions=' \
  -F 'allow_force_pushes=false' \
  -F 'allow_deletions=false'
```

Also enable, in **Settings → General / Rules**:
- **Require signed commits** (rulesets → "Require signed commits").
- **Require branches to be up to date before merging** (covered by `strict` above).

## Before flipping to required
- SHA-pin `actions/dependency-review-action` (currently `@v4`, matching the repo
  convention) — replace with the `@<sha> # v4.x` form used elsewhere.
- Confirm `GITLEAKS_VERSION` in `security.yml` is current; a stale pin fails
  loudly (by design) rather than skipping the scan.
- First run of `cargo-audit`/`cargo-deny`/`cyclonedx` compiles the tool from
  crates.io (a few minutes). Add `actions/cache` if the wall-clock matters.
