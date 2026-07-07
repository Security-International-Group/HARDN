# Test suite expansion plan

Owner: Chauncey Pelton
Branch: `test-suite`
Status: draft, not yet started

## Why this branch exists

`tests/README.md` already lists what the harness does not cover:
kernel state, real `systemctl` state, real firewall rules, package
installs. Those are the exact things I have been checking by hand in a
VM: services not starting or stopping the way the tooling reports,
and status displays that did not match the real system.

That gap is measurable, not just a feeling. As of this branch:

* `usr/share/hardn/modules/hardening.sh` (1650 lines): no behavioral
  test, only shellcheck syntax linting.
* `usr/share/hardn/scripts/hardn-service-manager.sh` (1091 lines): no
  behavioral test, only shellcheck syntax linting.
* Together these two files are over half of all shell code in the
  project, and they are the two scripts that mutate SSH, PAM,
  sudoers, sysctl, UFW, and systemd unit state, or that report on
  that state back to a human.

Manual VM testing does not scale past one person at a time, is not
reproducible run to run, and puts all regression detection on
whoever happens to click through the checklist that day. The goal of
this branch is to convert as much of that manual verification as
possible into automated checks with a real pass/fail result, so a
regression here shows up in CI before it shows up in someone's VM.

## Broader benefit

This is not only about closing a gap I ran into personally. A few
things this changes for the project as a whole:

* Shared safety net. Right now, a change to `hardening.sh` or
  `hardn-service-manager.sh` is only as safe as whoever happens to
  boot a VM and check it by hand that day. Once these suites exist,
  anyone can touch that layer and get a real pass or fail
  before merging, not just before someone happens to notice something
  looked off.
* Numbers instead of impressions. "Is the service manager reporting
  status correctly" stops being a guess or a memory of the last time
  someone checked, and becomes a specific count of pass and fail that
  anyone can point to in a PR or a status update.
* A record for whatever the status-reporting layer becomes next.
  Whatever ends up serving status to a future web frontend, it will
  answer the same question `hardn-service-manager.sh` answers today:
  is this service actually running. Pinning down what "correct"
  means now, in tests, means that knowledge carries forward as a spec
  instead of staying something only found by testing the GUI by hand.
* Faster review. A partner picking up a PR that touches the hardening
  layer can look at which suite covers which behavior instead of
  needing to reproduce a VM to decide if a change is safe.

## Scope

In scope, in priority order:

1. `hardn-service-manager.sh` status-reporting logic (directly tied
   to the status-mismatch class of bug I ran into).
2. `hardening.sh` branching and decision logic (sysctl fallback
   selection, container-vs-host behavior, SSH lockdown gating).
3. `hardening.sh` and `hardn-service-manager.sh` end-to-end behavior
   against a disposable container or VM (real resulting system
   state, not just "the script exited 0").
4. The remaining untested tool scripts under
   `usr/share/hardn/tools/` (`suricata.sh`, `grafana.sh`, `auditd.sh`,
   etc.), once 1-3 are in a good place.

Out of scope for this branch:

* The Rust core (`legion.rs`, `main.rs`). Both are large and
  untested, but that is a separate effort from the shell hardening
  layer and does not belong mixed into this branch.
* Any GUI work. The GTK GUI is being phased out in favor of a
  lighter web frontend; this branch does not touch either.
* Anything already in flight elsewhere (webhook signing, the
  `hardn-apid` migration, etc). This branch only adds tests; it does
  not change product behavior.

## Approach: three tiers, matched to what each can prove

**Tier 1: stubbed logic tests.** No root, no VM, runs on every
commit. Put a fake `systemctl` / `ufw` / `sysctl` on `PATH` (the same
pattern `tests/unit/preflight.t.sh` already uses for a fake
`apt-cache`) and run the real script or function against it. This
proves decision logic: does the sysctl fallback get selected
correctly, does the SSH lockdown block get skipped when
`HARDN_DISABLE_SSH=0`, does the service manager report the right
status string for a given `systemctl` output. It cannot prove the
real OS ends up in the right state, only that the script would have
tried to do the right thing.

**Tier 2: disposable container tests.** Run `hardening.sh` for real
inside a throwaway container with systemd running, then assert on
the actual result: read the generated sysctl.d file, read the live
`sysctl` value, check `systemctl is-enabled`/`is-active`, parse `ufw
status`. This is closer to what the "Integration test in fresh
container" CI job already does, just extended past "the binary
exists" into "the hardening actually landed."

This is also where most of the individual tool scripts under
`usr/share/hardn/tools/` belong, since each one mostly installs a
package, writes a config file, and enables a service, and a Tier 1
stub would only prove the script called the right commands, not that
the tool ended up configured and running the way HARDN intends. A
container has its own namespace for most of what these scripts
touch, so install/config/service-state checks are meaningful there:

* `aide.sh`: no kernel interaction at all, pure userspace file
  hashing.
* `clamv.sh`, `grafana.sh`, `prometheus.sh`, `ossec.sh`: standard
  userspace daemons, install/config/service-state is exactly what a
  container proves.
* `suricata.sh`, `fail2ban.sh`: install/config/service-start fits
  here. Their enforcement behavior (actually dropping a packet,
  actually banning an IP after repeated failures) belongs with the
  Tier 3 firewall-behavior item below instead, since that is closer
  to proving effect than proving configuration.
* `ufw.sh`: rule-table generation and `ufw status` output fit here,
  because a container has its own network namespace for the rules it
  writes. Real packet-drop enforcement is a Tier 3 concern.

**Tier 3: VM tests.** Reserved for things that touch a subsystem that
is global to the host kernel rather than namespaced per container, so
a disposable container cannot own or safely exercise them:

* `auditd.sh`: `auditctl -R` talks to the kernel audit subsystem over
  netlink, and there is one audit subsystem per host, not one per
  container. Loading real rules inside a container either gets
  blocked or leaks onto whatever else shares that kernel.
* `apparmor.sh`: AppArmor is a host-kernel LSM. Profile loading and
  enforcement do not nest reliably inside a container.
* `firejail.sh`: builds sandboxes out of Linux namespaces itself, so
  running it inside a container means nested namespaces, which is
  privilege-dependent enough to default to a VM rather than assume it
  behaves in CI.
* Real firewall packet behavior for `ufw.sh` and `fail2ban.sh`
  (proving a connection actually gets dropped, or an IP actually gets
  banned, not just that the rule table looks right), and reboot
  persistence in general.

Not run on every commit; more likely a pre-release pass.

A full install-and-boot cycle for every VM test would be slow enough
that this tier stops getting run regularly, which defeats the point.
The intent is to build one golden image once, snapshot it, and for
each test restore the snapshot, run the script, assert, run it again
for the idempotency check, assert, then discard. Restoring a snapshot
takes seconds, not a full reinstall, so the goal is to make even the
VM tier cheap enough to run often instead of becoming a once-in-a-while
chore.

**Idempotency, as its own check.** Several of these scripts are
meant to be safe to re-run (`hardening.sh` truncates its sysctl file
each time; `hardn_services_lockdown` resets UFW before reapplying
rules). That is exactly the kind of thing that breaks quietly during
a future edit, so it gets its own explicit test: run the script, run
it again, assert nothing errors and the resulting state did not
change.

## Working style

This mirrors how the `feature/hardn-*` branches on `main` have
already been run, since it is a style that has worked here:

* Read the current code and the current tests before writing
  anything new. No guessing at what is already covered.
* Test-first: land a failing guard test, then the change that makes
  it pass, same as the existing `A1/A2/A3...` invariant pattern used
  in `tests/static/*.t.sh`.
* Small, single-purpose commits. One suite, or even one assertion
  group, per commit, not a large batch of tests landing at once. The
  goal is that a reviewer can read one commit and know exactly what
  changed and why without reconstructing a large diff first.
* Docs follow the existing house rule already enforced by
  `tests/static/doc-hygiene.t.sh`: no em-dashes, no stock adjectives,
  no naming a specific AI vendor in shipped prose. That rule applies
  to this file too. Commit messages are a different surface and can
  carry as much detail and attribution as is useful; they are not
  covered by that check.
* Every new suite states a specific, falsifiable claim in its own
  header comment (what it checks, what would make it fail), the same
  way the existing suites do. "Adds tests for hardening.sh" is not a
  usable commit message on its own.

## First two targets

Starting narrow, on purpose:

1. `hardn-service-manager.sh` status-detection: stub `systemctl`,
   drive it through active / inactive / failed / unit-not-found, and
   assert the reported string is correct in each case.
2. `hardening.sh`'s `write_sysctl_setting()`: already an isolated,
   named function. Stub `sysctl` to fail the primary write and
   confirm the fallback table is used; stub `hardn_in_container` to
   confirm a failure downgrades to an info log instead of a warning
   outside a container.

Once those land and the pattern feels right, the plan is to widen
Tier 1 coverage across the rest of `hardening.sh`, then start on
Tier 2.

## Next

A checklist file tracking each suite (target file, tier, status)
gets built once this plan is agreed on, so progress stays visible
and it is obvious what is done versus still open.
