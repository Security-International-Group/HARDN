![HARDN Logo](docs/assets/IMG_1233.jpeg)
# Bug Report Template

Important
- During the testing phase, bugs are to be reported, not fixed. We will plan and schedule patches after local testing is complete.
- Target platforms: Debian 12–13 and Ubuntu 24.04
- Goal: 10 consecutive front-to-back tests with zero errors

1. Report Summary
- Brief title:
- Short description:

2. Environment
- HARDN version (commit or tag):
- Platform (Debian 12/13 or Ubuntu 24.04):
- VM details (vCPUs, RAM, disk):

3. Preconditions
- Installed from: .deb / source / other
- Services enabled (hardn.service, legion-daemon.service, hardn-api.service, hardn-monitor.service):
- Any non-default settings:

4. Steps to Reproduce
- Step 1:
- Step 2:
- Step 3:

5. Expected Result
- What should happen:

6. Actual Result
- What happened instead:
- Error messages (copy/paste):

7. Logs and Artifacts
- Relevant journal logs:
  - journalctl -u hardn.service --since "<time>"
  - journalctl -u legion-daemon.service --since "<time>"
  - journalctl -u hardn-api.service --since "<time>"
  - journalctl -u hardn-monitor.service --since "<time>"
- Attach snippets or files if possible

8. Severity
- Low / Medium / High / Critical
- Impact (functional, performance, security, packaging):

9. Workarounds
- Any known temporary mitigations:

10. Notes
- Additional context:
- Related issues/PRs:
