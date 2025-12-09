![hard](docs/IMG_1233.jpeg)
# HARDN Security Policy

## Supported Versions
Only versions listed below receive security updates and coordinated disclosure support. Upgrade to a supported release to receive fixes.

| Version | Supported |
| ------- | --------- |
| 1.2.35  | Yes       |
| 1.0.11  | No        |
| < 1.0   | No        |

## Reporting a Vulnerability
Report security issues privately. Do not publish exploit details in public issues or pull requests.

Preferred reporting channels:
- GitHub Security Advisory for this repository (recommended).
- Email: office@cybersynapse.com
- SIGNAL: @Teem.71

When reporting, include:
- Affected version(s)
- Short description of the issue and expected impact
- Reproduction steps or PoC (minimal, avoid production-destructive testing)
- Any logs, configs, or small sample files that help reproduce
- Contact email for follow-up

Do not send full exploit code in public. If sensitive data must be transmitted, use a private GitHub Advisory or an encrypted channel of your choice.

## Triage and Response
- Acknowledgement: within 48 hours.
- Initial triage: within 5 business days.
- Mitigation/fix plan: within 30 days for high/critical issues where feasible.
- Regular progress updates will be provided for prolonged investigations.

If coordinated disclosure is required, HARDN will work with the reporter to agree an embargo and will request a CVE when appropriate.

## Severity Classification
- Critical: Remote code execution, trivial privilege escalation, large-scale data exfiltration.
- High: Local privilege escalation, authentication bypass, significant DoS.
- Medium: Information exposure, limited DoS, configuration issues with moderate impact.
- Low: Minor misconfigurations, limited-impact findings.
- Informational: Hardening suggestions or low-risk observations.

## Handling and Disclosure
- Reports are evaluated privately. Fixes are prioritized by severity and exploitability.
- When a fix is available, HARDN will publish an advisory and notify the reporter.
- Credit is given to reporters unless they request anonymity.
- Public release will include mitigation guidance and, where applicable, CVE assignment.

## Safe Harbor
Researchers acting in good faith who follow this policy will not face legal action for their research. Avoid destructive testing against third-party systems and production data.

## Reporter Guidance & Template
Use the following template when submitting a report:

- Title:
- Affected version(s):
- Severity (your estimate):
- Description:
- Reproduction steps / PoC (minimal):
- Impact / Exploitability:
- Suggested mitigation (optional):
- Contact email:

## Operational Notes
- Do not file public issues with exploit details.
- If you cannot use GitHub Security Advisory, email office@cybersynapse.com with a concise report and preferred follow-up method.
- Sensitive attachments should be sent via a private, authenticated channel; HARDN maintainers will respond with instructions if a more secure channel is required.

## After a Fix
- Fixed vulnerabilities will be documented in release notes and advisories.
- Reporters who assist with remediation will be acknowledged unless they request otherwise.

---
