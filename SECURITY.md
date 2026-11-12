# Security Policy

## Scope

This policy covers the Quarry plugin code itself — its engine, agents, skills,
workflows, and CI artifacts. Vulnerabilities in targets that Quarry tests
(DVWA, Juice Shop, etc.) are out of scope; report those to their respective
maintainers.

## Reporting a Vulnerability

**Preferred:** open a [GitHub Security Advisory](https://github.com/mahumadad/quarry/security/advisories/new)
on this repository. This keeps the report private until a fix is available.

If you cannot use Security Advisories, email the maintainer directly
(contact information is in the GitHub profile).

Please include:

- Affected component (engine module, skill, workflow, CI action)
- Steps to reproduce
- Impact assessment
- Suggested fix, if you have one

## Response Timeline

| Step | Target |
|------|--------|
| Acknowledge report | 48 hours |
| Triage and severity assessment | 7 days |
| Fix available | 90 days |

Critical issues (scope bypass, evidence tampering, credential exposure) are
prioritized and may be patched faster.

## Bug Bounty

There is no bug bounty program at this time.

## Disclosure

We follow coordinated disclosure. Once a fix is released, reporters are
credited in the CHANGELOG (unless they prefer anonymity).
