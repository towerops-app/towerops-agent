# Security Policy

## Reporting a Vulnerability

Please do not open a public issue, pull request, or discussion for a suspected
vulnerability — a public report tells everyone running the agent about the
problem at the same time it tells us.

**Preferred: [open a private security advisory](https://github.com/towerops-app/towerops-agent/security/advisories/new).**
Private vulnerability reporting is enabled on this repository. The report
stays private to you and the maintainers, the whole exchange lives on the
report itself rather than in a mail thread, and it gives us somewhere to
develop and review the fix privately before publishing. It is also how credit
and a CVE get attached if the issue warrants one.

**Alternative: email graham@towerops.net.** Use this if you would rather not
have a GitHub account involved, if the report is awkward to file through the
form, or if you are unsure whether what you have found is a vulnerability at
all — a question costs us nothing to answer.

Either route reaches the same person. Pick whichever gets the report to us
soonest; do not spend time deciding.

### What to include

The more of this you can provide, the faster a fix lands:

- The agent version (`towerops-agent` logs it at startup) and how it is
  deployed — container image tag, or a standalone binary from a release.
- What an attacker can do, and what access they need to do it. Network
  position matters here: the agent polls devices on an internal network and
  holds an API token, so reachability is often the deciding factor.
- Steps to reproduce, ideally with a minimal configuration.
- Any logs, packet captures, or crash output. Please redact agent tokens,
  SNMP community strings, and SSH credentials before sending.

### What to expect

- **Acknowledgement within 3 business days.** If you have not heard back by
  then, chase us — on an advisory, comment on it; over email, assume the
  message went astray and resend, or file an advisory instead.
- An assessment of severity and affected versions, and whether we agree it is
  a vulnerability. If we do not, we will explain why rather than going quiet.
- Progress updates at least every 10 business days while we work on a fix.
- Credit in the published advisory and the release notes, unless you would
  rather not be named. If you reported by email we will open the advisory on
  your behalf and add you as a credited reporter, so mailing us does not cost
  you the attribution.

We ask that you give us 90 days before public disclosure. If a fix is ready
sooner we will ship it sooner, and if we are still stuck at 90 days we would
rather agree an extension with you than have you sit on it indefinitely.

We do not operate a paid bug bounty.

## Supported Versions

Fixes land on the latest release. There are no long-term support branches, so
upgrading to the current version is the supported remediation path.

| Version | Supported |
| ------- | --------- |
| Latest release | Yes |
| Anything older | No |

The container image is published as
`ghcr.io/towerops-app/towerops-agent:latest`. Pinning to an exact tag is fine
and is what we recommend for reproducible deployments — just be aware that a
pinned deployment does not pick up security fixes on its own.

## Scope

This policy covers the agent in this repository: the Phoenix channel client,
the SNMP, MikroTik, SSH, LLDP, and ping pollers, the self-update mechanism,
and the published container image.

Issues in the Towerops web application or API belong to that project, which is
not hosted here. Report them by either route above anyway and we will pass
them on — do not go looking for another disclosure channel.

The following are known properties of how the agent is meant to be deployed
rather than vulnerabilities:

- The agent trusts the Towerops server it is configured to talk to. It runs
  the polling jobs that server dispatches, by design.
- Self-update replaces the agent binary with one downloaded from a URL the
  server supplies, after verifying the SHA-256 digest the server supplies
  alongside it. An operator who does not want that can run the binary from a
  directory the agent cannot write to, which is how the published image is
  built.
- Credentials the operator configures for polling (SNMP communities, SSH
  keys) are readable by the agent process. That is what they are for.

## How We Check Our Own Builds

Every release image is scanned with [Grype](https://github.com/anchore/grype)
in CI and the build fails on any finding of high severity or above, so a
vulnerable image is never promoted to `latest` or attached to a release.
Results are published to this repository's code scanning alerts. Dependency
and base image updates are proposed automatically by Dependabot.
