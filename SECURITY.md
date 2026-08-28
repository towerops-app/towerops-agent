# Security Policy

## Reporting a Vulnerability

Report security issues privately to **graham@towerops.net**. Please do not
open a public issue, pull request, or discussion for a suspected
vulnerability — a public report tells everyone running the agent about the
problem at the same time it tells us.

If you prefer to work through GitHub, you can also use
[private vulnerability reporting](https://github.com/towerops-app/towerops-agent/security/advisories/new).

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
  then, assume the mail went astray and send a follow-up.
- An assessment of severity and affected versions, and whether we agree it is
  a vulnerability. If we do not, we will explain why rather than going quiet.
- Progress updates at least every 10 business days while we work on a fix.
- Credit in the advisory and release notes, unless you would rather not be
  named.

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

Agents self-update by default, and the container image is published as
`ghcr.io/towerops-app/towerops-agent:latest`. Pinning to an exact tag is fine
and is what we recommend for reproducible deployments — just be aware that a
pinned deployment does not pick up security fixes on its own.

## Scope

This policy covers the agent in this repository: the Phoenix channel client,
the SNMP, MikroTik, SSH, LLDP, and ping pollers, the self-update mechanism,
and the published container image.

Issues in the Towerops web application or API belong to that project, but
send them to the same address and we will route them.

The following are known properties of how the agent is meant to be deployed
rather than vulnerabilities:

- The agent trusts the Towerops server it is configured to talk to. It runs
  the polling jobs that server dispatches, by design.
- Mounting the Docker socket to enable self-update grants the container
  control of the Docker daemon. This is documented, opt-in, and inherent to
  a container updating itself.
- Credentials the operator configures for polling (SNMP communities, SSH
  keys) are readable by the agent process. That is what they are for.

## How We Check Our Own Builds

Every release image is scanned with [Grype](https://github.com/anchore/grype)
in CI and the build fails on any finding of high severity or above, so a
vulnerable image is never promoted to `latest` or attached to a release.
Results are published to this repository's code scanning alerts. Dependency
and base image updates are proposed automatically by Dependabot.
