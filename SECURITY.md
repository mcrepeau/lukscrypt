# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security reports. Use GitHub's private
vulnerability reporting: on this repository, go to **Security → Advisories →
"Report a vulnerability"** and file a private advisory. That notifies the
maintainer directly and lets us coordinate a fix and disclosure.

You can expect an acknowledgement within 7 days. If the report is accepted, we
will credit you in the release notes (unless you prefer otherwise) and publish a
fixed release before any public disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest release (v1.8.x) | ✅ |
| Older releases | ❌ — please upgrade |

Only the latest release line receives security fixes.

## Threat model and hardening

LUKSCrypt's security model and the controls in place are documented in the
README's [Security considerations](README.md#security-considerations) section.
The essentials:

- **TLS is required in production** — put the app behind a TLS-terminating
  reverse proxy; never expose port 8080 on an untrusted network.
- **The container runs `privileged`** (needed for dm-crypt, loop devices and
  mounts) — this grants full kernel access, so restrict network exposure.
- **No auto-unlock by design** — vault credentials never rest on the NAS, so
  physical theft of the machine does not expose vault contents.
- Credentials (passwords, keyfiles, API tokens) are never passed as command-line
  arguments, are hashed/ephemeral at rest, and all auth is rate-limited per IP.

If you believe you have found a vulnerability, please report it as above — thank
you for helping keep LUKSCrypt safe.
