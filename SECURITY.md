# Security Policy

Command Center handles credentials for the services in your homelab, so we take
security seriously and design for it (see the posture in
[ARCHITECTURE.md](ARCHITECTURE.md#security-posture)).

## Supported versions

Command Center is pre-1.0 and ships from `main`. Security fixes land on `main`
and in the latest tagged release. Please run a recent version.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the impact, and steps to reproduce.

We aim to acknowledge reports within **72 hours** and to ship a fix or
mitigation as quickly as the severity warrants. We'll credit you in the release
notes unless you prefer to remain anonymous.

## Scope

In scope:

- The server (`server.js`): auth, the secret vault, SSRF/CSRF defenses, the
  provider proxies, the audit log.
- The client (`app.html`): XSS, token leakage, CSRF.
- Deployment guidance in this repo.

Out of scope:

- Vulnerabilities in the third-party services you connect (report those
  upstream).
- Issues that require an already-compromised host or a malicious LAN operator.
- The relaxed TLS verification for self-signed LAN providers — this is a
  documented, deliberate trade-off for homelab use. If you have a cleaner design
  (per-endpoint opt-in verification), that's a welcome contribution.

## Hardening checklist for operators

- Set `DASHBOARD_PASSWORD` if the dashboard is reachable beyond a fully trusted
  network.
- Put it behind a TLS-terminating reverse proxy and set `PUBLIC_URL`.
- Keep the data directory (`/app/data`) private — it holds the encrypted vault
  and its key.
- Don't expose Command Center directly to the internet without authentication in
  front of it.
