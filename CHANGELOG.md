# Changelog

All notable changes to Command Center are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Guided first-run setup** — a fresh install walks through the basics, an
  optional dashboard password, and connecting the first provider, then enters
  the dashboard. Re-runnable from Settings → General.
- **Sign-in gate** — when a password is set (via setup or `DASHBOARD_PASSWORD`),
  a lock screen protects the dashboard; the password is stored as a SHA-256 hash
  in the encrypted vault. Single password, no accounts.
- Public open-source release preparation: full documentation set, Docker &
  Compose deployment, reverse-proxy examples, CI, issue/PR templates.
- **Demo mode** (`DEMO=1`) — a realistic, fully synthetic homelab for evaluation
  and documentation.
- Reverse-proxy / HTTPS awareness: `TRUST_PROXY`, `PUBLIC_URL`, forwarded-header
  detection and auto-`Secure` session cookies.

## [2.0.0] — GAUGE

The ground-up redesign into an operations console.

### Added
- **GAUGE design language** — a near-black instrument-panel UI where structure
  comes from the data and color is spent only on state.
- **Command-deck home** answering health / what-changed / who's-using-resources
  at a glance.
- **Topology-first networking** — real UniFi topology map, top talkers, per-AP
  health, searchable client drawer.
- **Compute cockpit** — CPU trend, ZFS-ARC-aware memory pressure, thermal
  heat-map, top consumers, disk I/O.
- **App-centric Applications** — containers grouped into their parent apps with
  resource rollups and a detail drawer.
- **Live media floor** — realtime streams with direct-play/transcode detection
  and per-session detail.
- **Provider registry** — a single common provider contract over native sources,
  the integration catalog and probed services.
- **Realtime SSE hub** — server-sampled status/host/media fanned to every tab.
- **Server-side container summary**, self-hosted icons & fonts (no CDN),
  detail-drawer component, per-source freshness.
- **Settings as an operating system** — provider cards, live security score,
  audit-journal viewer, appearance previews, config export/import, proactive
  intelligence.
- **Responsive system** — dedicated phone / tablet / desktop / ultrawide
  behavior with full feature parity.
- **Dropped Needle** provider with a first-class in-dashboard music surface.

### Security
- Encrypted secret vault (AES-256-GCM), API-response redaction, server-side
  token proxy, CSRF protection, per-IP rate limiting, SSRF hardening, audit
  journal, opt-in authentication.

[Unreleased]: https://github.com/techfather-glitch/command-center/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.0
