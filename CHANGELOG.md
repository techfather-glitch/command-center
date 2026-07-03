# Changelog

All notable changes to Command Center are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Password hashing upgraded from SHA-256 to **scrypt** (salted, work-factored,
  built-in); legacy digests upgrade transparently on next login. Minimum length
  raised to 12.
- Added a strict **Content-Security-Policy** and hardening headers
  (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS-behind-TLS).
- Session cookie is now **`SameSite=Strict`**; added `POST /api/logout` and
  session-token rotation on password change; the CSRF gate now requires a
  positive same-origin signal on POSTs.
- Outbound **TLS certificate verification is on by default**; self-signed
  upstreams opt in via `ALLOW_INSECURE_TLS` or `NODE_EXTRA_CA_CERTS`.
- Bounded proxied upstream response sizes.

### Fixed
- Self-hosted icon proxy now accepts SVGs that ship an XML prolog / doctype
  before `<svg>` (e.g. OPNsense), which were previously rejected and fell back to
  monogram placeholders.

### Removed
- Deleted a dead, Windows-only PowerShell "operator/watchdog" subsystem (~1,000
  lines) that was unreachable from the UI and errored on the Linux image, along
  with its `child_process` exec surface.

### Added
- **AI concept** — a new top-level page for local model runtimes. An **Ollama**
  provider reports the installed model library, what is loaded into memory, disk
  footprint and VRAM in use (all live from `/api/tags` + `/api/ps`, never faked);
  a bespoke inference deck surfaces it. The page self-gates into the nav only
  once a runtime is connected, and has an intentional phone layout.
- **Seven new providers** — Emby, Podman, Kubernetes, Incus/LXD, pfSense,
  OPNsense and Unraid, each a data-driven descriptor with health, metrics and a
  hero gauge. Brings first-class coverage to the container, virtualization,
  firewall and NAS ecosystems.
- **Provider write-actions** — control services from the dashboard, not just
  watch them: Sonarr/Radarr RSS-sync and search-missing, SABnzbd pause/resume,
  qBittorrent pause-all/resume-all. Actions run through the same authenticated,
  audited server pipeline; the client only ever names a declared action, never a
  URL, and confirm/danger actions gate before firing.
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
