# Roadmap

Command Center is in active development. This roadmap is directional, not a
commitment — priorities shift with feedback. Have an opinion? Open a
[Discussion](https://github.com/techfather-glitch/command-center/discussions).

## Now (beta)

The core experience is built and stable:

- ✅ Command-deck home, topology-first networking, compute cockpit, app-centric
  operations, live media floor
- ✅ 40+ provider catalog with a common provider contract
- ✅ Realtime SSE, encrypted secret vault, security gate (CSRF / rate-limit /
  SSRF / audit)
- ✅ Responsive layouts for phone / tablet / desktop / ultrawide
- ✅ Opt-in authentication, reverse-proxy / HTTPS awareness
- ✅ Guided first-run setup
- ✅ Demo mode for evaluation and documentation

## Next

- **Notification channels** — in-app, email, Discord, Slack, webhook — with
  per-event control and test/preview.
- **More provider adapters** — Unraid, Proxmox Backup Server, Scrutiny detail,
  Beszel, Glances, and community requests.

## Later

- **Automation surface** — schedules, background-job health, retry policy view.
- **Backups** — one-click config export/import is here; scheduled + encrypted
  snapshots and cloud targets are planned.
- **Per-endpoint TLS policy** — opt-in certificate verification per provider,
  retiring the blanket LAN relaxation.
- **Developer tools** — an in-app API explorer and webhook tester.
- **Theming** — additional accent palettes and a light theme.

## Non-goals

- **Becoming a monitoring backend.** Command Center reads from Prometheus,
  Grafana, Node Exporter and friends — it doesn't replace them.
- **A plugin marketplace / heavy framework.** Providers are plain data objects
  on purpose. Zero dependencies is a feature.
- **Controlling everything.** Where a provider owns an action better in its own
  UI, we deep-link to it rather than reimplementing it.

See the [CHANGELOG](CHANGELOG.md) for what's already shipped.
