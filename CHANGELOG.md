# Changelog

All notable changes to Command Center are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.16] — 2026-07-06

### Fixed
- **TrueNAS "API connection failed."** Node's built-in WebSocket cannot skip TLS
  verification, so every self-signed TrueNAS failed the `wss://` handshake —
  and the code then retried over **plain `ws://`, sending the API key
  unencrypted**, which is precisely what TrueNAS punishes with automatic key
  revocation. Replaced with a minimal RFC 6455 client that follows the outbound
  TLS policy; the plaintext fallback is gone (an `http://` TrueNAS endpoint is
  now refused outright, with an explanation).
- **Self-signed certificates on the LAN now work everywhere, with zero
  configuration.** One outbound TLS policy across all connectors (provider
  fetches, native probes, Grafana render, TrueNAS): self-signed is tolerated
  for **private addresses** (RFC1918/loopback IPs, `.local`/`.lan`/`.internal`/
  `.home.arpa`, single-label names); **public hostnames are always verified**.
  No more `ALLOW_INSECURE_TLS` hoop for UniFi/TrueNAS/Proxmox-class services
  (the env still force-relaxes everything; `NODE_EXTRA_CA_CERTS` remains the
  strict option).

### Added
- **One credential, everywhere.** Native fleet probes fall back to their
  integration's stored credential (TrueNAS, Plex, Emby, Sonarr, Radarr,
  SABnzbd, Overseerr/Seer, qBittorrent) — paste a key once in the provider
  card and every surface that talks to that service uses it.
- **Errors that name the actual problem.** Network failures across UniFi and
  every provider fetch are classified: *cannot reach from this server
  (VLAN/firewall)* vs *connection refused (wrong port)* vs *DNS* vs *TLS* vs
  *credentials rejected* — so an unreachable host and a bad password never look
  the same again.

## [2.0.15] — 2026-07-06

### Added
- **One add, everywhere.** Enabling a provider with a configured URL now puts it
  on the fleet automatically — health dot on Home, status sweeps, the works — no
  second manual add in Fleet & probes. Deduped against existing services by
  host:port; hosted APIs (no endpoint) are excluded; hideable by name like any
  service.

### Fixed
- The import review no longer renders native-service credentials (e.g.
  `Sonarr-Anime`) as confusing amber "URL required" rows — fleet services and
  their credentials ride along as-is (they carry their own addresses) and are
  summarized in the header instead.

## [2.0.14] — 2026-07-06

### Fixed
- **Native probes no longer default to `127.0.0.1` — the address you give a
  service is the address that gets probed.** Fleet probes (Tracearr, Node
  Exporter, TrueNAS, SABnzbd, qBittorrent, the *Arrs…) resolved their target as
  `endpoints override → hardcoded 127.0.0.1 default`, ignoring the host/port the
  user typed in Settings → Fleet & probes — inside a container that probed the
  container itself, so these services could never work and could not be pointed
  anywhere else. Resolution is now `endpoints override → the service's own
  URL/host/port → non-loopback default`, and a loopback default reads as **"not
  configured"** with a clear message instead of a bogus probe. The Tracearr
  proxy, image proxy and discover routes (three more hardcoded `127.0.0.1:30316`
  spots) follow the configured address too, including https.
- **UniFi works out of the box again** — controllers ship self-signed
  certificates, and strict outbound TLS verification blocked every login unless
  a global `ALLOW_INSECURE_TLS` env was set. The UniFi connector now accepts
  self-signed certs by default; set `unifi.strictTls: true` in settings to
  enforce verification for a controller with a real certificate.

### Added
- **Factory reset** (Settings → Data → "Start over") — erases all persisted
  state (settings, encrypted vault + key, audit journal) after typed
  confirmation and restarts into first-run setup. Also available as
  `POST /api/factory-reset` with `{"confirm":"ERASE"}`.

## [2.0.13] — 2026-07-05

### Fixed
- **`docker stop` no longer force-kills the container (exit 137).** Node runs as
  PID 1 in the container and gets no default signal handling, so every stop or
  update sat through Docker's 10s grace period and ended in SIGKILL. SIGTERM /
  SIGINT are now handled for a prompt, clean shutdown.

### Added
- The `LOG_REQUESTS=1` access log now **names the provider** on proxy calls —
  `POST /api/live (Sonarr) -> 502`, `POST /api/widget (truenasscale) -> 401` —
  so a failing provider is identifiable at a glance instead of an anonymous
  status code.

## [2.0.12] — 2026-07-05

### Fixed
- **A misconfigured provider could bounce a logged-in user to the lock screen.**
  The provider proxies (`/api/live`, `/api/widget`) relay the upstream service's
  HTTP status — and the client treated *any* 401 as "session expired". So one
  provider with a bad/stale credential (easy right after an import) answered 401
  and the dashboard threw up the sign-in screen even though the session was
  valid, looking exactly like a login loop. Real session rejections are now
  marked with a `WWW-Authenticate: CC-Session` header and the client only shows
  the lock screen for those; provider 401s surface as provider errors on their
  tiles.
- **Fonts and bundled icons were missing from the Docker image** —
  `.dockerignore` excluded `assets/fonts` and `assets/icons`, so containers
  404'd the self-hosted Inter/Geist fonts (falling back to system fonts) and
  bundled icons like Dropped Needle's. The image now ships them.

## [2.0.11] — 2026-07-05

### Fixed
- **Login loop caused by container restarts.** Sessions were kept in memory, so
  every restart wiped them and instantly invalidated your session cookie (the
  logs' *"cookie WAS sent but is not a valid session"*), forcing a re-login — and
  if the container was restart-looping (e.g. OOM), you could never stay signed
  in. Sessions are now **stateless signed tokens** (`<expiry>.<HMAC-SHA256>` keyed
  by the persistent vault key), validated with no server-side store, so a session
  survives restarts and works across replicas. Tampered/expired tokens are
  rejected; logout clears the cookie (tokens self-expire at their 12h TTL).

## [2.0.10] — 2026-07-05

### Added
- **`LOG_REQUESTS=1` — full per-request access log.** One line per request with
  method, path, status, timing, and whether a session cookie was sent — so a
  login/session problem is visible request by request (e.g. `POST /api/login ->
  200` followed by a bounced `GET /api/status -> 401 cc_session=sent` shows the
  browser is replaying an old cookie). Off by default; the startup summary shows
  its state.

## [2.0.9] — 2026-07-05

### Added
- **Diagnostic auth logging in the container log.** Startup now prints whether
  sign-in is on (and whether it comes from `DASHBOARD_PASSWORD` or a UI-set
  password), plus the effective `TRUST_PROXY`, `PUBLIC_URL` and `COOKIE_SECURE`.
  Each login logs its result, the detected request scheme, and whether the
  session cookie is issued `Secure`. And a rejected request logs the decisive
  detail for a login loop — whether the browser sent the session cookie back at
  all (*"was NOT sent — it dropped it; try COOKIE_SECURE=0"*) or sent an invalid
  one (*"did the container restart?"*), throttled to one line every 4s. No
  secrets are ever logged.

## [2.0.8] — 2026-07-05

### Added
- **`COOKIE_SECURE` override** for the session cookie. A cookie flagged `Secure`
  is dropped by the browser over http, so if a reverse proxy's scheme handling is
  off the session never sticks and sign-in loops (password accepted, bounces
  straight back). Set `COOKIE_SECURE=0` to force the flag off and break the loop;
  `COOKIE_SECURE=1` forces it on; unset keeps the automatic behavior (follows the
  real transport).

## [2.0.7] — 2026-07-05

### Fixed
- **Login loop behind an authenticating reverse proxy** (Pangolin, Authelia,
  Authentik, etc.). The session cookie was `SameSite=Strict`, so when the user
  reached the dashboard via the proxy's cross-site auth redirect the browser
  withheld the cookie on that navigation — the session never stuck and the lock
  screen reappeared on every attempt. The cookie is now `SameSite=Lax`, which
  keeps the session across that redirect while still omitting it on cross-site
  sub-requests/POSTs (CSRF stays closed via the same-origin Origin/Referer gate).

## [2.0.6] — 2026-07-05

### Fixed
- **Misleading startup log.** The boot line read `Dashboard running at
  http://127.0.0.1:8888/` even though the server binds to `0.0.0.0` and is
  reachable through the mapped port / reverse proxy — which made a container log
  look like it was stuck on localhost or had "changed" its address. It now prints
  `Command Center listening on 0.0.0.0:8888` plus the real `PUBLIC_URL` when set.

## [2.0.5] — 2026-07-05

### Changed
- **The container now runs as root** so writes to a mounted data volume succeed
  regardless of which uid owns the host directory. Running non-root, the app hit
  `EACCES: permission denied` writing its vault and settings on common host
  bind-mounts, which silently prevented anything from being saved — first-run
  setup, provider config and imports all *looked* like they worked but never
  persisted. To run unprivileged instead, set `user: "<uid>:<gid>"` in your
  compose (or `--user`) and make the data directory writable by that uid.

## [2.0.4] — 2026-07-05

### Added
- **Full-backup export and a review-based import** (Settings → Data). Export now
  offers *Safe* (secrets redacted `***`, as before) and *Full backup* (includes
  your keys and passwords) so a whole configuration — credentials and all — can
  move to another instance. Import opens a **review of every provider**: edit each
  URL, see which carry a key, with a highlight on any that have a key but still
  need a URL, before anything is saved. Keys in the file are encrypted into the
  vault on save; secrets already set are kept.

### Fixed
- **The importer reported success even when the save failed.** It ignored the
  server's response and always toasted "imported ✓", so a rejected save (for
  example a cross-origin POST blocked behind a reverse proxy) looked like it
  worked while nothing persisted. It now checks the result and surfaces the real
  error.

## [2.0.3] — 2026-07-05

### Security
- **Some provider credentials were written to the plaintext settings file
  instead of the encrypted vault.** The allowlist that decides which credential
  fields get pulled into the vault (`SECRET_FIELDS`) omitted the `apikey`,
  `sessionToken`, `user` and `tokenid` field names — so the Emby API key, the
  Dropped Needle session token, and Proxmox / PBS token IDs sat unencrypted in
  `dashboard-settings.json` and rode along in config exports. Completed the
  allowlist and added a smoke test that keeps it in sync with the provider
  registry. Re-save (or re-import) the affected providers to move any existing
  secrets into the vault.

## [2.0.2] — 2026-07-05

### Fixed
- **Blank dashboard after first-run setup, and in demo mode.** The full-screen
  onboarding and sign-in overlays are shown/hidden with the `hidden` attribute,
  but a `.onboard { display: flex }` rule overrode the browser's built-in
  `[hidden] { display: none }` (author styles beat the UA stylesheet). So once an
  overlay was dismissed it kept painting an *empty* fixed, near-black curtain over
  the entire app — the dashboard rendered correctly underneath but was completely
  covered. Added a `[hidden] { display: none !important }` guard so anything
  hidden via the attribute genuinely stays hidden.

## [2.0.1] — 2026-07-05

### Fixed
- **Sign-in loop when `PUBLIC_URL` is https but the dashboard is opened over
  plain http** (e.g. directly at `http://<LAN-IP>:8888`). The session cookie's
  `Secure` flag was derived from `PUBLIC_URL` rather than the actual connection,
  so a browser on `http://` silently dropped the cookie and every login bounced
  straight back to the lock screen. `Secure` now tracks the real transport — a
  TLS socket or a trusted proxy's forwarded-proto header — independent of
  `PUBLIC_URL`, so a proxied https origin and a direct http LAN hit both keep the
  session. Guarded by a regression test.

## [2.0.0] — 2026-07-04

The first public release — a ground-up operations console for the homelab,
organized around concepts (not products) behind a common provider interface,
hardened across three adversarial security review passes.

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
- **Read-SSRF in the custom-tile proxy** — the customapi tile fetch was guarded
  by a two-entry denylist, leaving loopback (Docker socket / own API), all
  RFC1918, and every metadata-encoding bypass reachable. Now the host is resolved
  and loopback/link-local/metadata/unspecified are rejected while LAN stays
  allowed; the same guard covers `igFetch` and the port-probe.
- **DOM-XSS in container buttons** — inline `onclick` handlers used the HTML
  escaper `esc()` in a JS-string context, so a quote in a container name could
  break out. Switched to `esc(jstr(...))`.
- **Stored XSS (server-injected settings)** — the inline `<script>` that seeds
  client settings escaped `<` with a no-op, so a stored settings string could
  break out and inject HTML. The JSON is now `\uXXXX`-escaped (`<>&`, line
  separators) before embedding; covered by a regression test.
- **Tablet layout collapse** — every page rendered as a ~60px sliver between
  768–880px because the tablet breakpoint restored the two-column grid tracks
  but not the area map; the two now stay in sync.
- **Credential encoding** — qBittorrent and Synology logins percent-encode the
  username/password, so passwords containing `&`, `+`, `%` or `#` no longer
  silently fail authentication.
- **Keyboard accessibility** — service rows, network/storage/integration
  expanders, and Dropped Needle results are now focusable and Enter/Space
  activatable; the command palette traps focus and restores it to the opener on
  close (WCAG 2.1.1).
- **Docker daemon load** — `/api/docker/containers` is cached (single-flight,
  12s), so multiple tabs no longer fan out a stats call per container every poll.
- Emby no longer reports a healthy idle server as degraded; Settings/Applications
  search inputs are debounced.
- Self-hosted icon proxy now accepts SVGs that ship an XML prolog / doctype
  before `<svg>` (e.g. OPNsense), which were previously rejected and fell back to
  monogram placeholders.

### Removed
- Deleted a dead, Windows-only PowerShell "operator/watchdog" subsystem (~1,000
  lines) that was unreachable from the UI and errored on the Linux image, along
  with its `child_process` exec surface.

### Added
- **Smoke test suite** (`test/smoke.test.js`, Node's built-in runner, zero deps)
  — asserts every provider adapter's `normalize()` survives empty/partial data
  and shapes a realistic response correctly, plus the security primitives
  (scrypt hashing + legacy fallback, request templating, response headers,
  redaction). Wired into CI; `server.js` is now importable without binding a port.
- **Logs concept** — a dedicated fleet log floor: a container rail beside a live
  tailing viewport with a line filter and a Follow toggle (polls every 3s, and
  self-cancels the moment you leave the page). Built on the existing Docker log
  proxy; self-gates into the nav only when a real Docker host is connected.
- **Smart Home concept** — a new top-level page backed by **Home Assistant**
  (promoted out of Automation). The enriched adapter reports lights, switches,
  climate, locks, presence and device health from `/api/states`; the page pairs
  an availability ring with domain stats and an honest "needs attention" lane
  for anything unlocked, open or unavailable. Self-gates into the nav, phone
  layout included.
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

## The GAUGE foundation

The 2.0 release above is built on this ground-up redesign into an operations
console.

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

[2.0.16]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.16
[2.0.15]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.15
[2.0.14]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.14
[2.0.13]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.13
[2.0.12]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.12
[2.0.11]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.11
[2.0.10]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.10
[2.0.9]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.9
[2.0.8]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.8
[2.0.7]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.7
[2.0.6]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.6
[2.0.5]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.5
[2.0.4]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.4
[2.0.3]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.3
[2.0.2]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.2
[2.0.1]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.1
[2.0.0]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.0
