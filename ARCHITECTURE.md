# Architecture

Command Center is deliberately small and boring in its foundations so the
interesting parts — the provider model and the UI — can be rich. This document
explains how it fits together.

## At a glance

```
┌─────────────────────────────────────────────────────────┐
│  Browser (app.html)                                      │
│  • one hand-written SPA, no bundler, no framework        │
│  • never talks to a provider directly                    │
│  • receives realtime updates over one SSE connection     │
└───────────────▲───────────────────────┬─────────────────┘
                │ SSE (status/host/media)│ fetch /api/*
                │                        ▼
┌─────────────────────────────────────────────────────────┐
│  server.js  (Node.js, zero npm dependencies)             │
│  • owns every secret (encrypted vault)                   │
│  • proxies + normalizes every provider                   │
│  • samples the homelab on timers, fans out over SSE      │
│  • security gate: rate-limit · CSRF · SSRF · audit       │
└───────────────┬─────────────────────────────────────────┘
                │ authenticated API calls
        ┌───────┼───────┬───────────┬──────────┐
        ▼       ▼       ▼           ▼          ▼
     Docker  UniFi   TrueNAS   Node Exp.   Plex / *Arr / …
```

## Design principles

1. **The server owns the network and the secrets.** The browser never holds a
   provider token or reaches a provider host. Every credential lives in an
   encrypted vault; the server attaches it, fetches, and returns normalized
   data. This kills an entire class of SSRF and token-exfiltration bugs.
2. **Concepts, not products.** The UI is organized around *what you want to
   know* (Media, Storage, Compute…). Products are swappable providers behind a
   common interface. A concept only appears when a provider backs it.
3. **Never fake data.** If a value can't be measured, the UI says so. There are
   no placeholder gauges, no invented thresholds, no fabricated history.
4. **Realtime first, polling as fallback.** The server samples on its own
   timers and streams deltas; N tabs cost one sampler, not N polls.

## Files

| File | Role |
|---|---|
| `server.js` | The entire backend. HTTP server, provider adapters, secret vault, SSE hub, security gate. ~5k lines, no dependencies. |
| `app.html` | The entire frontend. A single-page app: router, provider registry, page renderers, the GAUGE design system. |
| `assets/` | Self-hosted icons and fonts (no CDN — first paint never waits on a third party). |
| `services.json` | *(optional, gitignored)* declarative service list for GitOps-style setups. |
| `dashboard-settings.json` | *(runtime, gitignored)* persisted settings. Secrets are **not** here — they're in the encrypted vault. |

## The provider system

A provider is a plain data object in the `INTEGRATIONS` registry:

```js
sonarr: {
  id: 'sonarr', title: 'Sonarr', category: 'automation', icon: 'sonarr',
  defaultUrl: 'http://sonarr.local:8989',
  auth: { type: 'header', name: 'X-Api-Key', field: 'key' },
  poll: 30,
  requests: [{ id: 'status', path: '/api/v3/system/status' }, ...],
  normalize: (raw) => ({ fields: [...], items: [...], gauge: {...} })
}
```

Adding a provider means appending one object — no routing, no UI code. The
server handles auth, vaulting, redaction, SSRF-guarding, polling and testing
generically; the client renders whatever `normalize()` returns.

On the client, every source — native (Docker, UniFi, host metrics) *and* every
catalog integration *and* every probed service — is normalized once more into a
single **Provider contract** (`{ id, kind, concepts, setupState, healthState,
realtime, data, links, … }`). Nav gating, the provider cards and the page lanes
all read this contract, never the raw source. See `Providers` in `app.html`.

Special transports (session cookie login, Plex OAuth PIN, WebSocket RPC for
TrueNAS) are supported via optional descriptors on the provider — see the
`login`, `skipIfCred` and `queryTrueNas*` paths.

## Authentication

Authentication is **opt-in and env-gated** so a trusted-LAN deployment isn't
forced to log in, while a public deployment can require it:

- Set `DASHBOARD_PASSWORD` (or `DASHBOARD_PASSWORD_FILE`), or set a password in
  first-run setup, to require a session.
- Passwords are hashed with **scrypt** (built-in, salted, work-factored — no
  invented crypto), stored inside the AES-256-GCM vault; a 12-character minimum
  applies.
- `POST /api/login` verifies with a constant-time comparison and issues an
  `HttpOnly`, `SameSite=Strict` session cookie (auto-`Secure` behind TLS).
  `POST /api/logout` revokes it; the token rotates when the password changes.
- Every `/api/*` route (except the SSE stream handshake and `/api/meta`
  liveness) then requires a valid session. Sessions are in-memory with a 12h TTL.

A first-run setup flow guides the basics, an optional password, and the first
provider. Multi-user accounts and password reset are on
the [roadmap](ROADMAP.md).

## Realtime updates (SSE)

`GET /api/stream` is a Server-Sent Events endpoint with three channels:

| Channel | Source | Cadence |
|---|---|---|
| `status` | TCP-probe every configured service | 10s |
| `host` | Node Exporter scrape | 15s |
| `media` | Tracearr / media sessions | 5s |

Samplers run **only while at least one client is connected** and stop when the
last disconnects. New clients get the latest snapshot immediately on connect.
The client repaints on *state flips* (a service goes down, a stream starts), not
on every value change — continuously-moving numbers ride the normal render
ticks so the page never becomes a per-second DOM churn.

## HTTPS & reverse proxies

Command Center serves HTTP internally and is designed to sit behind a
TLS-terminating reverse proxy. It reads forwarded headers to detect the real
external scheme/host:

- `TRUST_PROXY=1` (default) honors `X-Forwarded-Proto` / `X-Forwarded-Host` /
  `Forwarded`.
- `PUBLIC_URL` pins the canonical external origin when you know it.
- Session cookies gain the `Secure` flag automatically once the request is
  detected as HTTPS.

It never needs to be served over plain HTTP to function. See
[INSTALL.md](INSTALL.md) for Caddy/Traefik/nginx examples.

## Security posture

- **Secret vault** — AES-256-GCM at rest, key file mode `0600`.
- **Redaction** — API responses return `***`, never real secret values.
- **Password hashing** — scrypt (salted, work-factored), inside the vault.
- **CSP + hardening headers** — the document ships a strict Content-Security-
  Policy plus `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
  and HSTS behind TLS.
- **CSRF** — cross-origin state-changing requests are rejected and journaled;
  the session cookie is `SameSite=Strict`.
- **Outbound TLS** — certificate verification is **on by default**; self-signed
  homelab upstreams opt in via `ALLOW_INSECURE_TLS=1` or a CA bundle.
- **Rate limiting** — per-IP token bucket (loopback exempt).
- **SSRF hardening** — fetch targets resolve from server config only; port
  probes are restricted to private ranges; proxied response sizes are bounded.
- **Audit journal** — settings/container/auth actions are appended to an
  audit log (the *fact*, never the values).

See [SECURITY.md](SECURITY.md) for the reporting process.

## The GAUGE design language

The UI is a deliberate system, documented inline in `app.html`:

- Near-black matte canvas divided into **lanes**; each domain gets **one** bespoke
  hero instrument shaped like the thing it measures.
- Color is rationed: the teal accent marks *live* pixels only; saturated
  green/amber/red mark *state* only. A nominal reading is monochrome.
- One responsive layer, appended last in the stylesheet, defines phone / tablet /
  desktop / ultrawide behavior per component.
