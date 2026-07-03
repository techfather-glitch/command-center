# Installation

Command Center is a single Node.js process with zero dependencies. You can run
it with Docker (recommended), Docker Compose, or bare Node.

- [Docker](#docker)
- [Docker Compose](#docker-compose)
- [Bare Node.js](#bare-nodejs)
- [Configuration](#configuration)
- [Reverse proxy & HTTPS](#reverse-proxy--https)
- [Adding providers](#adding-your-first-provider)
- [Troubleshooting](#troubleshooting)

## Docker

```bash
# Try the demo (synthetic data, no config)
docker run --rm -p 8888:8888 -e DEMO=1 ghcr.io/OWNER/command-center:latest

# Run for real (persist settings + secrets to a named volume)
docker run -d --name command-center \
  -p 8888:8888 \
  -v cc-data:/app/data \
  -e TZ=America/New_York \
  ghcr.io/OWNER/command-center:latest
```

Open <http://localhost:8888> and add your first provider in **Settings →
Providers**.

## Docker Compose

```yaml
# docker-compose.yml
services:
  command-center:
    image: ghcr.io/OWNER/command-center:latest
    container_name: command-center
    ports:
      - "8888:8888"
    volumes:
      - ./data:/app/data
    environment:
      - TZ=America/New_York
      # - DASHBOARD_PASSWORD=change-me       # require sign-in
      # - PUBLIC_URL=https://cc.example.com   # behind a reverse proxy
    restart: unless-stopped
```

```bash
docker compose up -d
```

A ready-to-edit copy lives in the repo root, and an `.env.example` documents
every variable.

## Bare Node.js

Requires **Node.js 20+** (uses the built-in global `WebSocket` and `fetch`).

```bash
git clone https://github.com/OWNER/command-center.git
cd command-center
node server.js         # listens on :8888
# or: DEMO=1 node server.js   for the synthetic demo
```

There is nothing to build and nothing to install.

## Configuration

All configuration is via environment variables. None are required.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8888` | Port to listen on. |
| `TZ` | system | Timezone for timestamps. |
| `DEMO` | off | `1` serves fully synthetic data — great for evaluating the UI. |
| `DASHBOARD_PASSWORD` | off | Require a sign-in session on every API call. |
| `DASHBOARD_PASSWORD_FILE` | off | Read the password from a file (Docker secrets). |
| `PUBLIC_URL` | — | Canonical external origin when behind a proxy, e.g. `https://cc.example.com`. |
| `TRUST_PROXY` | `1` | Honor `X-Forwarded-*` headers. Set `0` for a direct, untrusted bind. |
| `DASHBOARD_SECRET_KEY` / `_FILE` | auto | 32-byte key for the secret vault. Auto-generated and persisted if unset. |

Persisted state (settings, the encrypted vault, the audit log, the icon cache)
lives next to `server.js` — mount `/app/data` (or the app directory) to keep it
across restarts.

## Reverse proxy & HTTPS

Command Center speaks plain HTTP internally and expects TLS to be terminated by
a reverse proxy. It detects the external scheme from forwarded headers and
upgrades its session cookie to `Secure` automatically. **You never need to
expose it over plain HTTP.**

Copy-paste examples live in [`examples/reverse-proxy/`](examples/reverse-proxy):

- **Caddy** — automatic HTTPS, two lines.
- **Traefik** — labels for a Compose stack.
- **nginx** — a `server` block with the right forwarded headers.

Minimal Caddy:

```caddy
cc.example.com {
    reverse_proxy localhost:8888
}
```

Then set `PUBLIC_URL=https://cc.example.com` on the container.

## Adding your first provider

1. Open **Settings → Providers**.
2. Click **+ Add provider** and pick your service (or let auto-discovery
   pre-fill it).
3. Enter the URL and API key, click **Test**, then **Enable**.
4. The relevant concept page (Media, Networking, …) fills itself in with live
   data. Secrets are stored encrypted and never shown again.

Some providers have their own flow — e.g. **Dropped Needle** offers *Sign in
with Plex*, **qBittorrent** logs in with username/password. The card guides you.

## Troubleshooting

**The dashboard is empty / "no providers connected."**
That's expected on a fresh install — Command Center never invents data. Add a
provider in Settings, or start with `DEMO=1` to explore the UI first.

**A provider shows "unreachable" or an auth error.**
The card surfaces the real error message. Check the URL is reachable *from the
container* (not just from your laptop) and that the key is valid. Use the
**Test** button for an immediate check.

**Behind a proxy, links or cookies use `http://` or the wrong host.**
Set `PUBLIC_URL` to your external origin and make sure your proxy forwards
`X-Forwarded-Proto` and `X-Forwarded-Host` (or `Forwarded`).

**A self-signed LAN endpoint (UniFi, TrueNAS) fails TLS verification.**
These providers commonly use self-signed certs on the LAN; Command Center
tolerates that for the providers that need it. This is documented in the
security posture and revisited before any WAN exposure.

**Realtime badge says "polling" instead of "Live."**
Your proxy may be buffering Server-Sent Events. Disable proxy buffering for the
`/api/stream` path (the examples do this).
