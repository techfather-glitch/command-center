# Contributing to Command Center

Thanks for being here. Command Center is built to be easy to extend — a new
provider is often a single object — and contributions of all sizes are welcome.

## Ways to contribute

- **Add a provider** — the highest-leverage contribution. See below.
- **Fix a bug** — reproduce it, ideally in `DEMO=1` mode so it's shareable.
- **Improve a page or component** — the desktop layout is the reference; keep
  every feature available on mobile.
- **Improve the docs** — accuracy and clarity are features.

## Development setup

```bash
git clone https://github.com/techfather-glitch/command-center.git
cd command-center
DEMO=1 node server.js     # http://localhost:8888 with synthetic data
```

Requirements: **Node.js 20+**. There is no build step, no bundler and no
dependencies to install — edit `server.js` / `app.html` and reload.

Work against `DEMO=1` whenever you can: it gives you a full, realistic homelab
with zero setup and keeps your real infrastructure out of screenshots and bug
reports.

Run the checks before opening a PR (CI runs the same):

```bash
npm run check     # syntax-check the server
npm test          # smoke tests (Node's built-in runner, zero deps)
```

The smoke suite (`test/smoke.test.js`) asserts every provider adapter's
`normalize()` survives empty/partial data and shapes a realistic response
correctly, plus the security primitives (scrypt hashing, request templating,
response headers, redaction). If you add a provider, add a case.

## Project layout

| File | What lives here |
|---|---|
| `server.js` | Backend: HTTP routes, provider adapters, vault, SSE hub, security gate. |
| `app.html` | Frontend: router, provider registry, page renderers, GAUGE CSS. |
| `test/` | Smoke tests — `node --test`, zero dependencies. |
| `assets/` | Self-hosted icons + fonts. |
| `docs/` | Deeper guides. |
| `examples/` | Compose, env, reverse-proxy configs. |

Read [ARCHITECTURE.md](ARCHITECTURE.md) first — it explains the provider model
and the realtime design, which is most of what you need.

## Adding a provider

1. Append one object to the `INTEGRATIONS` registry in `server.js`:

   ```js
   myapp: {
     id: 'myapp', title: 'My App', category: 'observability', icon: 'myapp',
     defaultUrl: 'http://myapp.local:9999',
     auth: { type: 'bearer', field: 'token' },   // or header/query/basic/session
     poll: 30,
     testRequest: 'status',
     requests: [{ id: 'status', path: '/api/status' }],
     normalize: (raw) => ({
       fields: [{ label: 'Uptime', value: raw.status.uptime, kind: 'text' }],
       gauge:  { label: 'Load', value: raw.status.load, max: 100, unit: '%' },
       items:  [],
     }),
   }
   ```

2. Add an icon slug to `ICON_RULES` in `app.html` (or it falls back to colored
   initials).
3. Test it live via **Settings → Providers → your provider → Test**.

The framework handles auth, vaulting, redaction, SSRF-guarding, polling, the
catalog card and the concept wiring — you only describe the requests and the
normalization.

## Coding guidelines

- **Match the surrounding style.** No frameworks, no new dependencies — that's a
  core project value. If you think you need one, open a discussion first.
- **Never fake data.** If something can't be measured, render an honest empty or
  error state.
- **The server owns secrets.** Tokens must never be sent to the browser; proxy
  and normalize server-side.
- **Desktop is the reference, but parity is the rule.** Any feature you add on
  desktop must be reachable on mobile.
- **Keep it honest in the UI copy.** Say what's connected, degraded or
  unverified — never imply more than the data supports.

## Pull requests

- Keep PRs focused; one concern per PR.
- Describe *what changed and why*, and include a `DEMO=1` screenshot for UI
  changes.
- Confirm the app boots (`node server.js`) and all routes render without console
  errors.
- Never commit real credentials, IPs, hostnames or personal data. CI guards
  against common leaks, but you're the first line.

## Reporting bugs & requesting features

Use the issue templates. For bugs, a `DEMO=1` reproduction is gold. For
security issues, **do not** open a public issue — see
[SECURITY.md](SECURITY.md).

By contributing, you agree your contributions are licensed under the project's
[MIT license](LICENSE) and that you'll uphold the
[Code of Conduct](CODE_OF_CONDUCT.md).
