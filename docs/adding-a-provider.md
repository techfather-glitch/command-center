# Tutorial: add a provider

Providers are the heart of Command Center, and adding one is deliberately small:
a single data object in `server.js`. This walks through a complete example.

## The shape

Every provider is an entry in the `INTEGRATIONS` registry:

```js
const INTEGRATIONS = {
  // …
  uptimekuma: {
    id: 'uptimekuma',
    title: 'Uptime Kuma',
    category: 'observability',        // drives which concept it feeds
    icon: 'uptime-kuma',              // dashboard-icons slug
    defaultUrl: 'http://uptime.local:3001',
    auth: { type: 'header', name: 'Authorization', field: 'key' },
    poll: 30,                         // seconds
    testRequest: 'metrics',           // which request the Test button runs
    requests: [
      { id: 'metrics', path: '/metrics', accept: 'prometheus' },
    ],
    normalize: (raw) => {
      const up = /* parse raw.metrics … */ 0;
      return {
        gauge:  { label: 'Monitors up', value: up, max: 100, unit: '%', state: 'good' },
        fields: [{ label: 'Up', value: up, kind: 'stat', state: 'good' }],
        items:  [],
      };
    },
  },
};
```

That's it. You did **not** write: a route, an auth handler, a secrets store, a
polling loop, a UI card, or concept wiring. The framework does all of that from
the descriptor.

## Auth types

| `type` | Fields | Sends |
|---|---|---|
| `header` | `name`, `field` | `name: <secret>` header |
| `query` | `name`, `field` | `?name=<secret>` |
| `bearer` | `field` | `Authorization: Bearer <secret>` |
| `basic` | `userField`, `passField` | HTTP Basic |
| `session` | `userField`, `passField` + `login` | logs in, reuses the cookie/token |
| `none` | — | no auth |

For special flows (Plex OAuth PIN, WebSocket RPC), see how `droppedneedle` and
`truenas` are implemented.

## What `normalize` returns

A plain object the client renders generically:

```js
{
  gauge:  { label, value, max, unit, state },   // one headline dial (optional)
  fields: [{ label, value, kind, state }],       // key/value stats
  bars:   [{ label, value, max, unit }],         // labeled meters
  items:  [{ label, sub, state }],               // list rows
  ok:     true,                                  // set false to signal a soft failure
}
```

`state` is one of `good | warn | bad` and is the only place color is spent.

## Test it

1. `DEMO=1 node server.js` isn't needed here — run it normally: `node server.js`.
2. Open **Settings → Providers → + Add provider**, find your provider.
3. Enter the URL + key, click **Test** (runs `testRequest`), then **Enable**.
4. Its concept page fills in with live data.

## Add the icon

Map the service name to an icon slug in `ICON_RULES` (in `app.html`):

```js
[/uptime|kuma/, 'uptime-kuma'],
```

The server self-hosts icons under `assets/icons/`, fetching any missing slug
once and caching it. Unknown services fall back to colored initials.

## Checklist before a PR

- [ ] The descriptor has no hardcoded personal URL — use a generic `defaultUrl`.
- [ ] `normalize` degrades gracefully on missing fields (never throws).
- [ ] Secrets are referenced by `field`, never logged or returned.
- [ ] You tested against a real instance and it renders.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rest.
