# Screenshots

These images are captured from the **real application in demo mode** — no
mockups, no fabricated dashboards, and no real infrastructure.

## How to (re)capture

```bash
DEMO=1 node server.js      # http://localhost:8888, fully synthetic homelab
```

Then capture each page at the target viewport. File names referenced by the
README:

| File | Route | Viewport |
|---|---|---|
| `home-desktop.png` | `/#/dashboard` | 1440×900 |
| `networking-desktop.png` | `/#/networking` | 1440×900 |
| `compute-desktop.png` | `/#/compute` | 1440×900 |
| `applications-desktop.png` | `/#/applications` | 1440×900 |
| `media-desktop.png` | `/#/media` | 1440×900 |
| `settings-desktop.png` | `/#/settings` | 1440×900 |
| `home-phone.png` | `/#/dashboard` | 390×844 |
| `home-tablet.png` | `/#/dashboard` | 834×1112 |

Demo data drifts slightly over time (charts move, the live badge pulses), so
each capture looks alive.
