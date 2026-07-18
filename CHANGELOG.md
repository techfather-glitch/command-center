# Changelog

All notable changes to Command Center are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.9.22] — 2026-07-18

### Added
- **Capability build — reads batch 2** (from the API audit):
  - **Immich**: a **storage gauge** (disk % used), **background-job activity** (processing / failed counts), disk used/total, and version.
  - **Netdata**: reports its **version** alongside the alarm counts.

## [2.9.21] — 2026-07-18

### Changed
- **UniFi is faster.** Two fixes: a short server-side fresh-cache so rapid polls and multiple open tabs
  share one controller fetch instead of each hammering it, and the integration now remembers which API
  path shape your controller answers on (UniFi OS proxy vs legacy `/api/s`) so it stops wasting a dead
  request every poll.

### Added
- **UniFi device control — restart + device-aware LED colors.** In the Networking page's Device control
  panel (still behind the opt-in switch): every device gets a **Restart** button (with a confirm), and the
  **LED color palette now appears only on devices that actually support a colored LED** — most UniFi APs
  accept on/off/locate but ignore color in firmware, so the swatches show only where they'll do something.
  (Client controls — block / reconnect / forget — are already wired server-side; their UI lands next.)

## [2.9.20] — 2026-07-17

### Added
- **Full-capability build — reads batch 1 (from the 53-service API audit).** A parallel audit mapped every
  integration's real API — **556 extra readable fields** and **~1,740 actions**, saved as a structured
  capability map to drive the rollout. First verified reads landed:
  - **AdGuard**: blocklists (count + total rules), **Safe Browsing**, **Parental control**, and **DNSSEC** state.
  - **Traefik**: real **backend health** (X/Y upstreams UP, from each service's `serverStatus`) and the reported version.
  - More reads + the master **Service control** switch (gating every action, destructive ones confirmed) land in following batches.

## [2.9.19] — 2026-07-17

### Fixed
- **Installable PWA + working mobile icons.** The old tab icon was injected by JavaScript as an SVG
  data-URI, which phones don't pick up — so there was no home-screen icon and it wouldn't install.
  Command Center now serves a proper **web manifest**, real **PNG app icons** (192 / 512 / maskable,
  rendered server-side with zero dependencies), an **apple-touch-icon** for iOS, a theme-aware **SVG
  favicon**, and a **service worker**. It installs to your phone's home screen with the real logo and
  runs standalone (its own window). Use your browser's **Add to Home Screen / Install**.
  - Android's install *prompt* needs a secure context — open the dashboard over your **https** reverse-proxy
    domain and it becomes installable; iOS "Add to Home Screen" works over plain LAN too. The service
    worker caches the app shell for offline and never intercepts `/api/` (live data + SSE always hit the network).

## [2.9.18] — 2026-07-17

### Changed
- **New logo — the targeting-reticle mark.** Rebuilt to match the brand mark you provided: a reticle with
  four teal locator ticks around a hexagonal split-C core and a teal center dot. It's a theme-aware vector,
  so it reads light on a dark theme and dark on a light one automatically (device-based) and stays crisp at
  every size. The full reticle shows in the login / onboard hero and the sidebar; a bolder compact cut is
  used where it's small; and the **browser-tab favicon** now swaps light/dark with your OS theme too.

## [2.9.17] — 2026-07-17

### Fixed
- **UniFi Locate no longer gets stuck blinking.** The button's on/off state lived only in the button, so
  the 20-second auto-refresh rebuilt it "off" — and the next click sent another *start*-locate instead of
  *stop*, leaving the LED flashing until you stopped it in the UniFi app. Locate is now a proper toggle
  that survives refreshes (the button reads **Stop** while active) and auto-stops after 2 minutes as a
  safety net.

### Added
- **qui shows real torrent activity, not just "instances up".** The tile now aggregates across your
  connected qBittorrent instances — total torrents, downloading, seeding, paused, errored, and live
  down/up speed — pulled from each instance's stats (one lightweight call apiece).

## [2.9.16] — 2026-07-17

### Added
- **UniFi: authenticate with an API key *or* username/password.** Each UniFi instance now has an auth
  choice in its config. Pick **API key** to use UniFi's official Integration API (`X-API-KEY`) — handy when
  the account has 2FA/SSO that blocks password login — or keep **username/password** for the richer session
  API. The key is stored encrypted like any other credential, and you can switch anytime.

### Notes
- The two paths expose different things. Username/password (the session API) carries the fuller
  per-device/WAN stats and is the one that drives **LED override + flash-to-locate**. The API key's
  Integration API is read-only for the dashboard and can't control LEDs — so if an instance is in key mode,
  the Device control lane says so.

## [2.9.15] — 2026-07-17

### Added
- **UniFi device control (opt-in).** The Networking page has a new **Device control** panel with a master
  switch — **off by default**. Turn it on and every UniFi device gets controls: **Locate** (blink its LED
  to find it), **LED On / Off / Auto**, and a **color + brightness** picker for devices with RGB LEDs.
  Commands are sent server-side using your saved controller login; nothing is ever written unless you flip
  the switch, and the switch is remembered. This is the UniFi integration's first *write* capability —
  everything else stays read-only.

### Notes
- Works with both UniFi OS (UDM / Cloud Key gen2+, via the CSRF-token'd proxy API) and legacy self-hosted
  controllers. Color and brightness apply only to devices with RGB status LEDs; all devices accept Locate
  and On/Off/Auto. If the UniFi account you configured is read-only, control commands report "unauthorized".

## [2.9.14] — 2026-07-17

### Changed
- **A proper logo.** Command Center now has a real mark — a central core linked by four spokes to four
  nodes (one command center unifying everything around it). It replaces the generic placeholder glyph in
  the sidebar and on the login / onboard screens, and it's now the **browser-tab favicon** too (the tab
  previously had no icon at all).

## [2.9.13] — 2026-07-17

### Changed
- **The whole home screen is now a customizable board.** Hit **Customize home** and every element —
  each KPI (Health, Streams, WAN, CPU, Memory, Storage, Changes), every panel (needs-attention, live
  activity, recent changes, fleet, quick actions), and every integration tile — becomes a block you
  can rearrange with a **true pointer drag** (mouse *and* touch, with a floating preview that drops
  into place), **resize** by dragging its corner (1–12 columns wide), or **hide**. Hidden blocks tuck
  into a tray you can restore from, and **Reset layout** returns to defaults. The arrangement saves
  automatically. Defaults mirror the previous layout, so nothing looks different until you start moving things.

### Fixed
- The old tile drag-and-drop used native HTML5 dragging — jumpy on desktop and completely dead on
  touch. It's now a real pointer drag that works the same with a mouse or a finger.

## [2.9.12] — 2026-07-17

### Changed
- **Weather moved off the tile grid into a clean top-right chip.** Instead of a dashboard tile, current
  conditions now sit where you'd expect them — a compact chip in the top-right: in the header on every
  page, and at the top of Home on desktop (where the header gives way to the hero). At a glance it shows
  the sky condition and current temperature; click it for feels-like, today's high/low, humidity, wind and
  your location, plus a one-tap **°C/°F** switch (remembered per device).

### Added
- Weather now reads the actual sky condition (WMO code → icon with day/night variants + label), pulled
  alongside the readings it already fetched — no extra API calls.

## [2.9.11] — 2026-07-17

### Added
- **The tile-enrichment pass, finished across the whole catalog.** Every remaining integration that had
  more to show now shows it — almost all of it pulled from data those services *already return*, so tiles
  get richer with no heavier polling. Hide anything you don't want with the per-tile field toggles (2.9.9).
  - **DNS / proxy** — AdGuard: avg query latency · Pi-hole: unique clients + cached · Traefik: middleware count.
  - **Monitoring** — Prometheus: down targets + scrape pools · Uptime Kuma / Gatus / Healthchecks: an explicit "Up" count · Alertmanager: warning count · Glances: 5-min load + core count.
  - **Media** — Tautulli: direct-play count · Immich: user count · Audiobookshelf: book/podcast split + a library list · Sonarr / Radarr / Lidarr: "Cutoff unmet" (upgrades still wanted) · Prowlarr: total grabs + queries.
  - **Storage / infra** — Synology: RAM + firmware version · Proxmox Backup: per-datastore usage list · CrowdSec: unique-IP count · Gotify: high-priority count · Paperless: correspondents · Mealie: categories.
  - **Feeds** — Weather: feels-like, humidity, and wind alongside the daily high/low.
- The handful that add a field via a new call (the *arr "Cutoff unmet", Prowlarr stats, Weather conditions)
  use a single **optional** request, so a service that lacks the endpoint degrades quietly rather than erroring.

## [2.9.10] — 2026-07-17

### Added
- **More stats on more tiles — all from data those services already return.** Following Plex / SABnzbd /
  Overseerr in 2.9.9: **Jellyfin** adds Series + Albums, **Portainer** adds Images / Stacks / Volumes,
  **Proxmox** adds a VMs/LXC split + Storage %, **Nextcloud** adds Active-24h + Shares (and reports its
  version), and **TrueNAS** adds Cores (and its version). Trim any you don't want with the per-tile field
  toggles from 2.9.9.

## [2.9.9] — 2026-07-17

### Added
- **Pick which fields show on each service tile.** Every integration's config (Settings → Providers →
  Configure) now lists its stats as chips — click to **add or remove** any field from that service's
  dashboard tile. Saved per service.
- **Richer stats on the sparse tiles.** Plex now shows **Transcodes** and **Direct** (not just Streams),
  SABnzbd adds **ETA** and **Status**, and Overseerr / Jellyseerr adds **Processing**, **Available** and
  **Declined** — all derived from data those services already return. Trim any you don't want with the new
  per-tile field toggles.

## [2.9.8] — 2026-07-17

### Fixed
- **Settings → About now shows the real version.** The version was a hardcoded `2.0.0-gauge` string,
  so `/api/meta` and the About page reported the wrong release no matter what was actually running. It's
  now read from `package.json` (and the Docker image ships `package.json` so it's correct in the
  container too) — About will read the true version from here on.

## [2.9.7] — 2026-07-17

### Fixed
- **Mobile "Live activity" wording no longer breaks awkwardly.** The Direct Play / Transcode mode
  badges wrapped mid-phrase ("Direct" / "Play"), and the "Live activity · who's on it" header collided
  with its "N streams · updated" meta on narrow screens. Badges now stay on one line, and the header
  stacks cleanly on phones.

## [2.9.6] — 2026-07-17

### Added
- **Every service can carry an external URL, not just catalog integrations.** The External URL field
  is now on the native-provider forms (TrueNAS, Tracearr, Node Exporter, cAdvisor, Prometheus, Loki)
  and the Fleet & probes "Add service" form too — so any service you configure can have a public /
  reverse-proxy address, and the Internal / External open choice works for all of them.

### Changed
- **Custom tiles moved into Providers; the separate Tiles section is gone.** Bookmarks, embeds and
  custom-API tiles now live at the bottom of Settings → Providers alongside the rest of your dashboard
  content, instead of a redundant standalone section.

## [2.9.5] — 2026-07-17

### Changed
- **External URL is now the default when opening a service.** If you've set an external / public URL
  for a service, **Open** everywhere it appears — the provider card, the provider drawer, Home
  dashboard tiles and the Containers app cards — now goes to the external address by default, with the
  internal / local address kept one click away as a secondary link.

## [2.9.4] — 2026-07-17

### Fixed
- **Widget gauge rings no longer show red when a high value is *good*.** The tile gauge coloured its
  ring purely by percentage (a usage palette where ≥90% = red), so qui's "Connected 100%", Home
  Assistant "Available 99%" and Kubernetes "Nodes Ready 100%" all rendered alarming red. Gauges now
  colour by their own semantic state (green / amber / red); the usage palette stays only as the
  fallback for gauges that don't report a state (CPU, memory, disk).

## [2.9.3] — 2026-07-17

### Fixed
- **The Tiles settings section showed the Providers page.** The new **Tiles** section was wired into
  the settings rail and the body dispatcher, but not into the section-header map that validates the
  destination — so it silently fell back to Providers, making the two look identical. Tiles now
  renders its own custom-tiles page.

## [2.9.2] — 2026-07-17

### Fixed
- **Overseerr / Jellyseerr / Seer no longer show up twice.** A "Seer" monitored service and the
  Overseerr / Jellyseerr integration are the same product, but the dashboard de-dup only matched
  when the service *name contained the integration id* — and "seer" doesn't contain "overseerr", so
  both rendered as separate tiles. De-dup now also matches by shared icon identity, so the redundant
  probe collapses into the one integration tile.

## [2.9.1] — 2026-07-17

### Added
- **Internal / External open choice on Home tiles and the Containers page.** The internal-vs-external
  choice added in 2.8.1 now also appears on the Home dashboard tiles and on the Applications /
  Containers app cards — open a service by its local address or its public URL from wherever you're
  looking, not just the provider card.

## [2.9.0] — 2026-07-17

### Added
- **Customise the Home dashboard — move *and* resize tiles.** A new **Edit layout** button on
  Home turns on an edit mode: drag a tile to reorder it, and drag its bottom-right corner to
  resize — wider (1–3 columns) so a cramped tile like a multi-instance qui can show its full
  content, and taller to give it room. Nothing auto-resizes; sizing is manual and saved with the
  layout (alongside tile order). Click **Done** to lock it back to a clean, static board.

## [2.8.1] — 2026-07-17

### Added
- **Appearance: text size and font.** Settings → Appearance now has a **Text size**
  (Compact · Default · Large · Larger) and a **Font** (Inter · System · Mono · Serif)
  control — both self-hosted (no web fonts), saved per device.
- **Live Activity title preference.** Choose whether a stream reads **Episode** first
  (default), **Series** first, or **Combined** ("Show — Episode") — some people want the
  show name bigger, others the episode name. Settings → Appearance → Live Activity title.
- **Accent colours actually work now.** The Appearance colour swatches were dead (the accent
  had been pinned to teal); they recolour the live/active accent again — status green/amber/red
  stay reserved for state — with a wider palette (teal · cyan · sky · blue · indigo · violet ·
  fuchsia), applied on click and at boot.
- **Custom tiles have their own home.** Bookmarks, embeds and custom-API tiles moved out of
  Appearance into a dedicated **Tiles** settings section (and settings search finds them there).

### Changed
- **Networking only appears when you actually run a network controller.** The nav item used to
  light up for any network-category provider — a VPN (Tailscale) or a DNS filter (AdGuard/Pi-hole)
  — even without a router. It now requires a real controller (UniFi / pfSense / OPNsense / OpenWrt
  / MikroTik / Omada).
- **Compact density is noticeably tighter.** It now pulls in card and lane padding and the big
  hero figures, so the difference from Comfortable is obvious.
- **Open a service by internal *or* external address.** When a provider has both a local address
  and an external/public URL, the provider card and its drawer now offer **Internal ↗** and
  **External ↗** instead of defaulting to one — pick whichever reaches it from where you are.

## [2.8.0] — 2026-07-17

### Added
- **qui (autobrr) provider.** Add the qui qBittorrent web UI as a first-class integration
  (Settings → Integrations → qui): point it at your qui URL (default port `7476`) with an
  **X-API-Key** and its tile shows how many qBittorrent instances are wired up, how many are
  currently connected, and a badge when a qui update is available. Read-only — it reports
  state, it doesn't drive qui.
- **A second, external URL per service.** Every provider now has an optional **External URL**
  field (Settings → Integrations → Configure) for a public / reverse-proxy address such as
  `sonarr.example.com`, so the service is reachable from anywhere — not just on the LAN. It
  appears as a click-to-open chip on the provider card, next to the copyable local address.
  It's a link only: the server still fetches over the local URL.

### Fixed
- **The integration search box could only find already-visible services.** The catalog
  collapses less-common integrations behind **Browse all**; typing in the search box left
  those hidden, so most of the catalog was effectively unsearchable. Search now reveals
  matches from the collapsed set too.
- **"Browse all" (and an active search) collapsed themselves after a few seconds.** A live
  status update repaints the page, and the expanded/filtered catalog only lived in the DOM,
  so every repaint silently reset it. Both states now persist across repaints.
- **Clearer error when a provider hostname won't resolve.** Pointing a provider at a bare
  container name (e.g. `http://seer:5055`) fails if Command Center isn't on that container's
  Docker network — but the old message just said "DNS lookup failed". It now recognises a
  short/container-style name and explains the fix: share a Docker network (`docker network
  connect`) or use the service's LAN IP.
- **An unconfigured service no longer shows a false error.** A native source that isn't set
  up — e.g. TrueNAS with no address or API key — reports `configured: false`, but it was
  still rendered as a degraded "auth error" on the Storage view, in the provider strips and
  in Settings. Not-configured is now treated as a calm setup prompt everywhere; only a
  *configured* service that actually fails shows an error, and it now names the real cause
  instead of a hardcoded label.
- **The provider config no longer collapses or resets mid-setup.** A background refresh (an
  SSE status flip or the 20s tick) now holds off repainting the page while you have a drawer
  open or a provider's config expanded — so the panel stays put and a field you're filling
  in can't be wiped a few seconds after you open it. The next refresh catches up once you're
  done.
- **The media "History & Problems" panel now actually populates.** Its "Recently watched"
  and "Problem streams" columns expected Tautulli watch history that the integration never
  fetched — it only polled current activity — so both stayed on the "Connect Tautulli" note
  even with Tautulli connected. Tautulli now also pulls history: recently-watched fills from
  real sessions and problem streams flags transcodes. A renamed Tautulli instance is
  detected too.

## [2.7.0] — 2026-07-08

### Added
- **Each service's local address, visible and click-to-copy.** Every provider card
  (Settings → Providers) and every concept-page provider chip now shows the service's
  `host:port` — click it to copy the full URL. The Observability service detail gets an
  Address panel too. Works for catalog integrations (incl. extra instances), native
  providers, and monitored services.
- **A Tailscale device browser.** The Tailscale card gets a **Devices ↗** button that
  opens a drawer of your whole tailnet — each device's name, **`100.x` IP (click to
  copy)**, OS, online status and last-seen, plus an "update" badge where a client update
  is available. Verified against a live tailnet.

## [2.6.1] — 2026-07-08

### Added
- **Dropped Needle grabs now appear on the Automation "Downloading" lane** alongside
  qBittorrent/SABnzbd, each with inline **Cancel** (in-flight) / **Retry** (stuck) and a
  "· N stuck · manage →" link to the full drawer. Acting from the lane refreshes in place
  (no drawer pop-up), so the pipeline page is a single control surface for everything
  being acquired.

## [2.6.0] — 2026-07-08

### Fixed
- **Dropped Needle's "Downloading" count was wrong.** It counted every non-finished grab
  — including queued and *stuck/partial* ones — as "downloading", so it read e.g.
  "Downloading 5" when nothing was actually downloading. The lane now breaks the queue
  down honestly: **Downloading** (actually in flight), **Queued**, and **Stuck / failed**
  (partial + failed grabs needing attention). Verified against a live instance —
  0 downloading, 1 queued, 62 stuck/failed.

### Added
- **Manage Dropped Needle downloads from the dashboard.** The Downloads drawer now has
  per-item **Cancel** (in-flight) and **Retry** (stuck/failed), plus bulk **Retry all
  failed**, **Stop auto-retries**, and **Clear finished** — all proxied through the
  audited action route with the vaulted token, so you can clear out the stuck pile
  without opening Dropped Needle.

## [2.5.0] — 2026-07-08

### Added
- **Run multiple instances of the same service — each with its own name.** Command Center
  is no longer limited to one of each integration. Add as many as you run — e.g. three
  Sonarrs (Main · Anime · Asian) or several Bazarrs — from a provider's card via
  **+ Add another**, and give each a **Name** so they're distinct everywhere (nav, tiles,
  provider cards). Each instance keeps its own URL and key. The Automation pipeline
  (queue depth, indexers, recently-added) now sums across every instance of a type.
- **Rename any provider.** Every provider card now has a **Name** field, so you can label
  a single Sonarr "TV" or your Radarr "4K Movies" — leave it blank to keep the default.

### Notes
- An instance is stored as `type#N` (e.g. `sonarr#2`) and shares the base type's
  definition while keeping its own address, credentials and name. Verified end-to-end
  against a live second Sonarr instance.

## [2.4.0] — 2026-07-08

### Added
- **The Automation pipeline's "Library" stage now shows what actually landed.** Sonarr
  and Radarr integrations read their import history (`/api/v3/history` with
  `includeSeries`/`includeMovie`), so the Library stage lights up with today's import
  count and a new **"Recently added to library"** lane listing recent episodes and movies
  — clean titles, quality and when — newest first. No Tautulli needed: it's sourced from
  the *Arr pipeline that delivered them. Verified against live Sonarr/Radarr.

## [2.3.2] — 2026-07-08

### Fixed
- **The Automation "Downloading" stage stayed dark even with qBittorrent/SABnzbd
  connected.** The native pipeline probes resolved their *address* only from a legacy
  native-service entry — not from the catalog integration — so a download client added
  the normal way (as an integration) had working credentials but no address, and the
  stage read "Connect." Address resolution now falls back to the aliased integration's
  endpoint, mirroring how credentials already alias (`CRED_ALIASES`). The Downloading
  stage lights up with no reconfiguration. Verified end-to-end against a live qBittorrent
  (v5.1.2) and SABnzbd configured as integrations only.

### Changed
- The Automation stages now recognize integration-configured providers and guide you
  precisely: **Search** reads the Prowlarr integration's indexer count; **Grabbed** and
  **Library** prompt you to enable Sonarr/Radarr and Tautulli when they're missing rather
  than showing a bare "0/0".

## [2.3.1] — 2026-07-08

### Fixed
- **The Automation pipeline was broken on mobile.** The five-stage rail (Search →
  Grabbed → Downloading → Import & match → Library) wrapped into an overlapping,
  jumbled two-column grid on phones. It now stacks into a clean single column.
- **Made the Automation page self-explanatory.** The rail now carries an
  **"Acquisition pipeline"** header — *the path a request takes to your library, each
  stage lighting up as it's wired* — so the page's purpose is clear even on phones,
  where the header subtitle is hidden for space.

## [2.3.0] — 2026-07-07

### Added
- **Play playlists from Command Center, with a "whose playlists" picker.** The Dropped
  Needle lane gets a **Playlists** button that opens a drawer of your playlists plus the
  household's shared ones. Filter chips let you pick **whose** — *You*, or any other user
  (Alexander, Sam, …) — so you can jump straight to your own among a shared library. Hit
  **▶ Play** on any playlist and it streams track-by-track through the in-dashboard player
  (play / pause / seek / previous / next), each track showing its own cover art. Private
  playlists you can't see are marked as such rather than offered.

## [2.2.0] — 2026-07-07

### Added
- **Play your Dropped Needle library straight from Command Center — a real in-dashboard
  player.** DN's own player is browser-side with no remote-control API, so instead
  Command Center now *is* a DN player: a persistent bottom **player bar** with play /
  pause / seek / previous / next and a track queue. Press **▶ Play** on any in-library
  album (in search results or Recently Added) and its tracks stream through a new
  authenticated, **Range-capable** proxy (`/api/dn/stream`) — real seeking, and the
  vaulted session token never touches the browser. The bar lives outside the page view,
  so music keeps playing as you move between pages, and playback is reported back to DN
  so it appears in the Now Playing floor.

### Notes
- Only music that is **in your library** (already downloaded) can be played in the
  dashboard — streaming needs a real file. Music you search but don't own yet is one
  **+ Request** away and becomes playable once it finishes downloading. Dashboard
  playback streams via DN's resolved source (local / Navidrome / Jellyfin / Plex).

## [2.1.0] — 2026-07-07

### Added
- **Dropped Needle "Now Playing" is now a proper floor on the Media page.** What's
  spinning in Dropped Needle's own web player — track, artist · album, cover art,
  source (Navidrome / Jellyfin / Plex / local / YouTube), listener + device,
  paused/playing state and a live progress bar — now leads the DN lane, mirroring
  the media session floor. When connected but nothing is playing it shows an honest
  idle state instead of hiding.
- **Request music without opening Dropped Needle.** Album search results carry a
  **+ Request** button that queues the album through DN's request API
  (`POST /api/v1/requests/new`); items already in the library or already requested
  are shown as such rather than offered again. A new authenticated, audited
  `POST /api/dn/action` proxies album and track requests — the vaulted session
  token never reaches the browser.

### Notes
- Dropped Needle's playback *transport* (play / pause / skip / seek / volume) is a
  client-side heartbeat with no server API, so it can't be remote-controlled from
  the dashboard — Now Playing reflects DN's own web player, and control here means
  requesting and managing music.

## [2.0.21] — 2026-07-06

### Fixed
- **Saving UniFi credentials was slow and looked like it didn't save.** The save
  blocked on an immediate connection test, and against an unreachable controller
  the login ground through four attempts × a 10s timeout (~40s) before the save
  "finished" — so it felt like forever and the card still showed disconnected
  (the credentials always persisted; the *connect* was hanging). Now: the
  credentials save instantly and the controller is tested in the **background**;
  a login **bails on the first connection-level error** (with a 6s timeout), so
  an unreachable controller reports *"cannot reach from this server —
  VLAN/firewall"* in ~6s instead of ~40s. Measured: save 0.03s, a reachable
  controller connects in ~0.9s.

## [2.0.20] — 2026-07-06

### Fixed
- **The sidebar no longer "reloads" on refresh.** Each concept (Networking,
  Compute, Storage, Observability, Logs…) only appeared once its provider's live
  widget/probe data had arrived, so a refresh started with a sparse nav that
  filled in a beat later. The nav now decides from **configuration** (enabled
  integrations + settings, known immediately) instead of live health, backed by
  a persisted last-known set — so the complete nav renders on the very first
  paint and stays stable through load. Verified: the nav at refresh (zero live
  data) is byte-identical to the fully-loaded nav.

## [2.0.19] — 2026-07-06

### Performance
- **The dashboard no longer lags when one provider is slow or down.**
  - **Tracearr** fired three sequential requests on every poll when idle (public
    `streams` succeeds empty → two private fallbacks that 401 for a public
    token). It now returns on the first 2xx — an idle Tracearr is a single fast
    round-trip (measured ~14ms vs the old three-request chain).
  - **Enabled-integration widgets are cached server-side** (success briefly, a
    *failure* longer), so an unreachable provider is probed at most once per 20s
    instead of timing out on every poll cycle and stalling the whole refresh.
    The cache clears on any settings change and is bypassed by an explicit Test.
  - **Upstream timeouts trimmed to LAN-appropriate values** (live probe 8s→5s,
    provider fetch 12s→6s) so a single hung request can't gate a poll batch for
    long.

## [2.0.18] — 2026-07-06

### Added
- **Service discovery — scan a host, add what answers with one click.** A scan
  bar on Settings → Providers (host prefilled from services you already run) TCP-
  probes one machine across every port the catalog knows and lists whatever
  responds as clickable chips. Clicking a chip opens that provider pre-filled
  with its address — integrations land in the catalog form, native providers in
  their card — so all that's left is the credential. Shared ports list every
  possibility (`:8096` → Emby *or* Jellyfin; `:8080` → SABnzbd *or* qBittorrent…)
  so you choose. LAN-only by design: the target must resolve to a private/
  loopback address (`POST /api/discover`).

## [2.0.17] — 2026-07-06

### Fixed
- **Native providers are now fully configurable from their own card.** Tracearr,
  Node Exporter, cAdvisor, TrueNAS, Prometheus and Loki cards only exposed an
  API-key field (or nothing) — there was **no way to set their address** in the
  UI, forcing a detour through Fleet & probes. Every native provider card now
  carries an **Address (URL)** field plus its credential in one form; saving it
  configures the probe, joins the fleet automatically and lights the concept
  pages. Adding a provider is the only action — Fleet & probes remains only for
  extra watch-only services.
- The containers summary no longer probes cAdvisor's loopback default; like
  every native probe it uses the configured address or says plainly that none is
  set.
- "No address" errors now point at the right place — *open its card in
  Settings → Providers and set the URL* — instead of the old Fleet & probes
  detour.

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

[2.0.21]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.21
[2.0.20]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.20
[2.0.19]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.19
[2.0.18]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.18
[2.0.17]: https://github.com/techfather-glitch/command-center/releases/tag/v2.0.17
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
