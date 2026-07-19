const http = require('http');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const os = require('os');
const dns = require('dns').promises;
const tls = require('tls');
const https = require('https');

const PORT = process.env.PORT ? Number(process.env.PORT) : 8888;
// Single source of truth for the version — read from package.json so /api/meta and the
// About page always match the actual release (never a hardcoded string that drifts).
let APP_VERSION = 'dev';
try { APP_VERSION = require('./package.json').version || APP_VERSION; } catch (e) { /* package.json absent → 'dev' */ }
const SERVER_STARTED_AT = Date.now();
// Writable state (settings, the encrypted vault, the audit log) lives under
// DATA_DIR so it can be mounted as a volume in Docker. Defaults to the app
// directory for a bare `node server.js` run.
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
const DASHBOARD_PATH = path.join(__dirname, 'app.html');
const ICON_DIR = path.join(__dirname, 'assets', 'icons');
const FONT_DIR = path.join(__dirname, 'assets', 'fonts');
const SETTINGS_PATH = path.join(DATA_DIR, 'dashboard-settings.json');

function readDashboardSettings() {
    try {
        if (!fs.existsSync(SETTINGS_PATH)) return {};
        const parsed = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (err) {
        console.warn('Failed to read dashboard settings:', err.message);
        return {};
    }
}

function ensureParentDir(filePath) {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
}

function writeDashboardSettings(settings) {
    const tmp = SETTINGS_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(settings || {}, null, 2));
    fs.renameSync(tmp, SETTINGS_PATH);
}

const SECRET_SENTINEL='***';
// Every credential field name any integration's `auth` descriptor can use, so
// each is pulled into the encrypted vault and never left in the plaintext
// settings file. Keep in sync with the registry (a smoke test enforces it):
//   field/userField/passField/tokenField/secretField across INTEGRATIONS, plus
//   `sessionToken` (set by the Dropped Needle sign-in flow, not an auth field).
const SECRET_FIELDS = new Set(['key', 'apikey', 'username', 'password', 'token', 'sessionToken', 'secret', 'user', 'tokenid']);
const SECRETS_PATH = path.join(DATA_DIR, 'dashboard-secrets.json');
const SECRET_KEY_PATH = path.join(DATA_DIR, 'dashboard-secret.key');

function cloneJson(value) { return JSON.parse(JSON.stringify(value || {})); }
function isSecretPlaceholder(value) { return value === SECRET_SENTINEL || value === '••••••••' || value === '********'; }
function isRealSecret(value) { return typeof value === 'string' && value.length > 0 && !isSecretPlaceholder(value); }
function atomicWriteJson(filePath, value, mode) {
    const tmp = filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(value || {}, null, 2), mode ? { mode } : undefined);
    fs.renameSync(tmp, filePath);
    if (mode) {
        try { fs.chmodSync(filePath, mode); } catch (_) {}
    }
}
function dashboardSecretKey() {
    const fileRef = process.env.DASHBOARD_SECRET_KEY_FILE;
    let raw = process.env.DASHBOARD_SECRET_KEY || '';
    if (!raw && fileRef) {
        try { raw = fs.readFileSync(fileRef, 'utf8').trim(); } catch (err) { console.warn('Failed to read DASHBOARD_SECRET_KEY_FILE:', err.message); }
    }
    if (raw) {
        const trimmed = raw.trim();
        if (/^[a-f0-9]{64}$/i.test(trimmed)) return Buffer.from(trimmed, 'hex');
        try {
            const b = Buffer.from(trimmed, 'base64');
            if (b.length === 32) return b;
        } catch (_) {}
        return crypto.createHash('sha256').update(trimmed).digest();
    }
    try {
        if (fs.existsSync(SECRET_KEY_PATH)) {
            const stored = fs.readFileSync(SECRET_KEY_PATH, 'utf8').trim();
            return Buffer.from(stored, 'base64');
        }
        const generated = crypto.randomBytes(32);
        fs.writeFileSync(SECRET_KEY_PATH, generated.toString('base64') + '\n', { mode: 0o600 });
        try { fs.chmodSync(SECRET_KEY_PATH, 0o600); } catch (_) {}
        return generated;
    } catch (err) {
        console.warn('Secret key file unavailable; using process-local fallback:', err.message);
        return crypto.createHash('sha256').update(`${__dirname}:${os.userInfo?.().username || 'dashboard'}`).digest();
    }
}
function encryptJson(value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', dashboardSecretKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value || {}), 'utf8'), cipher.final()]);
    return { v: 1, alg: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: ciphertext.toString('base64') };
}
function decryptJson(payload) {
    if (!payload || typeof payload !== 'object') return {};
    if (!payload.iv || !payload.tag || !payload.data) return payload; // tolerate old plaintext vault during migration
    const decipher = crypto.createDecipheriv('aes-256-gcm', dashboardSecretKey(), Buffer.from(payload.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
    const plain = Buffer.concat([decipher.update(Buffer.from(payload.data, 'base64')), decipher.final()]).toString('utf8');
    const parsed = JSON.parse(plain || '{}');
    return parsed && typeof parsed === 'object' ? parsed : {};
}
function readSecretVault() {
    try {
        if (!fs.existsSync(SECRETS_PATH)) return {};
        return decryptJson(JSON.parse(fs.readFileSync(SECRETS_PATH, 'utf8')));
    } catch (err) {
        console.warn('Failed to read dashboard secrets vault:', err.message);
        return {};
    }
}
function writeSecretVault(vault) {
    atomicWriteJson(SECRETS_PATH, encryptJson(vault || {}), 0o600);
}
function putSecret(vault, scope, key, value) {
    if (!isRealSecret(value)) return;
    vault[scope] = vault[scope] && typeof vault[scope] === 'object' ? vault[scope] : {};
    vault[scope][key] = value;
}
function pullSecretsIntoVault(settings, vault) {
    const clean = cloneJson(settings);
    const nextVault = cloneJson(vault);
    if (clean.apiKeys && typeof clean.apiKeys === 'object') {
        for (const service of Object.keys(clean.apiKeys)) {
            const item = clean.apiKeys[service];
            if (!item || typeof item !== 'object') continue;
            const scope = `apiKeys.${service}`;
            nextVault[scope] = nextVault[scope] && typeof nextVault[scope] === 'object' ? nextVault[scope] : {};
            for (const field of Object.keys(item)) {
                if (SECRET_FIELDS.has(field)) {
                    putSecret(nextVault, scope, field, item[field]);
                    delete item[field];
                }
            }
            if (Object.keys(item).length === 0) delete clean.apiKeys[service];
        }
        if (Object.keys(clean.apiKeys).length === 0) delete clean.apiKeys;
    }
    if (clean.unifi && typeof clean.unifi === 'object') {
        nextVault.unifi = nextVault.unifi && typeof nextVault.unifi === 'object' ? nextVault.unifi : {};
        for (const field of ['username', 'password', 'apiKey']) {
            if (Object.prototype.hasOwnProperty.call(clean.unifi, field)) {
                putSecret(nextVault, 'unifi', field, clean.unifi[field]);
                delete clean.unifi[field];
            }
        }
    }
    // Custom-tile API headers (Authorization tokens etc.) — vaulted per tile id,
    // never stored in the settings file. Removing a tile prunes its vault entry.
    if (Array.isArray(clean.customTiles)) {
        nextVault.customTiles = nextVault.customTiles && typeof nextVault.customTiles === 'object' ? nextVault.customTiles : {};
        const liveIds = new Set();
        for (const tile of clean.customTiles) {
            if (!tile || typeof tile !== 'object' || !tile.id) continue;
            liveIds.add(String(tile.id));
            if (Object.prototype.hasOwnProperty.call(tile, 'headerVal')) {
                putSecret(nextVault, 'customTiles', String(tile.id), tile.headerVal);
                delete tile.headerVal;
            }
        }
        for (const id of Object.keys(nextVault.customTiles)) if (!liveIds.has(id)) delete nextVault.customTiles[id];
        if (Object.keys(nextVault.customTiles).length === 0) delete nextVault.customTiles;
    }
    return { clean, vault: nextVault };
}
function redactDashboardSettings(settings) {
    const out = cloneJson(settings);
    const vault = readSecretVault();
    out.apiKeys = out.apiKeys && typeof out.apiKeys === 'object' ? out.apiKeys : {};
    for (const scope of Object.keys(vault)) {
        if (!scope.startsWith('apiKeys.')) continue;
        const service = scope.slice('apiKeys.'.length);
        out.apiKeys[service] = out.apiKeys[service] && typeof out.apiKeys[service] === 'object' ? out.apiKeys[service] : {};
        for (const key of Object.keys(vault[scope] || {})) out.apiKeys[service][key] = SECRET_SENTINEL;
    }
    if (Object.keys(out.apiKeys).length === 0) delete out.apiKeys;
    out.unifi = out.unifi && typeof out.unifi === 'object' ? out.unifi : {};
    for (const key of Object.keys(vault.unifi || {})) out.unifi[key] = SECRET_SENTINEL;
    if (Array.isArray(out.customTiles)) {
        for (const tile of out.customTiles) {
            if (tile && tile.id && (vault.customTiles || {})[String(tile.id)]) tile.headerVal = SECRET_SENTINEL;
        }
    }
    return out;
}
// Full config INCLUDING real secrets — for a "full backup" export that can move
// to another instance with credentials intact. The inverse of redaction: fills
// the vault's real values back into apiKeys/unifi/customTiles. The dashboard
// password hash lives under vault.auth and is deliberately NOT included.
function fullDashboardSettings() {
    const out = cloneJson(readDashboardSettings());
    const vault = readSecretVault();
    out.apiKeys = out.apiKeys && typeof out.apiKeys === 'object' ? out.apiKeys : {};
    for (const scope of Object.keys(vault)) {
        if (!scope.startsWith('apiKeys.')) continue;
        const service = scope.slice('apiKeys.'.length);
        out.apiKeys[service] = Object.assign({}, out.apiKeys[service], vault[scope]);
    }
    if (Object.keys(out.apiKeys).length === 0) delete out.apiKeys;
    if (vault.unifi && typeof vault.unifi === 'object') out.unifi = Object.assign({}, out.unifi, vault.unifi);
    if (Array.isArray(out.customTiles)) {
        for (const tile of out.customTiles) {
            if (tile && tile.id && (vault.customTiles || {})[String(tile.id)]) tile.headerVal = vault.customTiles[String(tile.id)];
        }
    }
    return out;
}
function mergeSensitiveSettings(incoming, existing) {
    const vault = readSecretVault();
    const { clean, vault: nextVault } = pullSecretsIntoVault(incoming, vault);
    writeSecretVault(nextVault);
    return clean;
}
// A native fleet probe and its catalog integration are the same real service —
// one pasted credential must serve both. When a probe's own scope is empty, fall
// back to the integration's credential (maps probe field -> integration field).
const CRED_ALIASES = {
    'TrueNAS Web UI':    ['truenasscale',  { key: 'key' }],
    'Plex Media Server': ['plex',          { key: 'token' }],
    'Emby':              ['emby',          { key: 'apikey' }],
    'Sonarr':            ['sonarr',        { key: 'key' }],
    'Radarr':            ['radarr',        { key: 'key' }],
    'Sabnzbd':           ['sabnzbd',       { key: 'key' }],
    'Seer':              ['overseerr',     { key: 'key' }],
    'Qbt':               ['qbittorrent',   { username: 'username', password: 'password' }],
};
function storedCredential(service, key) {
    const vault = readSecretVault();
    const own = ((vault[`apiKeys.${service}`] || {})[key]) || '';
    if (own) return own;
    const alias = CRED_ALIASES[service];
    if (alias && alias[1][key]) return ((vault[`apiKeys.${alias[0]}`] || {})[alias[1][key]]) || '';
    return '';
}
function storedEndpoint(service) { return ((readDashboardSettings().endpoints || {})[service] || {}).url || ''; }

/* ── Outbound TLS policy ─────────────────────────────────────────────────
   Homelab services on the LAN (UniFi, TrueNAS, Proxmox…) ship self-signed
   certificates; verifying strictly would break them all out of the box and
   force everyone through an env-var hoop. Policy: self-signed is tolerated
   for PRIVATE addresses (RFC1918/loopback IPs, .local/.lan/.internal/
   .home.arpa names, single-label LAN names); PUBLIC hostnames are always
   verified. ALLOW_INSECURE_TLS=1 still relaxes everything, and
   NODE_EXTRA_CA_CERTS remains the strict-and-correct option. */
function isPrivateHostname(hostname) {
    const h = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    if (!h) return false;
    if (net.isIP(h)) { const z = ipZone(h); return z === 'private' || z === 'loopback'; }
    if (!h.includes('.')) return true;
    return /\.(local|lan|internal|home|home\.arpa)$/.test(h);
}
function tlsRelaxedFor(urlOrHost) {
    if (ALLOW_INSECURE_TLS) return true;
    try { return isPrivateHostname(new URL(String(urlOrHost)).hostname); }
    catch (e) { return isPrivateHostname(urlOrHost); }
}
// Turn a raw network error into a sentence that names the actual problem —
// "unreachable from the server" and "bad password" must never look the same.
function describeNetErr(err, where) {
    const code = (err && err.code) || '';
    const msg = (err && err.message) || String(err || 'error');
    const at = where ? ` (${where})` : '';
    if (code === 'ECONNREFUSED') return `connection refused${at} — the port is closed there; check the URL and port`;
    if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || code === 'ETIMEDOUT' || /timed? ?out/i.test(msg)) return `cannot reach${at} from this server — host down, or a VLAN/firewall blocks this server's subnet`;
    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
        const host = String(where || '').replace(/[[\]]/g, '').split(/[/:]/)[0];   // hostname only — strip any port/path/brackets
        if (host && !host.includes('.') && host !== 'localhost' && !net.isIP(host))
            return `DNS lookup failed${at} — '${host}' looks like a container/short name this server can't resolve. If it's a Docker service, put Command Center on the same Docker network (docker network connect) or use its LAN IP instead`;
        return `DNS lookup failed${at} — use an IP address or a name this server can resolve`;
    }
    if (/certificate|self.signed|CERT_|UNABLE_TO_VERIFY|DEPTH_ZERO/i.test(msg + ' ' + code)) return `TLS certificate rejected${at} — private LAN addresses accept self-signed automatically; for public names install a valid cert or set NODE_EXTRA_CA_CERTS`;
    return msg;
}
function storedUnifiSettings() {
    const settings = readDashboardSettings();
    const u = (settings && settings.unifi && typeof settings.unifi === 'object') ? settings.unifi : {};
    const secrets = readSecretVault().unifi || {};
    return { ...u, username: secrets.username || '', password: secrets.password || '', apiKey: secrets.apiKey || '' };
}
function migrateSettingsSecretsToVault() {
    const current = readDashboardSettings();
    const vault = readSecretVault();
    const { clean, vault: nextVault } = pullSecretsIntoVault(current, vault);
    if (JSON.stringify(clean) !== JSON.stringify(current)) writeDashboardSettings(clean);
    if (JSON.stringify(nextVault) !== JSON.stringify(vault)) writeSecretVault(nextVault);
}

// Escape a JSON payload for safe embedding inside an inline <script>. JSON.stringify
// does NOT escape <, >, & or the U+2028/2029 line separators, so a stored settings
// value like a script-closing sequence would break out and inject HTML. Rewriting
// those characters as uXXXX escapes keeps the payload inert to the HTML parser while
// it still parses byte-identically as JavaScript. (fromCharCode(92) is a backslash.)
function escapeJsonForScript(s) {
    const BS = String.fromCharCode(92);
    const re = new RegExp('[<>&' + String.fromCharCode(0x2028) + String.fromCharCode(0x2029) + ']', 'g');
    return String(s).replace(re, c => BS + 'u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4));
}
function injectDashboardSettings(html) {
    const safeJson = escapeJsonForScript(JSON.stringify(redactDashboardSettings(readDashboardSettings())));
    // In demo mode, tell the client so it can pre-seed history rings — otherwise
    // hero trend charts are empty on first paint (they normally fill over minutes).
    const demoFlag = DEMO ? 'window.__CC_DEMO__=1;' : '';
    const script = `<script>${demoFlag}window.__SERVER_DASHBOARD_SETTINGS__=${safeJson};</script>`;
    // Function replacer, NOT a string: a string replacement expands $-patterns
    // ($&, $`, $', $$), so a literal $ in the settings JSON would splice raw head
    // HTML into the payload and break it. A function return is used verbatim.
    return html.replace('</head>', () => `${script}\n</head>`);
}

function unifiRequest(baseUrl, requestPath, { method = 'GET', body = null, cookies = '', csrf = '', apiKey = '' } = {}) {
    return new Promise((resolve, reject) => {
        let target;
        try { target = new URL(requestPath, baseUrl); } catch (err) { reject(err); return; }
        const lib = target.protocol === 'https:' ? require('https') : require('http');
        const payload = body ? JSON.stringify(body) : null;
        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'command-center/2.0'
        };
        if (cookies) headers.Cookie = cookies;
        if (csrf) headers['X-CSRF-Token'] = csrf;   // UniFi OS requires this on write (POST/PUT) calls
        if (apiKey) headers['X-API-KEY'] = apiKey;   // official Integration API auth
        if (payload) headers['Content-Length'] = Buffer.byteLength(payload);
        // UniFi controllers ship with a self-signed certificate, so strict TLS
        // verification would break virtually every real controller out of the
        // box (and no env knob should be required for the flagship integration).
        // Self-signed is accepted by DEFAULT here; set `unifi.strictTls: true`
        // in settings to enforce verification (e.g. a controller with a real cert).
        const strict = (() => { try { return readDashboardSettings().unifi && readDashboardSettings().unifi.strictTls === true; } catch (e) { return false; } })();
        const options = {
            method,
            headers,
            timeout: 6000,   // a reachable controller answers fast; don't sit on a dead one
            ...(target.protocol === 'https:' ? { agent: new (require('https').Agent)({ rejectUnauthorized: strict && !ALLOW_INSECURE_TLS }) } : {})
        };
        const req = lib.request(target, options, (r) => {
            let data = '';
            r.on('data', chunk => data += chunk);
            r.on('end', () => {
                let parsed = data;
                try { parsed = data ? JSON.parse(data) : {}; } catch (_) {}
                const setCookie = r.headers['set-cookie'] || [];
                resolve({ status: r.statusCode || 0, headers: r.headers, cookies: setCookie, body: parsed, raw: data });
            });
        });
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

function joinCookies(cookieLines) {
    return (cookieLines || []).map(c => String(c).split(';')[0]).filter(Boolean).join('; ');
}

function safeUnifiSettings(settings) {
    const u = (settings && settings.unifi && typeof settings.unifi === 'object') ? settings.unifi : (settings || {});
    const apiKey = String(u.apiKey || '').trim();
    const authMethod = u.authMethod === 'apikey' ? 'apikey' : (u.authMethod === 'password' ? 'password' : (apiKey ? 'apikey' : 'password'));
    return {
        url: String(u.url || '').trim().replace(/\/+$/, ''),
        username: String(u.username || '').trim(),
        password: String(u.password || ''),
        site: String(u.site || 'default').trim() || 'default',
        authMethod,
        apiKey
    };
}

function unifiDeviceKind(device) {
    const type = String(device.type || device.device_type || '').toLowerCase();
    const model = String(device.model || device.displayable_version || device.name || '').toLowerCase();
    if (type === 'ugw' || type === 'udm' || /ucg|gateway|dream machine|udm/.test(model)) return 'gateway';
    if (type === 'usw' || /usw|switch|ultra|flex/.test(model)) return 'switch';
    if (type === 'uap' || /u7|u6|uap|access point|ap /.test(model)) return 'ap';
    return type || 'device';
}

function numberOrNull(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
}

function unifiRate(...values) {
    for (const value of values) {
        const n = numberOrNull(value);
        if (n !== null) return n;
    }
    return 0;
}

function unifiDeviceName(device) {
    return device.name || device.hostname || device.mac || device.model || 'UniFi device';
}

function summarizeUnifiPort(port) {
    const rate = unifiRate(port['bytes-r'], port.bytes_r) || (unifiRate(port['rx_bytes-r'], port.rx_bytes_r) + unifiRate(port['tx_bytes-r'], port.tx_bytes_r));
    const poePower = numberOrNull(port.poe_power ?? port.poePower);
    return {
        index: port.port_idx ?? port.num_port,
        name: port.name || port.ifname || `Port ${port.port_idx || port.num_port || '?'}`,
        up: Boolean(port.up),
        speed: numberOrNull(port.speed),
        maxSpeed: numberOrNull(port.max_speed),
        media: port.media || '',
        uplink: Boolean(port.is_uplink),
        poe: Boolean(port.port_poe || port.poe_enable || (poePower && poePower > 0)),
        poePower: poePower || 0,
        errors: (numberOrNull(port.rx_errors) || 0) + (numberOrNull(port.tx_errors) || 0) + (numberOrNull(port.rx_dropped) || 0) + (numberOrNull(port.tx_dropped) || 0),
        rate,
        clientName: port.last_connection?.hostname || port.last_connection?.name || port.name || '',
        clientIp: port.last_connection?.ip || ''
    };
}

function summarizeUnifiDevice(d) {
    const state = Number(d.state ?? d.status ?? 0);
    const online = d.up === true || state === 1 || String(d.status || '').toLowerCase() === 'online';
    const kind = unifiDeviceKind(d);
    const sys = d['system-stats'] || d.system_stats || {};
    const portRows = Array.isArray(d.port_table) ? d.port_table.map(summarizeUnifiPort) : [];
    const activePorts = portRows.filter(p => p.up).length;
    const poeUsed = portRows.reduce((sum, p) => sum + (numberOrNull(p.poePower) || 0), 0);
    const radioRows = Array.isArray(d.radio_table) ? d.radio_table.map(r => ({
        band: r.radio || r.name || '',
        channel: r.channel ?? '',
        width: r.ht || r.channel_width || '',
        txPower: numberOrNull(r.tx_power),
        wifi7: Boolean(r.is_11be),
        wifi6: Boolean(r.is_11ax)
    })) : [];
    const uplink = d.uplink || d.last_uplink || {};
    const rate = unifiRate(d['bytes-r'], d.bytes_r) || unifiRate(uplink['bytes-r'], uplink.bytes_r) || (unifiRate(uplink['rx_bytes-r'], uplink.rx_bytes_r) + unifiRate(uplink['tx_bytes-r'], uplink.tx_bytes_r));
    return {
        name: unifiDeviceName(d),
        model: d.model || d.type || 'unknown',
        kind,
        id: d._id || d.device_id || '',
        mac: d.mac,
        led: { override: d.led_override || 'default', color: d.led_override_color || '', brightness: numberOrNull(d.led_override_color_brightness), colorCapable: Object.prototype.hasOwnProperty.call(d, 'led_override_color') },
        ip: d.ip || d.ip_addr || d.gateway_ip,
        online,
        version: d.displayable_version || d.version || d.fw_version,
        updateAvailable: Boolean(d.upgradable || d.upgrade_to_firmware || d.has_firmware_update),
        clients: Number(d.num_sta ?? d['user-num_sta'] ?? d.user_num_sta ?? d.guest_num_sta ?? 0) || 0,
        uptime: numberOrNull(d.uptime || sys.uptime),
        cpu: numberOrNull(sys.cpu),
        memory: numberOrNull(sys.mem),
        satisfaction: numberOrNull(d.satisfaction),
        throughput: rate,
        uplinkName: uplink.uplink_device_name || uplink.name || uplink.type || '',
        uplinkPort: uplink.uplink_remote_port || uplink.port_idx || '',
        uplinkSpeed: numberOrNull(uplink.speed || uplink.max_speed),
        portCount: portRows.length,
        activePorts,
        poeUsed,
        poeBudget: numberOrNull(d.poe_budget || d.poe_stats?.poe_budget) || 0,
        ports: portRows.slice(0, 16),
        topPorts: portRows.filter(p => p.up).sort((a, b) => (b.rate || 0) - (a.rate || 0)).slice(0, 5),
        radios: radioRows,
        overheating: Boolean(d.overheating),
        anomalies: numberOrNull(d.anomalies)
    };
}

function summarizeUnifiClient(c, apNameByMac = {}, switchNameByMac = {}) {
    const wifi = c.is_wired === false || Boolean(c.ap_mac) || Boolean(c.radio);
    const rate = unifiRate(c['bytes-r'], c.bytes_r) || (unifiRate(c['rx_bytes-r'], c.rx_bytes_r) + unifiRate(c['tx_bytes-r'], c.tx_bytes_r));
    const uplinkName = c.last_uplink_name || (wifi ? apNameByMac[String(c.ap_mac || '').toLowerCase()] : switchNameByMac[String(c.sw_mac || c.last_uplink_mac || '').toLowerCase()]) || '';
    return {
        name: c.name || c.hostname || c.ip || c.mac || 'client',
        ip: c.ip || '',
        mac: c.mac || '',
        wired: !wifi,
        network: c.network || c.last_connection_network_name || '',
        uplink: uplinkName,
        apMac: c.ap_mac || '',
        radio: c.radio || c.radio_name || '',
        proto: c.radio_proto || '',
        channel: c.channel || '',
        signal: numberOrNull(c.signal),
        satisfaction: numberOrNull(c.satisfaction),
        rate,
        rxRate: unifiRate(c['rx_bytes-r'], c.rx_bytes_r),
        txRate: unifiRate(c['tx_bytes-r'], c.tx_bytes_r),
        linkRx: numberOrNull(c.rx_rate),
        linkTx: numberOrNull(c.tx_rate),
        vendor: c.oui || c.dev_vendor || ''
    };
}

function summarizeUnifi(devices = [], clients = [], health = [], settings = {}) {
    const normalized = Array.isArray(devices) ? devices : [];
    const healthRows = Array.isArray(health) ? health : [];
    const deviceRows = normalized.map(summarizeUnifiDevice);
    const byKind = kind => deviceRows.filter(d => d.kind === kind);
    const switches = byKind('switch');
    const aps = byKind('ap');
    const gateways = byKind('gateway');
    const nameByMac = Object.fromEntries(deviceRows.filter(d => d.mac).map(d => [String(d.mac).toLowerCase(), d.name]));
    const clientRows = (Array.isArray(clients) ? clients : []).map(c => summarizeUnifiClient(c, nameByMac, nameByMac));
    const offline = deviceRows.filter(d => !d.online);
    const updates = deviceRows.filter(d => d.updateAvailable);
    const wanHealth = healthRows.find(h => /wan|www|internet/i.test(String(h.subsystem || h.name || h.type || '')));
    const wwwHealth = healthRows.find(h => String(h.subsystem || '').toLowerCase() === 'www') || wanHealth;
    const lanHealth = healthRows.find(h => String(h.subsystem || '').toLowerCase() === 'lan');
    const wlanHealth = healthRows.find(h => String(h.subsystem || '').toLowerCase() === 'wlan');
    const wanUp = wanHealth ? !/fail|down|error/i.test(String(wanHealth.status || wanHealth.state || '')) : (gateways.length ? gateways.some(g => g.online) : null);
    const topClients = clientRows.sort((a, b) => (b.rate || 0) - (a.rate || 0)).slice(0, 8);
    const weakClients = clientRows.filter(c => !c.wired && c.signal !== null).sort((a, b) => (a.signal || 0) - (b.signal || 0)).slice(0, 6);
    const expected = { gateway: 1, switches: 5, aps: Math.max(3, aps.length || 0) };
    const totalRate = unifiRate(wwwHealth?.['bytes-r'], wwwHealth?.bytes_r) || (unifiRate(wwwHealth?.['rx_bytes-r'], wwwHealth?.rx_bytes_r) + unifiRate(wwwHealth?.['tx_bytes-r'], wwwHealth?.tx_bytes_r));
    pushWanHist(totalRate);
    return {
        configured: true,
        controller: settings.url,
        site: settings.site || 'default',
        expected,
        gateway: { online: gateways.filter(d => d.online).length, total: Math.max(gateways.length, expected.gateway), devices: gateways, primary: gateways[0] || null },
        switches: { online: switches.filter(d => d.online).length, total: Math.max(switches.length, expected.switches), devices: switches },
        aps: { online: aps.filter(d => d.online).length, total: Math.max(aps.length, expected.aps), devices: aps },
        clients: {
            total: clientRows.length,
            wifi: clientRows.filter(c => !c.wired).length,
            wired: clientRows.filter(c => c.wired).length,
            top: topClients,
            weak: weakClients,
            list: clientRows.slice(0, 80)   // full(ish) client list for the network monitor
        },
        wan: {
            up: wanUp,
            ip: wanHealth?.wan_ip || wwwHealth?.ip || gateways[0]?.ip || '',
            isp: wanHealth?.isp_name || wanHealth?.isp_organization || '',
            latency: numberOrNull(wwwHealth?.latency ?? wanHealth?.latency ?? wanHealth?.uptime_stats?.WAN?.latency_average),
            availability: numberOrNull(wanHealth?.uptime_stats?.WAN?.availability ?? wanHealth?.availability),
            drops: numberOrNull(wwwHealth?.drops),
            speedtestPing: numberOrNull(wwwHealth?.speedtest_ping),
            speedtestDown: numberOrNull(wwwHealth?.xput_down),
            speedtestUp: numberOrNull(wwwHealth?.xput_up),
            rxRate: unifiRate(wwwHealth?.['rx_bytes-r'], wwwHealth?.rx_bytes_r),
            txRate: unifiRate(wwwHealth?.['tx_bytes-r'], wwwHealth?.tx_bytes_r),
            rate: totalRate,
            history: _wanHist.slice()
        },
        lan: { users: numberOrNull(lanHealth?.num_user), rxRate: unifiRate(lanHealth?.['rx_bytes-r'], lanHealth?.rx_bytes_r), txRate: unifiRate(lanHealth?.['tx_bytes-r'], lanHealth?.tx_bytes_r) },
        wlan: { users: numberOrNull(wlanHealth?.num_user), iot: numberOrNull(wlanHealth?.num_iot), rxRate: unifiRate(wlanHealth?.['rx_bytes-r'], wlanHealth?.rx_bytes_r), txRate: unifiRate(wlanHealth?.['tx_bytes-r'], wlanHealth?.tx_bytes_r) },
        updates: updates.length,
        offline: offline.length,
        devices: deviceRows,
        alerts: [
            ...offline.map(d => `${d.name} offline`),
            ...deviceRows.filter(d => d.overheating).map(d => `${d.name} overheating`),
            ...(updates.length ? [`${updates.length} firmware update${updates.length === 1 ? '' : 's'} available`] : []),
            ...(wanUp === false ? ['WAN/internet health is down'] : []),
            ...weakClients.filter(c => c.signal !== null && c.signal < -75).slice(0, 3).map(c => `${c.name} has weak Wi‑Fi signal (${c.signal} dBm)`)
        ],
        updatedAt: Date.now()
    };
}

// ---- UniFi session cache (reuse the login cookie instead of logging in every
// poll, which UniFi rate-limits and which caused the constant "dropping"). ----
let _unifiCookies = '';
let _unifiCookieAt = 0;
let _unifiLastGood = null;
let _unifiLastGoodAt = 0;
let _unifiProxy = null;   // which private-API path shape answered (true=/proxy/network OS proxy, false=/api/s legacy) so later polls skip the dead one
const _wanHist = [];                        // rolling WAN throughput (bytes/s) for the dashboard sparkline
const WAN_HIST_MAX = 120;
// Only store when the rate actually changes — the controller reports the same
// smoothed value several samples in a row, which would flatten the chart.
function pushWanHist(rate) { const n = Number(rate); if (!isFinite(n)) return; const v = Math.max(0, n); if (_wanHist.length && _wanHist[_wanHist.length - 1] === v) return; _wanHist.push(v); if (_wanHist.length > WAN_HIST_MAX) _wanHist.shift(); }
const UNIFI_COOKIE_TTL = 25 * 60 * 1000;   // reuse a session for 25 minutes
const UNIFI_STALE_OK   = 6 * 60 * 1000;    // serve last-good data up to 6 min during a blip

// UniFi OS returns a CSRF token needed for write calls — as a response header on some
// versions, or embedded in the TOKEN cookie's JWT payload on others. Try both.
function unifiCsrfFrom(resp) {
    const h = resp && resp.headers && (resp.headers['x-csrf-token'] || resp.headers['x-updated-csrf-token']);
    if (h) return String(h);
    try {
        const tok = (resp.cookies || []).map(c => String(c)).find(c => /^TOKEN=/.test(c));
        if (tok) {
            const jwt = tok.split(';')[0].split('=')[1] || '';
            const payload = jwt.split('.')[1];
            if (payload) { const j = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); return j.csrfToken || ''; }
        }
    } catch (e) { /* not a JWT session (legacy controller) — no CSRF needed */ }
    return '';
}
async function unifiLogin(settings) {
    const loginBodies = [
        { username: settings.username, password: settings.password, rememberMe: true },
        { username: settings.username, password: settings.password }
    ];
    const loginPaths = ['/api/auth/login', '/api/login'];
    let loginStatus = 0, loginError = '';
    for (const loginPath of loginPaths) {
        for (const body of loginBodies) {
            try {
                const resp = await unifiRequest(settings.url, loginPath, { method: 'POST', body });
                loginStatus = resp.status;
                if (resp.status >= 200 && resp.status < 300) {
                    const cookies = joinCookies(resp.cookies);
                    if (cookies) return { cookies, csrf: unifiCsrfFrom(resp) };
                } else {
                    loginError = typeof resp.body === 'string' ? resp.body : (resp.body?.meta?.msg || resp.body?.error || `login ${resp.status}`);
                }
            } catch (err) {
                loginError = describeNetErr(err, settings.url);
                // A connection-level failure is host-wide — the other path/body
                // would just burn another full timeout against the same dead host.
                // Bail now so an unreachable controller fails in ~6s, not ~40s.
                const code = (err && err.code) || '';
                if (['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN'].includes(code) || /timed? ?out/i.test(err && err.message || '')) {
                    return { cookies: '', error: loginError };
                }
            }
        }
    }
    return { cookies: '', error: loginError || `UniFi login failed (${loginStatus || 'no response'})` };
}

// Write a control command to the controller (LED override / flash-to-locate). Fresh
// login per action (user-initiated, infrequent); tries the UniFi OS proxy path first,
// then the legacy self-hosted path.
async function unifiControlCmd(settings, cmd) {
    const login = await unifiLogin(settings);
    if (!login.cookies) return { ok: false, error: login.error || 'UniFi login failed' };
    const site = encodeURIComponent(settings.site || 'default');
    let method, paths, body;
    if (cmd.action === 'locate') {
        method = 'POST';
        paths = [`/proxy/network/api/s/${site}/cmd/devmgr`, `/api/s/${site}/cmd/devmgr`];
        body = { cmd: cmd.on ? 'set-locate' : 'unset-locate', mac: cmd.mac };
    } else if (cmd.action === 'led') {
        method = 'PUT';
        const id = encodeURIComponent(cmd.id);
        paths = [`/proxy/network/api/s/${site}/rest/device/${id}`, `/api/s/${site}/rest/device/${id}`];
        body = {};
        if (cmd.mode) body.led_override = cmd.mode;
        if (cmd.color) { body.led_override_color = cmd.color; body.led_override = 'on'; }
        if (cmd.brightness != null) body.led_override_color_brightness = cmd.brightness;
    } else if (cmd.action === 'restart') {
        method = 'POST';
        paths = [`/proxy/network/api/s/${site}/cmd/devmgr`, `/api/s/${site}/cmd/devmgr`];
        body = { cmd: 'restart', macs: [cmd.mac] };
    } else if (cmd.action === 'client') {
        method = 'POST';
        paths = [`/proxy/network/api/s/${site}/cmd/stamgr`, `/api/s/${site}/cmd/stamgr`];
        const c = cmd.op === 'block' ? 'block-sta' : cmd.op === 'unblock' ? 'unblock-sta' : cmd.op === 'forget' ? 'forget-sta' : 'kick-sta';
        body = c === 'forget-sta' ? { cmd: c, macs: [cmd.mac] } : { cmd: c, mac: cmd.mac };
    } else return { ok: false, error: 'unknown action' };
    let last = '';
    for (const p of paths) {
        try {
            const r = await unifiRequest(settings.url, p, { method, body, cookies: login.cookies, csrf: login.csrf });
            if (r.status === 401 || r.status === 403) { last = 'unauthorized (' + r.status + ') — the UniFi account may be read-only'; continue; }
            if (r.status >= 200 && r.status < 300) return { ok: true };
            last = (r.body && r.body.meta && r.body.meta.msg) || ('controller HTTP ' + r.status);
        } catch (e) { last = describeNetErr(e, settings.url); }
    }
    return { ok: false, error: last || 'command failed' };
}

async function unifiFetchData(settings, cookies) {
    const site = encodeURIComponent(settings.site || 'default');
    const candidates = {
        devices: [`/proxy/network/api/s/${site}/stat/device`, `/api/s/${site}/stat/device`],
        clients: [`/proxy/network/api/s/${site}/stat/sta`, `/api/s/${site}/stat/sta`],
        health: [`/proxy/network/api/s/${site}/stat/health`, `/api/s/${site}/stat/health`]
    };
    let unauthorized = false;
    async function firstData(paths) {
        const ordered = _unifiProxy === false ? paths.slice().reverse() : paths;   // prefer the path shape that answered last time
        for (const p of ordered) {
            try {
                const resp = await unifiRequest(settings.url, p, { cookies });
                if (resp.status === 401 || resp.status === 403) { unauthorized = true; continue; }
                if (resp.status >= 200 && resp.status < 300) {
                    _unifiProxy = /\/proxy\/network\//.test(p);
                    const body = resp.body || {};
                    return Array.isArray(body.data) ? body.data : (Array.isArray(body) ? body : []);
                }
            } catch (err) { /* try next candidate */ }
        }
        return [];
    }
    const [devices, clients, health] = await Promise.all([firstData(candidates.devices), firstData(candidates.clients), firstData(candidates.health)]);
    return { devices, clients, health, unauthorized };
}

// UniFi Network Integration API (X-API-KEY). Official + MFA-friendly, but exposes less
// than the private/session API — no WAN throughput, radios, ports or LED. We map its
// device/client objects into the shapes summarizeUnifi() already understands, so the
// dashboard renders the same, just with fewer per-device details.
async function unifiIntegrationGet(settings, path) {
    let last = '';
    for (const p of ['/proxy/network/integration/v1' + path, '/integration/v1' + path]) {
        try {
            const r = await unifiRequest(settings.url, p, { apiKey: settings.apiKey });
            if (r.status === 401 || r.status === 403) throw Object.assign(new Error('API key rejected (HTTP ' + r.status + ') — verify the key and that the Integration API is enabled on the controller'), { fatal: true });
            if (r.status >= 200 && r.status < 300) return r.body;
            if (r.status === 404) { last = 'HTTP 404'; continue; }   // try the non-proxy path shape
            last = 'controller HTTP ' + r.status;
        } catch (e) { if (e.fatal) throw e; last = describeNetErr(e, settings.url); }
    }
    throw new Error(last || 'Integration API unreachable');
}
async function unifiFetchIntegration(settings) {
    const sitesResp = await unifiIntegrationGet(settings, '/sites');
    const sites = (sitesResp && (sitesResp.data || sitesResp)) || [];
    if (!Array.isArray(sites) || !sites.length) throw new Error('Integration API returned no sites');
    const want = String(settings.site || 'default').toLowerCase();
    const site = sites.find(s => String(s.name || s.internalReference || '').toLowerCase() === want) || sites.find(s => String(s.name || '').toLowerCase() === 'default') || sites[0];
    const siteId = encodeURIComponent(site.id || site._id || '');
    let idev = [], icli = [];
    try { const r = await unifiIntegrationGet(settings, '/sites/' + siteId + '/devices'); idev = (r && (r.data || r)) || []; } catch (e) { /* devices unavailable — still render what we have */ }
    try { const r = await unifiIntegrationGet(settings, '/sites/' + siteId + '/clients'); icli = (r && (r.data || r)) || []; } catch (e) { /* clients unavailable */ }
    const onlineRe = /online|connected/i;
    const devices = (Array.isArray(idev) ? idev : []).map(d => {
        const on = onlineRe.test(String(d.state || d.status || ''));
        return { _id: d.id || d._id || '', name: d.name || d.hostname || d.model || '', model: d.model || d.shortname || d.type || '', type: d.type || '', mac: d.macAddress || d.mac || '', ip: d.ipAddress || d.ip || '', state: on ? 1 : 0, up: on, displayable_version: d.firmwareVersion || d.version || '', upgradable: !!(d.firmwareUpdatable || d.updateAvailable), num_sta: numberOrNull(d.clientCount != null ? d.clientCount : d.numClients) || 0 };
    });
    const clients = (Array.isArray(icli) ? icli : []).map(c => ({ name: c.name || c.hostname || c.ipAddress || c.macAddress || 'client', ip: c.ipAddress || c.ip || '', mac: c.macAddress || c.mac || '', is_wired: /wired/i.test(String(c.type || c.connectionType || '')) || c.wired === true, network: c.network || '' }));
    const summary = summarizeUnifi(devices, clients, [], settings);
    summary.integrationApi = true;
    return summary;
}
async function queryUnifiStatus() {
    const settings = safeUnifiSettings(storedUnifiSettings());
    const useKey = settings.authMethod === 'apikey' && !!settings.apiKey;
    if (!settings.url || (!useKey && (!settings.username || !settings.password))) {
        return {
            configured: false,
            expected: { gateway: 1, switches: 5, aps: 3 },
            gateway: { online: 0, total: 1, devices: [{ name: 'UCG Fiber', model: 'UCG Fiber', kind: 'gateway', online: false }] },
            switches: { online: 0, total: 5, devices: [] },
            aps: { online: 0, total: 3, devices: [] },
            clients: { total: 0, wifi: 0, wired: 0 },
            wan: { up: null },
            updates: 0,
            offline: 0,
            devices: [],
            alerts: ['Add UniFi controller URL and credentials in Settings.'],
            message: 'UniFi credentials not configured.'
        };
    }
    const now = Date.now();
    if (_unifiLastGood && _unifiLastGoodAt && (now - _unifiLastGoodAt) < 8000 && !_unifiLastGood.stale) return _unifiLastGood;   // short fresh-cache: rapid polls + multiple tabs share ONE controller fetch instead of hammering it
    try {
        if (useKey) {   // official Integration API path (X-API-KEY) — reads only, fewer stats, no LED
            const summary = await unifiFetchIntegration(settings);
            _unifiLastGood = summary; _unifiLastGoodAt = now;
            return summary;
        }
        // Reuse the cached session if it is still fresh; otherwise log in.
        if (!_unifiCookies || (now - _unifiCookieAt) > UNIFI_COOKIE_TTL) {
            const lg = await unifiLogin(settings);
            if (!lg.cookies) throw new Error(typeof lg.error === 'string' ? lg.error : (lg.error && (lg.error.message || lg.error.error)) || (lg.error ? JSON.stringify(lg.error).slice(0, 200) : 'UniFi login failed'));
            _unifiCookies = lg.cookies; _unifiCookieAt = now;
        }
        let data = await unifiFetchData(settings, _unifiCookies);
        // Cached session expired on the controller side → re-login once and retry.
        if (data.unauthorized || (!data.devices.length && !data.clients.length)) {
            const lg = await unifiLogin(settings);
            if (!lg.cookies) throw new Error(typeof lg.error === 'string' ? lg.error : (lg.error && (lg.error.message || lg.error.error)) || (lg.error ? JSON.stringify(lg.error).slice(0, 200) : 'UniFi login failed'));
            _unifiCookies = lg.cookies; _unifiCookieAt = now;
            data = await unifiFetchData(settings, _unifiCookies);
        }
        if (!data.devices.length && !data.clients.length && data.unauthorized) {
            throw new Error('UniFi authorization failed');
        }
        const summary = summarizeUnifi(data.devices, data.clients, data.health, settings);
        _unifiLastGood = summary; _unifiLastGoodAt = now;
        return summary;
    } catch (err) {
        // Serialize error objects properly — String({}) is "[object Object]", useless in the UI.
        const errMsg = (err && (err.message || err.error)) || (typeof err === 'object' && err !== null ? JSON.stringify(err).slice(0, 200) : String(err)) || 'UniFi unavailable';
        // Smooth over transient blips: keep showing the last good data for a few
        // minutes so the UI does not flap to "Auth issue" on a single failed poll.
        if (_unifiLastGood && (now - _unifiLastGoodAt) < UNIFI_STALE_OK) {
            return { ..._unifiLastGood, stale: true, staleReason: errMsg };
        }
        _unifiCookies = ''; // force a clean login next time
        return { configured: true, controller: settings.url, site: settings.site, ok: false, error: errMsg, alerts: ['UniFi temporarily unavailable; retrying.'] };
    }
}

// Ships empty: Command Center has no idea what's on your network until you tell it.
// Add services in Settings → Fleet & probes (persisted, encrypted), or drop a
// `services.json` next to this file for declarative/GitOps setups. In DEMO mode a
// realistic synthetic fleet is generated instead so the UI is explorable out-of-box.
function loadSeedServices() {
    if (process.env.DEMO === '1') return demoServices();
    try {
        const p = path.join(__dirname, 'services.json');
        if (fs.existsSync(p)) {
            const arr = JSON.parse(fs.readFileSync(p, 'utf8'));
            if (Array.isArray(arr)) return arr;
        }
    } catch (e) { console.warn('services.json ignored:', e.message); }
    return [];
}
const services = loadSeedServices();

// Live data probes. The client (dashboard.html) sends the per-service API key
// with each request, so we don't need to keep secrets server-side. Each probe
// knows the auth header scheme and one or more JSON paths to fetch.
const LIVE_PROBES = {
    'Plex Media Server': {
        defaultUrl: 'http://127.0.0.1:32400',
        authHeader: 'X-Plex-Token',
        path: '/identity'
    },
    'Emby': {
        defaultUrl: 'http://127.0.0.1:8096',
        authHeader: 'X-Emby-Token',
        path: '/System/Info/Public'
    },
    'Sonarr':           { defaultUrl: 'http://127.0.0.1:8989', authHeader: 'X-Api-Key', path: '/api/v3/system/status', extras: [{ key: 'queue', path: '/api/v3/queue?pageSize=1' }, { key: 'missing', path: '/api/v3/wanted/missing?pageSize=1' }, { key: 'wanted', path: '/api/v3/wanted?pageSize=1' }] },
    'Sonarr-Asian':     { defaultUrl: 'http://127.0.0.1:8991', authHeader: 'X-Api-Key', path: '/api/v3/system/status', extras: [{ key: 'queue', path: '/api/v3/queue?pageSize=1' }, { key: 'missing', path: '/api/v3/wanted/missing?pageSize=1' }, { key: 'wanted', path: '/api/v3/wanted?pageSize=1' }] },
    'Sonarr-Anime':     { defaultUrl: 'http://127.0.0.1:8990', authHeader: 'X-Api-Key', path: '/api/v3/system/status', extras: [{ key: 'queue', path: '/api/v3/queue?pageSize=1' }, { key: 'missing', path: '/api/v3/wanted/missing?pageSize=1' }, { key: 'wanted', path: '/api/v3/wanted?pageSize=1' }] },
    'Radarr':           { defaultUrl: 'http://127.0.0.1:7878', authHeader: 'X-Api-Key', path: '/api/v3/system/status', extras: [{ key: 'queue', path: '/api/v3/queue?pageSize=1' }, { key: 'missing', path: '/api/v3/wanted/missing?pageSize=1' }, { key: 'wanted', path: '/api/v3/wanted?pageSize=1' }] },
    'Lidarr':           { defaultUrl: 'http://127.0.0.1:8686', authHeader: 'X-Api-Key', path: '/api/v1/system/status', extras: [{ key: 'queue', path: '/api/v1/queue?pageSize=1' }, { key: 'missing', path: '/api/v1/wanted/missing?pageSize=1' }] },
    'Prowlarr':         { defaultUrl: 'http://127.0.0.1:9696', authHeader: 'X-Api-Key', path: '/api/v1/system/status', extras: [{ key: 'indexers', path: '/api/v1/indexer?pageSize=1' }] },
    'Jackett':          { defaultUrl: 'http://127.0.0.1:30118', authHeader: 'X-Api-Key', path: '/api/v3/system/status' },
    'Tracearr':         { defaultUrl: 'http://127.0.0.1:30316', authHeader: 'Bearer',   path: '/api/v1/public/streams', fallbacks: ['/api/v1/sessions/active', '/api/v1/sessions'] },
    'Sabnzbd':          { defaultUrl: 'http://127.0.0.1:8080', authHeader: 'apikey',   path: '/api?mode=queue&output=json' },
    'Qbt':              { defaultUrl: 'http://127.0.0.1:8081', authHeader: 'Cookie',   path: '/api/v2/app/version' },
    'slskd':            { defaultUrl: 'http://127.0.0.1:5030', authHeader: null,       path: '/' },
    'Dockge':           { defaultUrl: 'http://127.0.0.1:5001', authHeader: null,       path: '/' },
    'Seer':             { defaultUrl: 'http://127.0.0.1:5055', authHeader: 'X-Api-Key', path: '/api/v1/settings' },
    'Wizarr':           { defaultUrl: 'https://wizarr.example.com', authHeader: 'X-Api-Key', path: '/api/v1/users' },
    'TrueNAS Web UI':   { defaultUrl: 'http://127.0.0.1', authHeader: 'X-API-Key', path: '/api/current' },
    'Grafana':          { defaultUrl: 'http://127.0.0.1:3000', authHeader: null, path: '/api/health' },
    'Prometheus':       { defaultUrl: 'http://127.0.0.1:9090', authHeader: null, path: '/api/v1/query?query=up', extras: [{ key: 'targets', path: '/api/v1/targets' }] },
    'Node Exporter':    { defaultUrl: 'http://127.0.0.1:9100', authHeader: null, path: '/metrics' },
    'cAdvisor':         { defaultUrl: 'http://127.0.0.1:8089', authHeader: null, path: '/metrics' },
    'Loki':             { defaultUrl: 'http://127.0.0.1:3100', authHeader: null, path: '/ready', extras: [{ key: 'labels', path: '/loki/api/v1/labels' }] },
    'Promtail':         { defaultUrl: 'http://127.0.0.1:3100', authHeader: null, path: '/loki/api/v1/labels' }
};

function visibleServices() {
    const settings = readDashboardSettings();
    const hidden = new Set(Array.isArray(settings.hiddenServices) ? settings.hiddenServices : []);
    const custom = Array.isArray(settings.customServices) ? settings.customServices : [];
    const normalizedCustom = custom
        .filter(svc => svc && svc.name && svc.host && Number(svc.port))
        .map(svc => ({
            name: String(svc.name),
            host: String(svc.host),
            port: Number(svc.port),
            type: String(svc.type || 'Custom'),
            url: String(svc.url || ''),
            authHeader: String(svc.authHeader || ''),
            probePath: String(svc.probePath || '/')
        }));
    const out = [
        ...services.filter(svc => !hidden.has(svc.name)),
        ...normalizedCustom.filter(svc => !hidden.has(svc.name))
    ];
    // One add, everywhere: an ENABLED integration with a configured URL joins
    // the fleet automatically (health dot on Home, status sweeps) — no second
    // manual add in Fleet & probes. Skipped when an existing service already
    // covers that host:port, and hideable by name like any other service.
    const covered = new Set(out.map(s => `${s.host}:${s.port}`));
    for (const [id, cfg] of Object.entries(settings.integrations || {})) {
        if (!cfg || !cfg.enabled) continue;
        const def = INTEGRATIONS[id];
        if (!def) continue;
        const ep = storedEndpoint(id);
        if (!ep) continue;
        try {
            const u = new URL(ep);
            const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
            if (covered.has(`${u.hostname}:${port}`)) continue;
            if (hidden.has(def.title)) continue;
            covered.add(`${u.hostname}:${port}`);
            out.push({ name: def.title, host: u.hostname, port, type: def.category || 'Integration', url: ep, authHeader: '', probePath: '/' });
        } catch (e) { /* unparseable URL — skip */ }
    }
    // Same for native probes (Tracearr, Node Exporter, TrueNAS…): giving one an
    // address on its provider card IS the add — it joins the fleet automatically.
    for (const [name, ep] of Object.entries(settings.endpoints || {})) {
        if (!LIVE_PROBES[name] || !ep || !ep.url || hidden.has(name)) continue;
        try {
            const u = new URL(ep.url);
            const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
            if (covered.has(`${u.hostname}:${port}`)) continue;
            covered.add(`${u.hostname}:${port}`);
            out.push({ name, host: u.hostname, port, type: 'Native', url: ep.url, authHeader: '', probePath: '/' });
        } catch (e) { /* unparseable URL — skip */ }
    }
    return out;
}

// Where should a native probe for `svcName` actually connect?
//   1. an explicit endpoints override (settings.endpoints[name].url),
//   2. the address the user gave the service in Settings → Fleet & probes
//      (its url, else http(s)://host:port),
//   3. the LIVE_PROBES default — but ONLY if it isn't loopback. Inside a
//      container 127.0.0.1 is the container itself, never the user's service,
//      so a loopback default means "not configured" (return ''), not a probe
//      of the wrong machine.
function isLoopbackUrl(u) { return /^https?:\/\/(127\.(\d+\.){2}\d+|localhost|\[::1\])(:|\/|$)/i.test(String(u || '')); }
function serviceProbeBase(svcName) {
    const ep = storedEndpoint(svcName);
    if (ep) return String(ep).replace(/\/+$/, '');
    const svc = visibleServices().find(s => s.name === svcName);
    if (svc) {
        if (svc.url && /^https?:\/\//i.test(svc.url)) return String(svc.url).replace(/\/+$/, '');
        if (svc.host && Number(svc.port)) return `${Number(svc.port) === 443 ? 'https' : 'http'}://${svc.host}:${svc.port}`;
    }
    // Fall back to the aliased catalog integration's configured address. Credentials
    // already alias via CRED_ALIASES, so a normally-configured qBittorrent / SABnzbd /
    // Sonarr… integration authenticates — but without this its native pipeline probe had
    // no address and silently read "not configured", leaving the Automation page dark.
    const alias = CRED_ALIASES[svcName];
    if (alias) {
        const aliasEp = storedEndpoint(alias[0]);
        if (aliasEp) return String(aliasEp).replace(/\/+$/, '');
    }
    const def = (LIVE_PROBES[svcName] || {}).defaultUrl || '';
    if (def && !isLoopbackUrl(def)) return String(def).replace(/\/+$/, '');
    return '';
}

// Perform a single authenticated fetch for a service probe.
// Handles the different auth schemes (header / query / cookie) per probe.
function liveFetch({ baseUrl, path, key, probe }) {
    return new Promise((resolve, reject) => {
        let url = baseUrl + path;
        // SABnzbd uses ?apikey=, qBittorrent uses Cookie: SID=..., Plex accepts
        // X-Plex-Token as both header and ?X-Plex-Token=. We handle the common cases here.
        if (probe.authHeader === 'apikey') {
            const sep = url.includes('?') ? '&' : '?';
            url += `${sep}apikey=${encodeURIComponent(key)}&output=json`;
        } else if (probe.authHeader === 'Cookie') {
            // qBittorrent expects SID cookie obtained from /api/v2/auth/login.
            // For the simple live probe we just hit /app/version; it does NOT
            // require auth in most builds. If your build requires it, swap this
            // for a real login flow.
        } else if (probe.authHeader === 'Bearer') {
            // Tracearr uses Authorization: Bearer <token>
        } else {
            // X-Api-Key / X-Plex-Token / X-Emby-Token — all use the same header pattern.
        }
        const lib = url.startsWith('https://') ? require('https') : require('http');
        const headers = { 'Accept': 'application/json', 'User-Agent': 'dashboard-server/1.0' };
        if (key && probe.authHeader === 'Bearer') headers['Authorization'] = `Bearer ${key}`;
        else if (key && probe.authHeader && probe.authHeader !== 'apikey' && probe.authHeader !== 'Cookie') {
            headers[probe.authHeader] = key;
        }
        const req = lib.get(url, { headers, timeout: 5000 }, (r) => {   // LAN services answer fast; don't let one unreachable probe stall the poll batch
            let data = '';
            r.on('data', c => { data += c; if (data.length > 8e6) req.destroy(new Error('response too large')); });   // bound a misbehaving upstream
            r.on('end', () => {
                let parsed = {};
                try { parsed = data ? JSON.parse(data) : {}; } catch (_) { parsed = { raw: data.slice(0, 1500000) }; }
                resolve({ status: r.statusCode, ok: r.statusCode >= 200 && r.statusCode < 300, body: parsed });
            });
        });
        req.on('timeout', () => { req.destroy(new Error('timeout')); });
        req.on('error', reject);
    });
}

function qbtRequest({ baseUrl, path, method = 'GET', body = '', cookie = '' }) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, baseUrl);
        const lib = url.protocol === 'https:' ? require('https') : require('http');
        const headers = {
            'Accept': 'application/json',
            'User-Agent': 'dashboard-server/1.0',
            'Referer': baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`,
            'Origin': new URL(baseUrl).origin
        };
        if (cookie) headers.Cookie = cookie;
        if (body) {
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
            headers['Content-Length'] = Buffer.byteLength(body);
        }
        const req = lib.request(url, { method, headers, timeout: 8000 }, (r) => {
            let data = '';
            r.on('data', c => data += c);
            r.on('end', () => {
                let parsed = {};
                try { parsed = data ? JSON.parse(data) : {}; } catch (_) { parsed = { raw: data }; }
                resolve({
                    status: r.statusCode,
                    ok: r.statusCode >= 200 && r.statusCode < 300,
                    headers: r.headers,
                    body: parsed
                });
            });
        });
        req.on('timeout', () => { req.destroy(new Error('timeout')); });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

async function queryQbt(baseUrl, credentials = {}) {
    const username = String(credentials.username || '');
    const password = String(credentials.password || '');
    let cookie = '';

    if (username || password) {
        if (!username || !password) throw new Error('qBit username and password are both required');
        const form = new URLSearchParams({ username, password }).toString();
        const login = await qbtRequest({ baseUrl, path: '/api/v2/auth/login', method: 'POST', body: form });
        const rawCookie = login.headers['set-cookie'];
        cookie = Array.isArray(rawCookie)
            ? rawCookie.map(v => v.split(';')[0]).join('; ')
            : String(rawCookie || '').split(';')[0];
        const loginText = String(login.body?.raw || '').trim().toLowerCase();
        if (!login.ok || !cookie || (loginText && loginText !== 'ok.')) {
            throw new Error(`qBit login failed: HTTP ${login.status}${login.body?.raw ? ` ${String(login.body.raw).slice(0, 80)}` : ''}`);
        }
    }

    const versionResp = await qbtRequest({ baseUrl, path: '/api/v2/app/version', cookie });
    const transferResp = await qbtRequest({ baseUrl, path: '/api/v2/transfer/info', cookie });
    const torrentsResp = await qbtRequest({ baseUrl, path: '/api/v2/torrents/info', cookie });
    if (!versionResp.ok) throw new Error(`qBit version HTTP ${versionResp.status}`);
    if (!transferResp.ok) throw new Error(`qBit transfer HTTP ${transferResp.status}`);
    if (!torrentsResp.ok) throw new Error(`qBit torrents HTTP ${torrentsResp.status}`);

    const torrents = Array.isArray(torrentsResp.body) ? torrentsResp.body : [];
    const downloading = torrents.filter(t => ['downloading', 'stalledDL', 'metaDL', 'forcedDL', 'queuedDL'].includes(t.state)).length;
    const uploading = torrents.filter(t => ['uploading', 'stalledUP', 'forcedUP', 'queuedUP'].includes(t.state)).length;
    const paused = torrents.filter(t => String(t.state || '').toLowerCase().includes('paused')).length;
    const active = torrents.filter(t => Number(t.dlspeed || 0) > 0 || Number(t.upspeed || 0) > 0).length;

    return {
        version: String(versionResp.body?.raw || versionResp.body?.version || '').replace(/^"|"$/g, ''),
        transfer: transferResp.body || {},
        torrents,
        queue: {
            total: torrents.length,
            active,
            downloading,
            uploading,
            paused
        }
    };
}

async function queryTracearr(baseUrl, key, probe) {
    let lastResp = null;
    const paths = [probe.path, ...(probe.fallbacks || [])];
    for (const path of paths) {
        const resp = await liveFetch({ baseUrl, path, key, probe });
        lastResp = resp;
        // A 2xx IS the answer — zero active streams is a valid answer. Return
        // immediately instead of firing the remaining fallback requests every
        // poll (that turned an idle Tracearr into 3 sequential round-trips).
        if (resp.ok) return { status: resp.status, ok: true, body: { ...resp.body, _tracearrPath: path } };
        // A definitive auth failure on the PRIMARY public path is the real
        // verdict; the private fallbacks would 401 for a public token anyway.
        if ((resp.status === 401 || resp.status === 403) && path === probe.path) return resp;
        // otherwise (404 / 5xx / timeout, or auth failure on a fallback) → try the next path
    }
    return lastResp || { status: 502, ok: false, body: { error: 'Tracearr unavailable' } };
}

function parseNodeNetworkTotal(raw) {
    const ignored = /(device="(?:lo|docker\d*|br-[^"]+|veth[^"]+|tun[^"]+|tailscale[^"]*)")/;
    let total = 0;
    for (const line of raw.split('\n')) {
        if (!/^node_network_(receive|transmit)_bytes_total\{/.test(line)) continue;
        if (ignored.test(line)) continue;
        const value = Number(line.trim().split(/\s+/).pop());
        if (Number.isFinite(value)) total += value;
    }
    return total;
}

async function queryNetworkTotal(endpoint) {
    const probe = LIVE_PROBES['Node Exporter'];
    const baseUrl = (endpoint || serviceProbeBase('Node Exporter')).replace(/\/+$/, '');
    if (!baseUrl) return { total: null, at: Date.now(), configured: false };
    const response = await liveFetch({ baseUrl, path: probe.path, key: '', probe });
    const raw = response.body?.raw || '';
    return {
        total: parseNodeNetworkTotal(raw),
        at: Date.now()
    };
}

/* ── cAdvisor server-side summary ─────────────────────────────────────────
   Parses the ~1.4MB /metrics scrape ONCE on the server and ships a ~2KB list.
   CPU% needs two counter samples; the server keeps per-container previous
   counters across requests, so every tab gets a rate without warming its own
   delta window. */
const _ctrSummary = { body: null, at: 0, inflight: null };
// /api/docker/containers single-flight TTL cache. Without it, each open tab
// re-fans-out one stats?stream=false request per running container every 20s
// poll, hammering the Docker daemon (N tabs × M containers). Keyed on host so a
// reconfigure bypasses stale data.
const _dockerList = { body: null, at: 0, inflight: null, host: '' };
const _ctrCpuPrev = Object.create(null);   // name → { c: cpu counter (s), t: sample time (ms) }

function fetchTextUrl(url, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
        const lib = url.startsWith('https://') ? require('https') : require('http');
        const req = lib.get(url, { headers: { 'User-Agent': 'dashboard-server/1.0' }, timeout: timeoutMs }, (r) => {
            if (r.statusCode < 200 || r.statusCode >= 300) { r.resume(); reject(new Error(`HTTP ${r.statusCode}`)); return; }
            let data = '';
            r.on('data', c => { data += c; if (data.length > 8e6) req.destroy(new Error('response too large')); });   // bound a misbehaving upstream
            r.on('end', () => resolve(data));
        });
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.on('error', reject);
    });
}

async function queryContainerSummary() {
    const baseUrl = serviceProbeBase('cAdvisor');
    if (!baseUrl) throw new Error('cAdvisor has no address — open its card in Settings → Providers and set the URL');
    const raw = await fetchTextUrl(baseUrl + '/metrics');
    const now = Date.now();
    // Targeted line scan — only the metrics the summary needs, no generic label parse.
    const WANT = /^(?:container_memory_working_set_bytes|container_memory_usage_bytes|container_memory_rss|container_spec_memory_limit_bytes|container_cpu_usage_seconds_total|container_network_receive_bytes_total|container_network_transmit_bytes_total|container_start_time_seconds|machine_cpu_cores)[{ ]/;
    const byName = Object.create(null);
    let cores = null;
    for (const line of raw.split('\n')) {
        if (!line || line.charCodeAt(0) === 35 || !WANT.test(line)) continue;
        // Exposition format is `name{labels} value [timestamp-ms]` — cAdvisor appends
        // the timestamp, so take the FIRST token after the label block, not the last.
        let head, tail;
        const cb = line.indexOf('} ');
        if (cb !== -1) { head = line.slice(0, cb + 1); tail = line.slice(cb + 2); }
        else { const s = line.indexOf(' '); head = line.slice(0, s); tail = line.slice(s + 1); }
        const value = Number(tail.split(' ')[0]);
        if (!Number.isFinite(value)) continue;
        if (head.startsWith('machine_cpu_cores')) { cores = value; continue; }
        const nm = /name="([^"]+)"/.exec(head);
        if (!nm || nm[1].startsWith('/')) continue;
        const bi = head.indexOf('{');
        const metric = bi === -1 ? head : head.slice(0, bi);
        const c = byName[nm[1]] || (byName[nm[1]] = { cpuTot: null });
        if (metric === 'container_cpu_usage_seconds_total') c.cpuTot = (c.cpuTot || 0) + value;
        else if (metric === 'container_memory_working_set_bytes') c.ws = value;
        else if (metric === 'container_memory_usage_bytes') c.usage = value;
        else if (metric === 'container_memory_rss') c.rss = value;
        else if (metric === 'container_spec_memory_limit_bytes') c.limit = value;
        else if (metric === 'container_network_receive_bytes_total') c.netRxTot = (c.netRxTot || 0) + value;   // summed across interfaces
        else if (metric === 'container_network_transmit_bytes_total') c.netTxTot = (c.netTxTot || 0) + value;
        else if (metric === 'container_start_time_seconds') c.started = Math.max(c.started || 0, value);
        if (!c.image) { const im = /image="([^"]+)"/.exec(head); if (im) c.image = im[1]; }
    }
    const list = Object.keys(byName).map(n => {
        const c = byName[n];
        const mem = c.ws ?? c.usage ?? c.rss ?? null;
        let cpuPct = null, netRx = null, netTx = null;
        const prev = _ctrCpuPrev[n];
        if (prev && now > prev.t) {
            const dt = (now - prev.t) / 1000;
            if (c.cpuTot != null && prev.c != null) cpuPct = Math.max(0, Math.min(100, (c.cpuTot - prev.c) / dt / (cores || 1) * 100));
            if (c.netRxTot != null && prev.rx != null) netRx = Math.max(0, (c.netRxTot - prev.rx) / dt);   // bytes/s
            if (c.netTxTot != null && prev.tx != null) netTx = Math.max(0, (c.netTxTot - prev.tx) / dt);
        }
        _ctrCpuPrev[n] = { c: c.cpuTot, rx: c.netRxTot, tx: c.netTxTot, t: now };
        return { name: n, image: c.image || '', mem, memLimit: (c.limit && c.limit < 1e15) ? c.limit : null, cpuPct, netRx, netTx, started: c.started || null, running: true };
    });
    // Drop counters for containers that vanished so the map can't grow unbounded.
    for (const n of Object.keys(_ctrCpuPrev)) if (!byName[n]) delete _ctrCpuPrev[n];
    list.sort((a, b) => (b.mem || 0) - (a.mem || 0) || a.name.localeCompare(b.name));
    return { list, count: list.length, cores, ts: now };
}

/* ── Minimal RFC 6455 WebSocket client (text frames) over http(s) Upgrade ──
   Node's built-in WebSocket cannot skip TLS verification, which made every
   self-signed TrueNAS "API connection failed" out of the box. This client
   applies the same LAN TLS policy as every other outbound call. Client frames
   are masked as the RFC requires; server frames (incl. fragmented) are
   reassembled; pings are answered. Sufficient for small JSON-RPC exchanges. */
function wsOpen(rpcUrl, handlers) {
    const u = new URL(rpcUrl);
    const secure = u.protocol === 'wss:';
    const lib = secure ? require('https') : require('http');
    const key = crypto.randomBytes(16).toString('base64');
    const req = lib.request({
        host: u.hostname, port: u.port || (secure ? 443 : 80), path: u.pathname + u.search,
        headers: { 'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key },
        ...(secure ? { rejectUnauthorized: !tlsRelaxedFor(rpcUrl) } : {}),
        timeout: 10000
    });
    const api = { send: () => {}, close: () => { try { req.destroy(); } catch (e) {} } };
    const frame = (opcode, payload) => {   // client→server frames must be masked
        const mask = crypto.randomBytes(4);
        const data = Buffer.from(payload);
        for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
        let head;
        if (data.length < 126) { head = Buffer.alloc(2); head[1] = 0x80 | data.length; }
        else if (data.length < 65536) { head = Buffer.alloc(4); head[1] = 0x80 | 126; head.writeUInt16BE(data.length, 2); }
        else { head = Buffer.alloc(10); head[1] = 0x80 | 127; head.writeBigUInt64BE(BigInt(data.length), 2); }
        head[0] = 0x80 | opcode;   // FIN
        return Buffer.concat([head, mask, data]);
    };
    req.on('upgrade', (res, socket) => {
        let buf = Buffer.alloc(0);
        let msgParts = [];
        api.send = (text) => { try { socket.write(frame(0x1, text)); } catch (e) {} };
        api.close = () => { try { socket.write(frame(0x8, '')); } catch (e) {} try { socket.destroy(); } catch (e) {} };
        socket.on('data', (chunk) => {
            buf = Buffer.concat([buf, chunk]);
            while (buf.length >= 2) {
                const fin = (buf[0] & 0x80) !== 0, opcode = buf[0] & 0x0f;
                const masked = (buf[1] & 0x80) !== 0;
                let len = buf[1] & 0x7f, off = 2;
                if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
                else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
                const maskKey = masked ? buf.slice(off, off + 4) : null;
                if (masked) off += 4;
                if (buf.length < off + len) return;   // wait for the rest
                let payload = buf.slice(off, off + len);
                if (maskKey) { payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i & 3]; }
                buf = buf.slice(off + len);
                if (opcode === 0x9) { try { socket.write(frame(0xA, payload)); } catch (e) {} continue; }   // ping → pong
                if (opcode === 0x8) { api.close(); handlers.onClose && handlers.onClose(); return; }
                if (opcode === 0x1 || opcode === 0x0) {
                    msgParts.push(payload);
                    if (fin) { const text = Buffer.concat(msgParts).toString('utf8'); msgParts = []; handlers.onMessage && handlers.onMessage(text); }
                }
            }
        });
        socket.on('error', (err) => handlers.onError && handlers.onError(err));
        handlers.onOpen && handlers.onOpen();
    });
    req.on('response', (res) => handlers.onError && handlers.onError(new Error(`WebSocket upgrade refused (HTTP ${res.statusCode})`)));
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (err) => handlers.onError && handlers.onError(err));
    req.end();
    return api;
}

function trueNasRpc(apiKey, endpoint, method, params = []) {
    return new Promise((resolve, reject) => {
        let rpcUrl;
        try {
            const base = new URL(endpoint || serviceProbeBase('TrueNAS Web UI') || 'invalid://');
            // NEVER a plain-text transport for the API key: TrueNAS (correctly)
            // auto-revokes any key it sees on http/ws. https → wss only.
            if (base.protocol !== 'https:') { reject(new Error('TrueNAS must be reached over https — an API key sent over plain http is auto-revoked by TrueNAS')); return; }
            rpcUrl = `wss://${base.host}/api/current`;
        } catch (_) {
            reject(new Error('Invalid TrueNAS endpoint'));
            return;
        }
        const pending = new Map();
        let nextId = 1, settled = false;
        const finish = (fn, v) => { if (!settled) { settled = true; clearTimeout(timer); try { ws.close(); } catch (e) {} fn(v); } };
        const timer = setTimeout(() => finish(reject, new Error('TrueNAS API timeout')), 10000);
        const call = (rpcMethod, rpcParams = []) => new Promise((res, rej) => {
            const id = nextId++;
            pending.set(id, { res, rej });
            ws.send(JSON.stringify({ jsonrpc: '2.0', id, method: rpcMethod, params: rpcParams }));
        });
        const ws = wsOpen(rpcUrl, {
            onOpen: async () => {
                try {
                    const authed = await call('auth.login_with_api_key', [apiKey]);
                    if (!authed) throw new Error('TrueNAS rejected the API key — renew it in TrueNAS (Credentials → API Keys) and paste it in Settings → Providers → TrueNAS');
                    const result = await call(method, params);
                    finish(resolve, result);
                } catch (err) { finish(reject, err); }
            },
            onMessage: (text) => {
                let msg; try { msg = JSON.parse(text); } catch (_) { return; }
                if (!pending.has(msg.id)) return;
                const p = pending.get(msg.id);
                pending.delete(msg.id);
                if (msg.error) p.rej(new Error(msg.error.message || 'TrueNAS API error'));
                else p.res(msg.result);
            },
            onError: (err) => finish(reject, new Error(describeNetErr(err, rpcUrl))),
            onClose: () => finish(reject, new Error('TrueNAS closed the connection'))
        });
    });
}

async function trueNasRpcOptional(apiKey, endpoint, method, params = []) {
    try {
        return { ok: true, result: await trueNasRpc(apiKey, endpoint, method, params) };
    } catch (err) {
        return { ok: false, error: err.message || 'TrueNAS API error' };
    }
}

async function queryTrueNasPools(apiKey, endpoint) {
    if (!apiKey) {
        return { pools: [], configured: false, notice: 'TrueNAS API key not set' };
    }
    const pools = await trueNasRpc(apiKey, endpoint, 'pool.query', [
        [],
        { select: ['name', 'size', 'allocated', 'free', 'status', 'healthy'] }
    ]);
    return {
        configured: true,
        pools: (Array.isArray(pools) ? pools : []).map(pool => {
            const size = Number(pool.size) || 0;
            const used = Number(pool.allocated) || 0;
            const free = pool.free != null ? Number(pool.free) : Math.max(0, size - used);
            return {
                name: pool.name,
                size, used, free, avail: free,
                usedPct: size ? (used / size) * 100 : 0,
                status: pool.status || '',
                healthy: pool.healthy !== false,
                health: pool.status || (pool.healthy === false ? 'DEGRADED' : 'ONLINE')
            };
        })
    };
}

function asArray(value) {
    return Array.isArray(value) ? value : [];
}

function firstFinite(...values) {
    for (const value of values) {
        const n = Number(value);
        if (Number.isFinite(n)) return n;
    }
    return null;
}

function isoOrNull(value) {
    if (!value) return null;
    const d = new Date(value);
    return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}

function ageHours(isoValue) {
    const t = Date.parse(isoValue || '');
    if (!Number.isFinite(t)) return null;
    return Math.max(0, Math.round((Date.now() - t) / 3600000));
}

function newestIso(values) {
    return values
        .filter(Boolean)
        .map(value => ({ iso: value, time: Date.parse(value) }))
        .filter(item => Number.isFinite(item.time))
        .sort((a, b) => b.time - a.time)[0]?.iso || null;
}

function snapshotCreatedIso(snapshot) {
    const candidates = [
        snapshot?.created,
        snapshot?.creation,
        snapshot?.properties?.creation?.value,
        snapshot?.properties?.creation?.parsed,
        snapshot?.properties?.creation?.rawvalue,
        snapshot?.properties?.createtxg?.parsed
    ];
    for (const value of candidates) {
        if (!value) continue;
        if (typeof value === 'number') {
            const d = new Date(value > 100000000000 ? value : value * 1000);
            if (Number.isFinite(d.getTime())) return d.toISOString();
        }
        if (typeof value === 'object' && value.$date) {
            const iso = isoOrNull(value.$date);
            if (iso) return iso;
        }
        const iso = isoOrNull(value);
        if (iso) return iso;
    }
    return null;
}

function trueNasTaskTone(items, badStates = /failed|error|fault|degraded|offline/i) {
    if (!Array.isArray(items) || !items.length) return 'warn';
    return items.some(item => badStates.test(String(item.state || item.status || item.health || item.result || ''))) ? 'bad' : 'good';
}

async function queryTrueNasMaintenance(apiKey, endpoint) {
    const baseEndpoint = (endpoint || LIVE_PROBES['TrueNAS Web UI'].defaultUrl).replace(/\/+$/, '');
    if (!apiKey) {
        return {
            configured: false,
            endpoint: baseEndpoint,
            notice: 'TrueNAS API key not set',
            pools: [],
            scrubTasks: [],
            smartTests: [],
            snapshotTasks: [],
            replications: [],
            snapshotInventory: [],
            backupAssurance: {
                state: 'warn',
                label: 'unverified',
                newestSnapshot: null,
                newestSnapshotAgeHours: null,
                alerts: ['Add the TrueNAS API key to verify snapshots and replication.']
            },
            alerts: ['TrueNAS API key is missing, so maintenance health is limited.']
        };
    }

    const [poolResp, scrubResp, smartResp, snapshotResp, replicationResp, snapshotInventoryResp] = await Promise.all([
        trueNasRpcOptional(apiKey, baseEndpoint, 'pool.query', []),
        trueNasRpcOptional(apiKey, baseEndpoint, 'pool.scrub.query', []),
        trueNasRpcOptional(apiKey, baseEndpoint, 'smart.test.query', []),
        trueNasRpcOptional(apiKey, baseEndpoint, 'pool.snapshottask.query', []),
        trueNasRpcOptional(apiKey, baseEndpoint, 'replication.query', []),
        trueNasRpcOptional(apiKey, baseEndpoint, 'pool.snapshot.query', [
            [],
            { order_by: ['-created'], limit: 25 }
        ])
    ]);

    const pools = asArray(poolResp.result).map(pool => {
        const size = firstFinite(pool.size, pool.total);
        const used = firstFinite(pool.allocated, pool.used);
        const free = firstFinite(pool.free, pool.available, pool.avail);
        const usedPct = size && used !== null ? Math.round((used / size) * 100) : null;
        const state = String(pool.status || pool.state || pool.health || '').toUpperCase();
        return {
            name: String(pool.name || pool.id || 'pool'),
            status: state || (pool.healthy === true ? 'ONLINE' : 'UNKNOWN'),
            healthy: pool.healthy === true || /ONLINE|HEALTHY|AVAILABLE/i.test(state),
            size: size || 0,
            used: used || 0,
            free: free || 0,
            usedPct,
            scan: pool.scan || pool.scrub || null
        };
    });

    const scrubTasks = asArray(scrubResp.result).map(task => ({
        pool: String(task.pool_name || task.pool || task.pool_id || task.name || 'pool'),
        enabled: task.enabled !== false,
        schedule: String(task.schedule?.dom || task.schedule || task.cron || ''),
        nextRun: isoOrNull(task.next_run || task.next_run_time),
        threshold: task.threshold ?? null,
        state: String(task.state || task.status || '')
    }));

    const smartTests = asArray(smartResp.result).map(test => ({
        disks: asArray(test.disks).map(d => String(d.name || d.identifier || d)).filter(Boolean),
        type: String(test.type || test.test_type || 'SMART'),
        enabled: test.enabled !== false,
        schedule: String(test.schedule?.dom || test.schedule || test.cron || ''),
        nextRun: isoOrNull(test.next_run || test.next_run_time)
    }));

    const snapshotTasks = asArray(snapshotResp.result).map(task => ({
        dataset: String(task.dataset || task.naming_schema || task.name || 'dataset'),
        enabled: task.enabled !== false,
        recursive: Boolean(task.recursive),
        nextRun: isoOrNull(task.next_run || task.next_run_time),
        lifetime: [task.lifetime_value, task.lifetime_unit].filter(v => v !== undefined && v !== null && v !== '').join(' ')
    }));

    const replications = asArray(replicationResp.result).map(task => ({
        name: String(task.name || task.id || 'replication'),
        enabled: task.enabled !== false,
        state: String(task.state || task.status || task.last_run_state || ''),
        direction: String(task.direction || ''),
        lastRun: isoOrNull(task.last_run || task.last_run_time),
        nextRun: isoOrNull(task.next_run || task.next_run_time)
    }));

    const snapshotInventory = asArray(snapshotInventoryResp.result).map(snapshot => {
        const name = String(snapshot.name || snapshot.id || '');
        return {
            name,
            dataset: String(snapshot.dataset || name.split('@')[0] || ''),
            created: snapshotCreatedIso(snapshot)
        };
    }).filter(snapshot => snapshot.name || snapshot.created);

    const newestSnapshot = newestIso(snapshotInventory.map(snapshot => snapshot.created));
    const newestSnapshotAgeHours = ageHours(newestSnapshot);
    const enabledSnapshotTasks = snapshotTasks.filter(task => task.enabled);
    const enabledReplications = replications.filter(task => task.enabled);
    const newestReplicationRun = newestIso(enabledReplications.map(task => task.lastRun));
    const newestReplicationAgeHours = ageHours(newestReplicationRun);
    const replicationTone = trueNasTaskTone(replications);
    const backupAlerts = [];
    if (!snapshotResp.ok) backupAlerts.push(`Snapshot tasks unavailable: ${snapshotResp.error}`);
    if (!snapshotInventoryResp.ok) backupAlerts.push(`Snapshot inventory unavailable: ${snapshotInventoryResp.error}`);
    if (!replicationResp.ok) backupAlerts.push(`Replication tasks unavailable: ${replicationResp.error}`);
    if (snapshotResp.ok && !enabledSnapshotTasks.length) backupAlerts.push('No enabled snapshot task detected.');
    if (snapshotInventoryResp.ok && snapshotInventory.length === 0) backupAlerts.push('No snapshots were returned by TrueNAS.');
    if (Number.isFinite(Number(newestSnapshotAgeHours)) && Number(newestSnapshotAgeHours) > 48) {
        backupAlerts.push(`Newest snapshot is ${Math.round(newestSnapshotAgeHours / 24)}d old.`);
    }
    if (replicationResp.ok && enabledReplications.length && replicationTone !== 'good') {
        backupAlerts.push('One or more replication tasks need review.');
    }
    const backupAssurance = {
        state: backupAlerts.length ? 'warn' : 'good',
        label: backupAlerts.length ? 'review' : 'protected',
        newestSnapshot,
        newestSnapshotAgeHours,
        snapshotCount: snapshotInventory.length,
        enabledSnapshotTasks: enabledSnapshotTasks.length,
        enabledReplications: enabledReplications.length,
        newestReplicationRun,
        newestReplicationAgeHours,
        alerts: backupAlerts
    };

    const alerts = [];
    if (!poolResp.ok) alerts.push(`Pools unavailable: ${poolResp.error}`);
    if (!scrubResp.ok) alerts.push(`Scrub tasks unavailable: ${scrubResp.error}`);
    if (!smartResp.ok) alerts.push(`SMART tests unavailable: ${smartResp.error}`);
    if (!snapshotResp.ok) alerts.push(`Snapshot tasks unavailable: ${snapshotResp.error}`);
    if (!replicationResp.ok) alerts.push(`Replication tasks unavailable: ${replicationResp.error}`);
    if (!snapshotInventoryResp.ok) alerts.push(`Snapshot inventory unavailable: ${snapshotInventoryResp.error}`);
    for (const pool of pools) {
        if (!pool.healthy) alerts.push(`${pool.name} pool is ${pool.status || 'not healthy'}.`);
        if (pool.usedPct !== null && pool.usedPct >= 85) alerts.push(`${pool.name} is ${pool.usedPct}% full.`);
    }
    if (scrubResp.ok && !scrubTasks.some(t => t.enabled)) alerts.push('No enabled scrub task detected.');
    if (smartResp.ok && !smartTests.some(t => t.enabled)) alerts.push('No enabled SMART test detected.');
    if (snapshotResp.ok && !snapshotTasks.some(t => t.enabled)) alerts.push('No enabled snapshot task detected.');
    if (replicationResp.ok && replications.length && replicationTone !== 'good') alerts.push('One or more replication tasks need review.');
    for (const alert of backupAlerts) {
        if (!alerts.includes(alert)) alerts.push(alert);
    }

    return {
        configured: true,
        endpoint: baseEndpoint,
        pools,
        scrubTasks,
        smartTests,
        snapshotTasks,
        replications,
        snapshotInventory,
        backupAssurance,
        probes: {
            pools: poolResp.ok,
            scrub: scrubResp.ok,
            smart: smartResp.ok,
            snapshots: snapshotResp.ok,
            snapshotInventory: snapshotInventoryResp.ok,
            replication: replicationResp.ok
        },
        alerts
    };
}

function checkPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
        const start = Date.now();
        const socket = new net.Socket();
        let resolved = false;
        
        const done = (status) => {
            if (resolved) return;
            resolved = true;
            socket.destroy();
            resolve({
                status,
                responseTime: Date.now() - start
            });
        };
        
        socket.setTimeout(timeout);
        socket.on('connect', () => done('online'));
        socket.on('timeout', () => done('offline'));
        socket.on('error', () => done('offline'));
        
        socket.connect(port, host);
    });
}

function readJsonBody(req, limit = 16384) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk;
            if (body.length > limit) req.destroy();
        });
        req.on('end', () => {
            try { resolve(JSON.parse(body || '{}')); } catch (_) { resolve({}); }
        });
        req.on('error', () => resolve({}));
    });
}

migrateSettingsSecretsToVault();

// ===================================================================
// Docker Engine API integration (container list + live stats + control)
// Configure a reachable Docker API URL via settings.dockerHost or the
// DOCKER_HOST_URL env var, e.g. http://127.0.0.1:2375 (a docker
// socket-proxy is the safe way to expose it).
// ===================================================================
function getDockerHost() {
    const s = readDashboardSettings();
    const h = (s && (s.dockerHost || (s.docker && s.docker.host))) || process.env.DOCKER_HOST_URL || '';
    return String(h || '').trim().replace(/\/+$/, '');
}
function dockerRequest(method, p, host) {
    return new Promise((resolve, reject) => {
        let target;
        try { target = new URL(p, host); } catch (e) { reject(e); return; }
        const lib = target.protocol === 'https:' ? require('https') : require('http');
        const opts = { method, timeout: 9000, ...(target.protocol === 'https:' ? { agent: new (require('https').Agent)({ rejectUnauthorized: !tlsRelaxedFor(target) }) } : {}) };
        const rq = lib.request(target, opts, r => {
            let data = '';
            r.on('data', c => data += c);
            r.on('end', () => { let b = data; try { b = data ? JSON.parse(data) : {}; } catch (_) {} resolve({ status: r.statusCode || 0, body: b, raw: data }); });
        });
        rq.on('timeout', () => rq.destroy(new Error('timeout')));
        rq.on('error', reject);
        rq.end();
    });
}
function stripDockerFrames(s) {
    // Docker multiplexes non-TTY logs with 8-byte frame headers; strip control
    // bytes so the text is readable in the UI.
    return String(s).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').replace(/\r/g, '').trim();
}
function dockerStat(s) {
    try {
        const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
        const sysDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
        const cores = s.cpu_stats.online_cpus || (s.cpu_stats.cpu_usage.percpu_usage || []).length || 1;
        const cpuPct = sysDelta > 0 ? (cpuDelta / sysDelta) * cores * 100 : 0;
        const cache = (s.memory_stats.stats && (s.memory_stats.stats.inactive_file || s.memory_stats.stats.cache)) || 0;
        const memUsed = Math.max(0, (s.memory_stats.usage || 0) - cache);
        return { cpuPct: Math.max(0, Math.round(cpuPct * 10) / 10), mem: memUsed, memLimit: s.memory_stats.limit || 0 };
    } catch (_) { return {}; }
}
async function dockerListContainers(host) {
    const list = await dockerRequest('GET', '/containers/json?all=1', host);
    if (list.status < 200 || list.status >= 300) throw new Error('Docker API HTTP ' + list.status);
    const containers = Array.isArray(list.body) ? list.body : [];
    const running = containers.filter(c => c.State === 'running');
    const statMap = {};
    const cap = 20;
    for (let i = 0; i < running.length; i += cap) {
        await Promise.all(running.slice(i, i + cap).map(async c => {
            try {
                const st = await dockerRequest('GET', `/containers/${c.Id}/stats?stream=false`, host);
                if (st.status >= 200 && st.status < 300 && st.body) statMap[c.Id] = dockerStat(st.body);
            } catch (_) {}
        }));
    }
    return containers.map(c => ({
        id: c.Id,
        name: ((c.Names && c.Names[0]) || '').replace(/^\//, ''),
        image: c.Image,
        state: c.State,
        status: c.Status,
        ...(statMap[c.Id] || {})
    })).sort((a, b) => (b.mem || 0) - (a.mem || 0) || a.name.localeCompare(b.name));
}

// ===================================================================
// UniFi device product images (the actual device renders from Ubiquiti).
// The controller model code embeds the hardware sysid (e.g. USW"ED35"
// -> 0xED35), which maps to a device in Ubiquiti's public fingerprint.
// ===================================================================
let _uiPublic = null, _uiPublicAt = 0;
let _uiBySysid = new Map(), _uiByName = new Map(), _uiIndexBuilt = false;
function loadUiPublic() {
    if (_uiPublic && (Date.now() - _uiPublicAt) < 24 * 3600 * 1000) return Promise.resolve(_uiPublic);
    return new Promise((resolve, reject) => {
        require('https').get('https://static.ui.com/fingerprint/ui/public.json', r => {
            let d = '';
            r.on('data', c => d += c);
            r.on('end', () => { try { _uiPublic = JSON.parse(d); _uiPublicAt = Date.now(); _uiIndexBuilt = false; resolve(_uiPublic); } catch (e) { reject(e); } });
        }).on('error', reject);
    });
}
function buildUiIndex(devices) {
    _uiBySysid.clear(); _uiByName.clear();
    for (const d of devices) {
        if (!d || !d.images || !d.images.default) continue;
        const sids = [];
        if (d.sysid) sids.push(String(d.sysid).toLowerCase());
        if (Array.isArray(d.sysids)) d.sysids.forEach(s => { if (s) sids.push(String(s).toLowerCase()); });
        sids.forEach(s => { if (!_uiBySysid.has(s)) _uiBySysid.set(s, d); });
        const names = [].concat(d.shortnames || [], d.sku ? [d.sku] : []);
        names.forEach(n => { const k = String(n).toUpperCase().replace(/[^A-Z0-9]/g, ''); if (k && !_uiByName.has(k)) _uiByName.set(k, d); });
    }
    _uiIndexBuilt = true;
}
async function resolveUnifiImage(model) {
    const data = await loadUiPublic();
    const devices = (data && data.devices) || [];
    if (!_uiIndexBuilt) buildUiIndex(devices);
    const m = String(model || '').toUpperCase();
    const key = m.replace(/[^A-Z0-9]/g, '');
    let dev = _uiByName.get(key) || null;
    if (!dev) { const hex = (m.match(/([0-9A-F]{4})$/) || [])[1]; if (hex) dev = _uiBySysid.get(hex.toLowerCase()) || null; }
    if (!dev) return null;
    const inner = `https://static.ui.com/fingerprint/ui/images/${dev.id}/default/${dev.images.default}.png`;
    return `https://images.svc.ui.com/?u=${encodeURIComponent(inner)}&w=256&q=85`;
}

/* ============================================================================
   Data-driven integration framework. Each integration is pure data: an auth
   descriptor + named requests + a small pure normalize(raw) -> widget contract.
   Adding integration #N is one entry here — it auto-appears in the catalog,
   gets vaulting/redaction free, is fetched generically, and renders as a tile.
   ============================================================================ */
function jsonRes(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); }
// Template substitution for provider paths/bodies. `{{scope.key}}` inserts the
// raw value (correct for headers/JSON); `{{enc:scope.key}}` percent-encodes it,
// which is required when a credential is placed into a URL query string or an
// x-www-form-urlencoded body — otherwise a password containing &, +, %, # etc.
// silently corrupts the request. `{{base}}` is always literal.
function igApplyTpl(str, ctx) {
    return String(str || '')
        .replace(/\{\{base\}\}/g, ctx.base || '')
        .replace(/\{\{(?:(enc):)?(\w+)\.([\w.-]+)\}\}/g, (m, enc, scope, key) => {
            const o = ctx[scope];
            const v = (o && o[key] != null) ? String(o[key]) : '';
            return enc ? encodeURIComponent(v) : v;
        });
}
function igAuthFields(a) {
    if (!a || a.type === 'none') return [];
    const sec = (name, label) => ({ name, label, kind: 'secret' });
    const txt = (name, label) => ({ name, label, kind: 'text' });
    switch (a.type) {
        case 'header': case 'query': return [sec(a.field || 'key', a.label || 'API key')];
        case 'bearer': return [sec(a.field || 'token', a.label || 'Token')];
        case 'token': return [sec(a.field || 'token', a.label || 'Token')];
        case 'basic': case 'session': return [txt(a.userField || 'username', 'Username'), sec(a.passField || 'password', 'Password')];
        case 'pveToken': return [txt(a.userField || 'user', 'User@realm'), txt(a.tokenField || 'tokenid', 'Token name'), sec(a.secretField || 'secret', 'Token secret')];
        default: return [];
    }
}
function igResolveAuth(a, cred) {
    const out = { headers: {}, query: {} };
    if (!a || a.type === 'none') { if (a && a.headers) Object.assign(out.headers, a.headers); return out; }
    const f = (n) => (cred && cred[n] != null) ? String(cred[n]) : '';
    switch (a.type) {
        case 'header': out.headers[a.name] = f(a.field || 'key'); break;
        case 'query': out.query[a.name || 'apikey'] = f(a.field || 'key'); break;
        case 'bearer': out.headers['Authorization'] = 'Bearer ' + f(a.field || 'token'); break;
        case 'token': out.headers['Authorization'] = (a.prefix || 'token ') + f(a.field || 'token'); break;
        case 'basic': out.headers['Authorization'] = 'Basic ' + Buffer.from(f(a.userField || 'username') + ':' + f(a.passField || 'password')).toString('base64'); break;
        case 'pveToken': out.headers['Authorization'] = (a.scheme || 'PVEAPIToken') + '=' + f(a.userField || 'user') + '!' + f(a.tokenField || 'tokenid') + (a.sep || '=') + f(a.secretField || 'secret'); break;
    }
    if (a.headers) Object.assign(out.headers, a.headers);
    return out;
}
// ── SSRF egress guard ──────────────────────────────────────────────────────
// Classify an IP literal into a trust zone (IPv4 + the IPv6 cases that matter).
function ipZone(ip) {
    ip = String(ip || '');
    const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);   // IPv4-mapped IPv6 (dotted) → the IPv4
    if (m) ip = m[1];
    const mh = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);   // IPv4-mapped IPv6 (hex, as Node normalizes it)
    if (mh) { const a = parseInt(mh[1], 16), b = parseInt(mh[2], 16); ip = [(a >> 8) & 255, a & 255, (b >> 8) & 255, b & 255].join('.'); }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) {
        const o = ip.split('.').map(Number);
        if (o.some(x => x > 255)) return 'invalid';
        if (o[0] === 127) return 'loopback';
        if (o[0] === 0) return 'unspecified';
        if (o[0] === 169 && o[1] === 254) return 'linklocal';                                // incl. 169.254.169.254 cloud metadata
        if (o[0] === 100 && o[1] === 100 && o[2] === 100 && o[3] === 200) return 'metadata';  // Alibaba metadata
        if (o[0] === 10) return 'private';
        if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'private';
        if (o[0] === 192 && o[1] === 168) return 'private';
        return 'public';
    }
    const low = ip.toLowerCase();
    if (low === '::1') return 'loopback';
    if (low === '::' || low === '') return 'unspecified';
    if (low.startsWith('fe80')) return 'linklocal';
    if (low.startsWith('fc') || low.startsWith('fd')) return 'private';                       // ULA
    return 'public';
}
// A homelab dashboard legitimately reaches loopback + LAN, so private ranges are NOT
// blanket-blocked — but link-local (cloud metadata) and unspecified are never valid, and
// the custom-tile proxy additionally must not reach loopback (Docker socket / the
// dashboard's own admin API). Resolving the host first defeats decimal/hex/IPv4-mapped
// and DNS-name bypasses. Throws on a blocked target.
async function assertFetchTarget(rawUrl, opt) {
    opt = opt || {};
    const allowLoopback = !!opt.allowLoopback;
    const allowPrivate = opt.allowPrivate !== false;
    let u; try { u = new URL(rawUrl); } catch (e) { throw new Error('bad url'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('only http/https allowed');
    const host = u.hostname.replace(/^\[|\]$/g, '');
    let ips;
    if (net.isIP(host)) ips = [host];
    else { try { ips = (await dns.lookup(host, { all: true })).map(a => a.address); } catch (e) { throw new Error('cannot resolve host'); } }
    if (!ips.length) throw new Error('host did not resolve');
    for (const ip of ips) {
        const z = ipZone(ip);
        if (z === 'metadata' || z === 'linklocal' || z === 'unspecified' || z === 'invalid') throw new Error('blocked target: ' + z);
        if (z === 'loopback' && !allowLoopback) throw new Error('blocked target: loopback');
        if (z === 'private' && !allowPrivate) throw new Error('blocked target: private');
    }
}
function igFetch(rawUrl, opt) {
    opt = opt || {};
    return new Promise((resolve) => {
        let u; try { u = new URL(rawUrl); } catch (e) { return resolve({ status: 0, error: 'bad url' }); }
        // Cheap literal-IP guard on every proxied fetch — cloud-metadata / link-local /
        // unspecified targets are never a legitimate provider (no DNS cost for IP hosts).
        const _h = u.hostname.replace(/^\[|\]$/g, '');
        if (net.isIP(_h)) { const z = ipZone(_h); if (z === 'linklocal' || z === 'metadata' || z === 'unspecified' || z === 'invalid') return resolve({ status: 0, error: 'blocked target' }); }
        const lib = u.protocol === 'https:' ? require('https') : require('http');
        const opts = { method: opt.method || 'GET', headers: Object.assign({ 'User-Agent': 'dashboard-server/1.0', 'Accept': opt.accept === 'prometheus' ? 'text/plain' : 'application/json' }, opt.headers || {}), timeout: opt.timeout || 6000 };   // 6s: a LAN provider answers fast; a long hang just stalls the poll batch
        if (u.protocol === 'https:' && (opt.insecure || tlsRelaxedFor(u))) opts.rejectUnauthorized = false;
        let body = opt.body; if (body && typeof body !== 'string') { body = JSON.stringify(body); opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json'; }
        const req2 = lib.request(u, opts, (r) => {
            let data = ''; r.on('data', d => { data += d; if (data.length > 4e6) req2.destroy(new Error('too large')); });
            r.on('end', () => { let parsed = data; if (opt.accept !== 'prometheus') { try { parsed = JSON.parse(data); } catch (e) { } } resolve({ status: r.statusCode, body: parsed, raw: data, headers: r.headers || {} }); });
        });
        req2.on('timeout', () => req2.destroy(new Error('timeout')));
        req2.on('error', (err) => resolve({ status: 0, error: describeNetErr(err, u.host) }));
        if (body) req2.write(body);
        req2.end();
    });
}
// Resolve auth headers + an optional session-login pre-step (cookie/SID/token)
// into the header/query context every request needs. Shared by read-fetch and
// write-actions so both authenticate identically. Returns { error } on failure.
async function igResolveSession(def, base, cred, cfg) {
    const auth = igResolveAuth(def.auth, cred);
    const sessionQuery = {}, sessionHeaders = {};
    if (def.login && def.login.skipIfCred && cred[def.login.skipIfCred]) {
        // A ready-made session token (e.g. from a Plex sign-in flow) short-circuits login.
        sessionHeaders[def.login.applyName || 'Authorization'] = (def.login.applyPrefix || '') + cred[def.login.skipIfCred];
    } else if (def.login) {
        const lreq = def.login;
        const lurl = base + igApplyTpl(lreq.path, { cred, cfg, base });
        // JSON login bodies: resolve templates per field THEN stringify (quote-safe creds).
        let lbody;
        if (lreq.body != null) {
            if (typeof lreq.body === 'string') lbody = igApplyTpl(lreq.body, { cred, cfg, base });
            else if ((lreq.contentType || '') === 'application/json') { const o = {}; for (const [k, v] of Object.entries(lreq.body)) o[k] = typeof v === 'string' ? igApplyTpl(v, { cred, cfg, base }) : v; lbody = JSON.stringify(o); }
            else lbody = igApplyTpl(JSON.stringify(lreq.body), { cred, cfg, base });
        }
        const lhdr = Object.assign({}, auth.headers, lreq.headers || {});
        if (lbody != null) lhdr['Content-Type'] = lreq.contentType || 'application/x-www-form-urlencoded';
        const lr = await igFetch(lurl, { method: lreq.method || 'GET', headers: lhdr, body: lbody, insecure: def.allowInsecure });
        if (lr.status < 200 || lr.status >= 300) {
            const b = lr.body || {};
            const why = (b.error && (b.error.message || b.error.code)) || b.detail || b.message || lr.error || ('HTTP ' + lr.status);
            return { error: 'login failed: ' + why, status: lr.status };
        }
        let token = '';
        if (lreq.tokenFrom === 'cookie') {
            const name = lreq.cookieName || 'SID';
            const sc = lr.headers && lr.headers['set-cookie'];
            (Array.isArray(sc) ? sc : sc ? [sc] : []).forEach(c => { const m = c.match(new RegExp('(?:^|\\s)' + name + '=([^;]+)')); if (m) token = m[1]; });
            if (token) sessionHeaders['Cookie'] = name + '=' + token;
        } else {
            let v = lr.body; (lreq.tokenPath || 'data.sid').split('.').forEach(k => { v = (v == null) ? v : v[k]; });
            token = (v == null) ? '' : String(v);
            if ((lreq.apply || 'query') === 'header') sessionHeaders[lreq.applyName || 'X-Token'] = (lreq.applyPrefix || '') + token;
            else sessionQuery[lreq.applyName || '_sid'] = token;
        }
        if (!token) return { error: 'login: no session token returned (check credentials)' };
    }
    return { auth, sessionQuery, sessionHeaders };
}
async function runIntegration(def, base, cred, cfg, test) {
    const sess = await igResolveSession(def, base, cred, cfg);
    if (sess.error) return { ok: false, status: sess.status, error: sess.error };
    const { auth, sessionQuery, sessionHeaders } = sess;
    const reqs = (test && def.testRequest) ? def.requests.filter(r => r.id === def.testRequest) : def.requests;
    const raw = {};
    for (const rq of reqs) {
        let url = base + igApplyTpl(rq.path, { cred, cfg, base });
        const qs = Object.entries(auth.query).concat(Object.entries(sessionQuery)).filter(([, v]) => v !== '').map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v));
        if (qs.length) url += (url.includes('?') ? '&' : '?') + qs.join('&');
        const body = rq.body ? JSON.parse(igApplyTpl(JSON.stringify(rq.body), { cred, cfg, base })) : undefined;
        const r = await igFetch(url, { headers: Object.assign({}, auth.headers, sessionHeaders), method: rq.method, body, insecure: def.allowInsecure, accept: rq.accept });
        if (r.status >= 200 && r.status < 300) raw[rq.id] = r.body;
        else { if (test) return { ok: false, status: r.status, error: r.error || ('HTTP ' + r.status) }; if (!rq.optional) raw[rq.id] = undefined; }
    }
    if (test) { const k = def.testRequest || def.requests[0].id; return { ok: raw[k] !== undefined, sample: raw[k] }; }
    // Optional second stage: a provider whose data needs a follow-up call per sub-resource
    // (e.g. qui → per-instance torrent stats) fetches it here, through the same
    // authenticated pipeline, and mutates `raw` before normalize. Best-effort — a failure
    // here never fails the widget; normalize just renders without the enrichment.
    if (def.postFetch) {
        const igGet = async (path) => {
            let url = base + path;
            const qs2 = Object.entries(auth.query).concat(Object.entries(sessionQuery)).filter(([, v]) => v !== '').map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v));
            if (qs2.length) url += (url.includes('?') ? '&' : '?') + qs2.join('&');
            const r = await igFetch(url, { headers: Object.assign({}, auth.headers, sessionHeaders), insecure: def.allowInsecure });
            return (r.status >= 200 && r.status < 300) ? r.body : undefined;
        };
        try { await def.postFetch(raw, { igGet, base, cfg }); } catch (e) { /* enrichment is best-effort */ }
    }
    try { const d = def.normalize(raw, { base, cfg }) || {}; return Object.assign({ ok: d.ok !== false }, d); }
    catch (e) { return { ok: false, error: 'normalize: ' + e.message }; }
}
// Run ONE named write-action from a provider's `actions` array through the same
// authenticated pipeline. Actions are declarative: { id, label, method, path,
// body?, contentType?, confirm?, scope:'control' }. Params from the request body
// are template-substituted ({{param.name}}) so an action can target a torrent
// hash, VM id, entity id, etc. — all resolved server-side, never trusting a URL.
async function runIntegrationAction(def, base, cred, cfg, actionId, params) {
    const act = (def.actions || []).find(a => a.id === actionId);
    if (!act) return { ok: false, error: 'unknown action' };
    const sess = await igResolveSession(def, base, cred, cfg);
    if (sess.error) return { ok: false, status: sess.status, error: sess.error };
    const { auth, sessionQuery, sessionHeaders } = sess;
    const ctx = { cred, cfg, base, param: params || {} };
    let url = base + igApplyTpl(act.path, ctx);
    const qs = Object.entries(auth.query).concat(Object.entries(sessionQuery)).filter(([, v]) => v !== '').map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v));
    if (qs.length) url += (url.includes('?') ? '&' : '?') + qs.join('&');
    let body;
    const headers = Object.assign({}, auth.headers, sessionHeaders);
    if (act.body != null) {
        if (typeof act.body === 'string') { body = igApplyTpl(act.body, ctx); headers['Content-Type'] = act.contentType || 'application/x-www-form-urlencoded'; }
        else { const o = {}; for (const [k, v] of Object.entries(act.body)) o[k] = typeof v === 'string' ? igApplyTpl(v, ctx) : v; body = JSON.stringify(o); headers['Content-Type'] = act.contentType || 'application/json'; }
    }
    const r = await igFetch(url, { method: act.method || 'POST', headers, body, insecure: def.allowInsecure });
    if (r.status >= 200 && r.status < 300) return { ok: true, status: r.status };
    const b = r.body || {}; const why = (b.error && (b.error.message || b.error.code)) || b.detail || b.message || r.error || ('HTTP ' + r.status);
    return { ok: false, status: r.status, error: why };
}
function integrationCred(id) {
    const settings = readDashboardSettings();
    const plain = (settings.apiKeys || {})[id] || {};
    const vault = readSecretVault()['apiKeys.' + id] || {};
    return Object.assign({}, plain, vault);
}
// Multiple instances of one integration type share a catalog definition but keep their
// own address / credentials / name. An instance id is the bare "type" (the first one) or
// "type#N" for extras; the part before '#' selects the definition, the full id keys config.
function baseType(id) { return String(id || '').split('#')[0]; }
function integrationDef(id) { return INTEGRATIONS[baseType(id)]; }

/* ── Dropped Needle server-side auth for the in-dashboard proxy routes ──
   Prefers the vaulted Plex-issued session token; falls back to a cached
   username/password login. Credentials and tokens never reach the browser. */
function dnBaseUrl() { return (storedEndpoint('droppedneedle') || INTEGRATIONS.droppedneedle.defaultUrl).replace(/\/+$/, ''); }
let _dnLoginTok = { tok: '', at: 0 };
async function dnAuthHeaders() {
    const cred = integrationCred('droppedneedle');
    if (cred.sessionToken) return { Authorization: 'Bearer ' + cred.sessionToken, Accept: 'application/json' };
    if (cred.username && cred.password) {
        if (_dnLoginTok.tok && Date.now() - _dnLoginTok.at < 10 * 60000) return { Authorization: 'Bearer ' + _dnLoginTok.tok, Accept: 'application/json' };
        const r = await igFetch(dnBaseUrl() + '/api/v1/auth/login', { method: 'POST', body: { username: cred.username, password: cred.password } });
        if (r.status === 200 && r.body && r.body.token) { _dnLoginTok = { tok: r.body.token, at: Date.now() }; return { Authorization: 'Bearer ' + _dnLoginTok.tok, Accept: 'application/json' }; }
        throw new Error('Dropped Needle login failed — check credentials in Settings');
    }
    throw new Error('Dropped Needle not connected — use Sign in with Plex in Settings');
}

// Each entry: pure data. Adding one here makes the integration appear in the
// catalog, get vaulting/redaction free, be fetched generically, and render.
const INTEGRATIONS = {
    adguard: { id: 'adguard', title: 'AdGuard Home', category: 'network', icon: 'adguard-home', defaultUrl: 'http://192.168.1.1:3000', auth: { type: 'basic', userField: 'username', passField: 'password' }, poll: 30, testRequest: 'stats', requests: [{ id: 'stats', path: '/control/stats' }, { id: 'status', path: '/control/status', optional: true }, { id: 'filtering', path: '/control/filtering/status', optional: true }, { id: 'dnsinfo', path: '/control/dns_info', optional: true }, { id: 'sb', path: '/control/safebrowsing/status', optional: true }, { id: 'parental', path: '/control/parental/status', optional: true }], normalize: (r) => { const s = r.stats || {}; const total = s.num_dns_queries || 0, blocked = s.num_blocked_filtering || 0; const f = r.filtering || {}; const lists = Array.isArray(f.filters) ? f.filters.filter(x => x.enabled).length : null; const rules = Array.isArray(f.filters) ? f.filters.reduce((a, x) => a + (x.rules_count || 0), 0) : 0; const di = r.dnsinfo || {}; const fields = [{ label: 'Queries', value: total, kind: 'stat' }, { label: 'Blocked', value: blocked, kind: 'stat', state: 'warn' }, { label: 'Protection', value: (r.status && r.status.protection_enabled) ? 'On' : 'Off', kind: 'text', state: (r.status && r.status.protection_enabled) ? 'good' : 'bad' }, { label: 'Avg latency', value: s.avg_processing_time != null ? Math.round(s.avg_processing_time * 1000) + ' ms' : '—', kind: 'text' }]; if (lists != null) fields.push({ label: 'Blocklists', value: rules ? (lists + ' · ' + rules.toLocaleString() + ' rules') : String(lists), kind: 'text' }); if (r.sb) fields.push({ label: 'Safe Browsing', value: r.sb.enabled ? 'On' : 'Off', kind: 'text', state: r.sb.enabled ? 'good' : 'idle' }); if (r.parental) fields.push({ label: 'Parental', value: r.parental.enabled ? 'On' : 'Off', kind: 'text', state: r.parental.enabled ? 'good' : 'idle' }); if (di.dnssec_enabled != null) fields.push({ label: 'DNSSEC', value: di.dnssec_enabled ? 'On' : 'Off', kind: 'text', state: di.dnssec_enabled ? 'good' : 'idle' }); return { gauge: { label: 'Blocked', value: total ? Math.round(blocked / total * 100) : 0, max: 100, unit: '%', state: 'good' }, fields }; } },
    pihole: { id: 'pihole', title: 'Pi-hole', category: 'network', icon: 'pi-hole', defaultUrl: 'http://192.168.1.1', auth: { type: 'query', name: 'auth', field: 'token' }, poll: 30, testRequest: 'summary', requests: [{ id: 'summary', path: '/admin/api.php?summaryRaw' }], normalize: (r) => { const s = r.summary || {}; return { gauge: { label: 'Blocked', value: Math.round(Number(s.ads_percentage_today) || 0), max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Queries', value: Number(s.dns_queries_today) || 0, kind: 'stat' }, { label: 'Blocked', value: Number(s.ads_blocked_today) || 0, kind: 'stat', state: 'warn' }, { label: 'On lists', value: Number(s.domains_being_blocked) || 0, kind: 'stat' }, { label: 'Clients', value: Number(s.unique_clients) || 0, kind: 'stat' }, { label: 'Cached', value: Number(s.queries_cached) || 0, kind: 'stat' }] }; } },
    proxmox: { id: 'proxmox', title: 'Proxmox VE', category: 'virtualization', icon: 'proxmox', defaultUrl: 'https://192.168.1.10:8006', allowInsecure: true, auth: { type: 'pveToken', userField: 'user', tokenField: 'tokenid', secretField: 'secret' }, poll: 30, testRequest: 'resources', requests: [{ id: 'resources', path: '/api2/json/cluster/resources' }], normalize: (r) => { const d = (r.resources && r.resources.data) || []; const vms = d.filter(x => x.type === 'qemu' || x.type === 'lxc'); const running = vms.filter(x => x.status === 'running').length; const nodes = d.filter(x => x.type === 'node'); const cpu = nodes.reduce((a, n) => a + (n.cpu || 0), 0) / (nodes.length || 1) * 100; const mem = nodes.reduce((a, n) => a + (n.mem || 0), 0), maxmem = nodes.reduce((a, n) => a + (n.maxmem || 0), 0); const seenSt = new Set(); const storage = d.filter(x => x.type === 'storage' && x.storage && (seenSt.has(x.storage) ? false : seenSt.add(x.storage))); const stMax = storage.reduce((a, s) => a + (s.maxdisk || 0), 0), stUsed = storage.reduce((a, s) => a + (s.disk || 0), 0); const running_ct = vms.filter(x => x.type === 'lxc').length, running_vm = vms.filter(x => x.type === 'qemu').length; return { gauge: { label: 'CPU', value: Math.round(cpu), max: 100, unit: '%', state: cpu >= 90 ? 'bad' : cpu >= 75 ? 'warn' : 'good' }, fields: [{ label: 'VMs/LXC', value: running + '/' + vms.length, kind: 'text', state: running === vms.length ? 'good' : 'warn' }, { label: 'VMs', value: running_vm, kind: 'stat' }, { label: 'LXC', value: running_ct, kind: 'stat' }, { label: 'Nodes', value: nodes.filter(n => n.status === 'online').length + '/' + nodes.length, kind: 'text' }, { label: 'Memory', value: maxmem ? Math.round(mem / maxmem * 100) + '%' : '—', kind: 'text' }, { label: 'Storage', value: stMax ? Math.round(stUsed / stMax * 100) + '%' : '—', kind: 'text', state: stMax && stUsed / stMax >= 0.9 ? 'bad' : stMax && stUsed / stMax >= 0.75 ? 'warn' : 'good' }] }; } },
    portainer: { id: 'portainer', title: 'Portainer', category: 'containers', icon: 'portainer', defaultUrl: 'http://192.168.1.10:9000', auth: { type: 'header', name: 'X-API-Key', field: 'key' }, poll: 30, testRequest: 'endpoints', requests: [{ id: 'endpoints', path: '/api/endpoints' }], normalize: (r) => { const eps = Array.isArray(r.endpoints) ? r.endpoints : []; const up = eps.filter(e => e.Status === 1).length; let running = 0, total = 0, images = 0, stacks = 0, volumes = 0; eps.forEach(e => { const s = e.Snapshots && e.Snapshots[0]; if (s) { running += s.RunningContainerCount || 0; total += (s.RunningContainerCount || 0) + (s.StoppedContainerCount || 0); images += s.ImageCount || 0; stacks += s.StackCount || 0; volumes += s.VolumeCount || 0; } }); return { fields: [{ label: 'Endpoints', value: up + '/' + eps.length, kind: 'text', state: up === eps.length ? 'good' : 'warn' }, { label: 'Containers', value: running + '/' + total, kind: 'text' }, { label: 'Running', value: running, kind: 'stat', state: 'good' }, { label: 'Images', value: images, kind: 'stat' }, { label: 'Stacks', value: stacks, kind: 'stat' }, { label: 'Volumes', value: volumes, kind: 'stat' }] }; } },
    homeassistant: { id: 'homeassistant', title: 'Home Assistant', category: 'smarthome', icon: 'home-assistant', defaultUrl: 'http://192.168.1.10:8123', auth: { type: 'bearer', field: 'token' }, poll: 30, testRequest: 'config', requests: [{ id: 'config', path: '/api/config' }, { id: 'states', path: '/api/states', optional: true }], normalize: (r) => { const states = Array.isArray(r.states) ? r.states : []; const dom = (s) => String(s.entity_id || '').split('.')[0]; const nm = (s) => (s.attributes && s.attributes.friendly_name) || s.entity_id || ''; const of = (d) => states.filter(s => dom(s) === d); const lights = of('light'); const lightsOn = lights.filter(s => s.state === 'on').length; const switches = of('switch').filter(s => s.state === 'on').length; const climate = of('climate'); const locks = of('lock'); const locked = locks.filter(s => s.state === 'locked').length; const unlocked = locks.filter(s => s.state === 'unlocked'); const covers = of('cover'); const openCovers = covers.filter(s => s.state === 'open'); const personsHome = of('person').filter(s => s.state === 'home').length; const unavailable = states.filter(s => s.state === 'unavailable' || s.state === 'unknown'); const total = states.length; const availPct = total ? Math.round((total - unavailable.length) / total * 100) : 0; const fields = [{ label: 'Lights on', value: lightsOn + '/' + lights.length, kind: 'text', state: lightsOn ? 'good' : 'idle' }, { label: 'Switches on', value: switches, kind: 'stat', state: switches ? 'good' : 'idle' }, { label: 'Climate', value: climate.length, kind: 'stat' }, { label: 'Locks', value: locks.length ? (locked + '/' + locks.length) : '—', kind: 'text', state: unlocked.length ? 'warn' : (locks.length ? 'good' : 'idle') }, { label: 'People home', value: personsHome, kind: 'stat', state: personsHome ? 'good' : 'idle' }, { label: 'Entities', value: total, kind: 'stat' }]; const attn = []; unlocked.slice(0, 4).forEach(s => attn.push({ label: nm(s), sub: 'unlocked', value: 'unlocked', state: 'warn' })); openCovers.slice(0, 4).forEach(s => attn.push({ label: nm(s), sub: 'open', value: 'open', state: 'warn' })); unavailable.slice(0, 6).forEach(s => attn.push({ label: nm(s), sub: dom(s), value: 'unavailable', state: 'bad' })); return { gauge: { label: 'Available', value: availPct, max: 100, unit: '%', state: availPct >= 98 ? 'good' : availPct >= 90 ? 'warn' : 'bad' }, fields, items: attn.slice(0, 8), version: (r.config && r.config.version) || undefined, ok: !!(r.config && r.config.version) || total > 0 }; } },
    ollama: { id: 'ollama', title: 'Ollama', category: 'ai', icon: 'ollama', defaultUrl: 'http://localhost:11434', auth: { type: 'none' }, poll: 30, testRequest: 'tags', requests: [{ id: 'tags', path: '/api/tags' }, { id: 'ps', path: '/api/ps', optional: true }, { id: 'ver', path: '/api/version', optional: true }], normalize: (r) => { const models = (r.tags && Array.isArray(r.tags.models)) ? r.tags.models : []; const loaded = (r.ps && Array.isArray(r.ps.models)) ? r.ps.models : []; const gb = (b) => (Number(b) / 1e9).toFixed(1); const diskBytes = models.reduce((a, m) => a + (Number(m.size) || 0), 0); const vramBytes = loaded.reduce((a, m) => a + (Number(m.size_vram) || 0), 0); const loadedNames = new Set(loaded.map(m => m.name || m.model)); const desc = (m) => { const d = m.details || {}; return [d.parameter_size, d.quantization_level].filter(Boolean).join(' · '); }; const fields = [{ label: 'Models', value: models.length, kind: 'stat' }, { label: 'Loaded', value: loaded.length, kind: 'stat', state: loaded.length ? 'good' : 'idle' }, { label: 'On disk', value: models.length ? gb(diskBytes) + ' GB' : '—', kind: 'text' }]; if (vramBytes) fields.push({ label: 'VRAM in use', value: gb(vramBytes) + ' GB', kind: 'text', state: 'good' }); const src = models.length ? models : loaded; const items = src.slice(0, 6).map(m => { const nm = m.name || m.model || 'model'; const isLoaded = loadedNames.has(nm); return { label: nm, sub: desc(m) || (m.size ? gb(m.size) + ' GB' : ''), value: isLoaded ? 'loaded' : (m.size ? gb(m.size) + ' GB' : ''), state: isLoaded ? 'good' : 'idle' }; }); return { fields, items, version: (r.ver && r.ver.version) || undefined, ok: r.tags !== undefined }; } },
    plex: { id: 'plex', title: 'Plex', category: 'media', icon: 'plex', defaultUrl: 'http://192.168.1.10:32400', auth: { type: 'header', name: 'X-Plex-Token', field: 'token' }, poll: 20, testRequest: 'sessions', requests: [{ id: 'sessions', path: '/status/sessions' }], normalize: (r) => { const mc = r.sessions && r.sessions.MediaContainer; const meta = (mc && mc.Metadata) || []; const n = (mc && mc.size) || meta.length || 0; const tc = meta.filter(m => m.TranscodeSession || (Array.isArray(m.Media) && m.Media.some(md => Array.isArray(md.Part) && md.Part.some(pt => pt.decision === 'transcode')))).length; const items = meta.slice(0, 5).map(m => ({ label: m.title || m.grandparentTitle || 'stream', sub: (m.User && m.User.title) || '', state: 'good' })); return { fields: [{ label: 'Streams', value: n, kind: 'stat', state: n ? 'good' : 'idle' }, { label: 'Transcodes', value: tc, kind: 'stat', state: tc ? 'warn' : 'good' }, { label: 'Direct', value: Math.max(0, n - tc), kind: 'stat' }], items }; } },
    jellyfin: { id: 'jellyfin', title: 'Jellyfin', category: 'media', icon: 'jellyfin', defaultUrl: 'http://192.168.1.10:8096', auth: { type: 'header', name: 'X-Emby-Token', field: 'key' }, poll: 20, testRequest: 'sessions', requests: [{ id: 'sessions', path: '/Sessions' }, { id: 'counts', path: '/Items/Counts', optional: true }], normalize: (r) => { const ses = Array.isArray(r.sessions) ? r.sessions.filter(s => s.NowPlayingItem) : []; const c = r.counts || {}; return { fields: [{ label: 'Streams', value: ses.length, kind: 'stat', state: ses.length ? 'good' : 'idle' }, { label: 'Movies', value: c.MovieCount || 0, kind: 'stat' }, { label: 'Series', value: c.SeriesCount || 0, kind: 'stat' }, { label: 'Episodes', value: c.EpisodeCount || 0, kind: 'stat' }, { label: 'Albums', value: c.AlbumCount || 0, kind: 'stat' }], items: ses.slice(0, 5).map(s => ({ label: (s.NowPlayingItem && s.NowPlayingItem.Name) || 'stream', sub: s.UserName || '', state: 'good' })) }; } },
    overseerr: { id: 'overseerr', title: 'Overseerr / Jellyseerr', category: 'media', icon: 'overseerr', defaultUrl: 'http://192.168.1.10:5055', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 60, testRequest: 'count', requests: [{ id: 'count', path: '/api/v1/request/count' }], normalize: (r) => { const c = r.count || {}; return { fields: [{ label: 'Pending', value: c.pending || 0, kind: 'stat', state: (c.pending || 0) > 0 ? 'warn' : 'good' }, { label: 'Approved', value: c.approved || 0, kind: 'stat' }, { label: 'Processing', value: c.processing || 0, kind: 'stat', state: (c.processing || 0) > 0 ? 'warn' : 'idle' }, { label: 'Available', value: c.available || 0, kind: 'stat', state: 'good' }, { label: 'Declined', value: c.declined || 0, kind: 'stat', state: (c.declined || 0) > 0 ? 'bad' : 'idle' }, { label: 'Total', value: c.total || 0, kind: 'stat' }] }; } },
    immich: { id: 'immich', title: 'Immich', category: 'media', icon: 'immich', defaultUrl: 'http://192.168.1.10:2283', auth: { type: 'header', name: 'x-api-key', field: 'key' }, poll: 300, testRequest: 'stats', requests: [{ id: 'stats', path: '/api/server/statistics' }, { id: 'storage', path: '/api/server/storage', optional: true }, { id: 'ver', path: '/api/server/version', optional: true }, { id: 'queues', path: '/api/queues', optional: true }], normalize: (r) => { const s = r.stats || {}; const st = r.storage || {}; const q = Array.isArray(r.queues) ? r.queues : []; const active = q.reduce((a, x) => a + ((x.statistics && x.statistics.active) || 0), 0); const failed = q.reduce((a, x) => a + ((x.statistics && x.statistics.failed) || 0), 0); const v = r.ver || {}; const fields = [{ label: 'Photos', value: s.photos || 0, kind: 'stat' }, { label: 'Videos', value: s.videos || 0, kind: 'stat' }, { label: 'Users', value: Array.isArray(s.usageByUser) ? s.usageByUser.length : 0, kind: 'stat' }, { label: 'Usage', value: s.usage || 0, kind: 'bytes' }]; if (q.length) { fields.push({ label: 'Processing', value: active, kind: 'stat', state: active ? 'good' : 'idle' }); if (failed) fields.push({ label: 'Failed jobs', value: failed, kind: 'stat', state: 'bad' }); } if (st.diskUse && st.diskSize) fields.push({ label: 'Disk', value: st.diskUse + ' / ' + st.diskSize, kind: 'text' }); const dp = Number(st.diskUsagePercentage); return { gauge: isFinite(dp) && st.diskUsagePercentage != null ? { label: 'Storage', value: Math.round(dp), max: 100, unit: '%', state: dp >= 90 ? 'bad' : dp >= 75 ? 'warn' : 'good' } : undefined, fields, version: (v.major != null) ? (v.major + '.' + v.minor + '.' + v.patch) : undefined }; } },
    tailscale: { id: 'tailscale', title: 'Tailscale', category: 'network', icon: 'tailscale', defaultUrl: 'https://api.tailscale.com', auth: { type: 'bearer', field: 'token' }, poll: 300, testRequest: 'devices', requests: [{ id: 'devices', path: '/api/v2/tailnet/-/devices' }], normalize: (r) => {
        const d = (r.devices && r.devices.devices) || []; const now = Date.now();
        const devs = d.map(x => { const ip = (x.addresses || []).find(a => /^100\./.test(a)) || (x.addresses || [])[0] || ''; const online = !!(x.lastSeen && (now - new Date(x.lastSeen).getTime()) < 300000); return { name: x.hostname || String(x.name || '').split('.')[0] || 'device', ip, os: x.os || '', online, lastSeen: x.lastSeen || null, update: !!x.updateAvailable }; }).sort((a, b) => (b.online - a.online) || a.name.localeCompare(b.name));
        const online = devs.filter(x => x.online).length; const updates = devs.filter(x => x.update).length;
        return { fields: [{ label: 'Devices', value: devs.length, kind: 'stat' }, { label: 'Online', value: online, kind: 'stat', state: online ? 'good' : 'idle' }, { label: 'Updates', value: updates, kind: 'stat', state: updates ? 'warn' : 'good' }], items: devs.slice(0, 12).map(x => ({ label: x.name, sub: [x.ip, x.os].filter(Boolean).join(' · '), value: x.online ? 'online' : 'offline', state: x.online ? 'good' : 'idle' })), tailscale: { devices: devs } };
    } },
    gotify: { id: 'gotify', title: 'Gotify', category: 'notifications', icon: 'gotify', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'header', name: 'X-Gotify-Key', field: 'key' }, poll: 30, testRequest: 'messages', requests: [{ id: 'messages', path: '/message?limit=10' }], normalize: (r) => { const m = (r.messages && r.messages.messages) || []; return { fields: [{ label: 'Messages', value: (r.messages && r.messages.paging && r.messages.paging.size) || m.length, kind: 'stat' }, { label: 'High priority', value: m.filter(x => (x.priority || 0) >= 6).length, kind: 'stat', state: m.some(x => (x.priority || 0) >= 6) ? 'warn' : 'good' }], items: m.slice(0, 5).map(x => ({ label: x.title || 'message', sub: (x.message || '').slice(0, 48), state: (x.priority || 0) >= 6 ? 'bad' : (x.priority || 0) >= 3 ? 'warn' : 'idle' })) }; } },
    healthchecks: { id: 'healthchecks', title: 'Healthchecks', category: 'monitoring', icon: 'healthchecks', defaultUrl: 'https://healthchecks.io', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 60, testRequest: 'checks', requests: [{ id: 'checks', path: '/api/v3/checks/' }], normalize: (r) => { const c = (r.checks && r.checks.checks) || []; const down = c.filter(x => x.status === 'down').length; const grace = c.filter(x => x.status === 'grace').length; return { fields: [{ label: 'Checks', value: c.length, kind: 'stat' }, { label: 'Up', value: c.filter(x => x.status === 'up').length, kind: 'stat', state: 'good' }, { label: 'Down', value: down, kind: 'stat', state: down ? 'bad' : 'good' }, { label: 'Grace', value: grace, kind: 'stat', state: grace ? 'warn' : 'good' }] }; } },
    speedtest: { id: 'speedtest', title: 'Speedtest Tracker', category: 'network', icon: 'speedtest-tracker', defaultUrl: 'http://192.168.1.10:8765', auth: { type: 'bearer', field: 'token' }, poll: 600, testRequest: 'latest', requests: [{ id: 'latest', path: '/api/v1/results/latest' }], normalize: (r) => { const d = (r.latest && r.latest.data) || {}; const dl = d.download_bits ? d.download_bits / 1e6 : (d.download ? d.download / 125000 : 0); const ul = d.upload_bits ? d.upload_bits / 1e6 : (d.upload ? d.upload / 125000 : 0); return { fields: [{ label: 'Down', value: Math.round(dl) + ' Mbps', kind: 'text', state: 'good' }, { label: 'Up', value: Math.round(ul) + ' Mbps', kind: 'text' }, { label: 'Ping', value: d.ping != null ? Math.round(d.ping) + ' ms' : '—', kind: 'text' }] }; } },
    glances: { id: 'glances', title: 'Glances', category: 'monitoring', icon: 'glances', defaultUrl: 'http://192.168.1.10:61208', auth: { type: 'none' }, poll: 15, testRequest: 'cpu', requests: [{ id: 'cpu', path: '/api/4/cpu' }, { id: 'mem', path: '/api/4/mem', optional: true }, { id: 'load', path: '/api/4/load', optional: true }], normalize: (r) => { const cpu = (r.cpu && r.cpu.total) || 0; const mem = (r.mem && r.mem.percent) || 0; return { gauge: { label: 'CPU', value: Math.round(cpu), max: 100, unit: '%', state: cpu >= 90 ? 'bad' : cpu >= 75 ? 'warn' : 'good' }, bars: [{ label: 'CPU', value: Math.round(cpu), max: 100, unit: '%' }, { label: 'RAM', value: Math.round(mem), max: 100, unit: '%', state: mem >= 90 ? 'bad' : mem >= 75 ? 'warn' : '' }], fields: [{ label: 'Load', value: (r.load && r.load.min1 != null) ? r.load.min1.toFixed(2) : '—', kind: 'text' }, { label: 'Load 5m', value: (r.load && r.load.min5 != null) ? r.load.min5.toFixed(2) : '—', kind: 'text' }, { label: 'Cores', value: (r.load && r.load.cpucore) || '—', kind: 'stat' }] }; } },
    uptimekuma: { id: 'uptimekuma', title: 'Uptime Kuma', category: 'monitoring', icon: 'uptime-kuma', defaultUrl: 'http://192.168.1.10:3001', auth: { type: 'none' }, poll: 30, testRequest: 'heartbeat', configFields: [{ name: 'slug', label: 'Status-page slug', kind: 'text' }], requests: [{ id: 'heartbeat', path: '/api/status-page/heartbeat/{{cfg.slug}}' }], normalize: (r) => { const hb = (r.heartbeat && r.heartbeat.heartbeatList) || {}; const mons = Object.keys(hb); const down = mons.filter(id => { const l = hb[id]; return l && l.length && l[l.length - 1].status === 0; }).length; return { fields: [{ label: 'Monitors', value: mons.length, kind: 'stat' }, { label: 'Up', value: mons.length - down, kind: 'stat', state: 'good' }, { label: 'Down', value: down, kind: 'stat', state: down ? 'bad' : 'good' }], items: mons.slice(0, 6).map(id => { const l = hb[id]; const last = l && l[l.length - 1]; return { label: 'Monitor ' + id, value: last && last.status === 1 ? 'up' : 'down', state: last && last.status === 1 ? 'good' : 'bad' }; }) }; } },
    prometheus: { id: 'prometheus', title: 'Prometheus', category: 'monitoring', icon: 'prometheus', defaultUrl: 'http://192.168.1.10:9090', auth: { type: 'none' }, poll: 30, testRequest: 'targets', requests: [{ id: 'targets', path: '/api/v1/targets?state=active' }], normalize: (r) => { const t = (r.targets && r.targets.data && r.targets.data.activeTargets) || []; const up = t.filter(x => x.health === 'up').length; const pools = new Set(t.map(x => x.scrapePool || (x.labels && x.labels.job))).size; return { gauge: { label: 'Targets up', value: t.length ? Math.round(up / t.length * 100) : 0, max: 100, unit: '%', state: up < t.length ? 'warn' : 'good' }, fields: [{ label: 'Targets', value: up + '/' + t.length, kind: 'text', state: up === t.length ? 'good' : 'warn' }, { label: 'Down', value: t.length - up, kind: 'stat', state: (t.length - up) ? 'bad' : 'good' }, { label: 'Pools', value: pools, kind: 'stat' }] }; } },
    weather: { id: 'weather', title: 'Weather', category: 'feeds', icon: 'openweathermap', defaultUrl: 'https://api.open-meteo.com', auth: { type: 'none' }, poll: 900, configFields: [{ name: 'lat', label: 'Latitude', kind: 'text' }, { name: 'lon', label: 'Longitude', kind: 'text' }], testRequest: 'forecast', requests: [{ id: 'forecast', path: '/v1/forecast?latitude={{cfg.lat}}&longitude={{cfg.lon}}&current=temperature_2m,apparent_temperature,relative_humidity_2m,wind_speed_10m,weather_code,is_day&daily=temperature_2m_max,temperature_2m_min&timezone=auto' }], normalize: (r) => { const c = (r.forecast && r.forecast.current) || {}; const d = (r.forecast && r.forecast.daily) || {}; const num = (x) => (typeof x === 'number' && isFinite(x)) ? x : null; const temp = num(c.temperature_2m), feels = num(c.apparent_temperature), humidity = num(c.relative_humidity_2m), wind = num(c.wind_speed_10m), code = num(c.weather_code); const high = d.temperature_2m_max ? num(d.temperature_2m_max[0]) : null; const low = d.temperature_2m_min ? num(d.temperature_2m_min[0]) : null; const T = (x) => x == null ? '—' : Math.round(x) + '°'; return { fields: [{ label: 'Now', value: T(temp), kind: 'text', state: 'good' }, { label: 'Feels', value: T(feels), kind: 'text' }, { label: 'High', value: T(high), kind: 'text' }, { label: 'Low', value: T(low), kind: 'text' }, { label: 'Humidity', value: humidity != null ? Math.round(humidity) + '%' : '—', kind: 'text' }, { label: 'Wind', value: wind != null ? Math.round(wind) + ' km/h' : '—', kind: 'text' }], wx: { code, isDay: c.is_day == null ? 1 : c.is_day, temp, feels, high, low, humidity, wind } }; } },
    truenasscale: { id: 'truenasscale', title: 'TrueNAS SCALE', category: 'storage', icon: 'truenas-scale', defaultUrl: 'https://192.168.1.10', allowInsecure: true, auth: { type: 'bearer', field: 'key' }, poll: 60, testRequest: 'info', requests: [{ id: 'info', path: '/api/v2.0/system/info' }, { id: 'pools', path: '/api/v2.0/pool', optional: true }, { id: 'alerts', path: '/api/v2.0/alert/list', optional: true }], normalize: (r) => { const info = r.info || {}; const pools = Array.isArray(r.pools) ? r.pools : []; const alerts = Array.isArray(r.alerts) ? r.alerts.filter(a => !a.dismissed) : []; const alertCrit = alerts.filter(a => /CRITICAL|ERROR/i.test(a.level || '')).length; return { fields: [{ label: 'Pools', value: pools.length, kind: 'stat' }, { label: 'Healthy', value: pools.filter(p => p.healthy !== false).length + '/' + pools.length, kind: 'text', state: pools.every(p => p.healthy !== false) ? 'good' : 'bad' }, { label: 'Alerts', value: alerts.length, kind: 'stat', state: alertCrit ? 'bad' : alerts.length ? 'warn' : 'good' }, { label: 'Cores', value: info.cores || info.physical_cores || '—', kind: 'stat' }], version: info.version || undefined }; } },
    sonarr: { id: 'sonarr', title: 'Sonarr', category: 'media', icon: 'sonarr', defaultUrl: 'http://192.168.1.10:8989', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 120, testRequest: 'queue', requests: [{ id: 'queue', path: '/api/v3/queue?pageSize=1' }, { id: 'missing', path: '/api/v3/wanted/missing?pageSize=1', optional: true }, { id: 'cutoff', path: '/api/v3/wanted/cutoff?pageSize=1', optional: true }, { id: 'history', path: '/api/v3/history?page=1&pageSize=50&sortKey=date&sortDirection=descending&includeSeries=true&includeEpisode=true', optional: true }], actions: [{ id: 'rss', label: 'RSS sync', method: 'POST', path: '/api/v3/command', body: { name: 'RssSync' } }, { id: 'search-missing', label: 'Search missing', method: 'POST', path: '/api/v3/command', body: { name: 'MissingEpisodeSearch' } }], normalize: (r) => { const h = (r.history && Array.isArray(r.history.records)) ? r.history.records : []; const recentlyImported = h.filter(x => x.eventType === 'downloadFolderImported').slice(0, 12).map(x => ({ title: (x.series && x.series.title) || String(x.sourceTitle || 'import').replace(/\.[a-z0-9]{2,4}$/i, '').replace(/[._]+/g, ' ').slice(0, 80), sub: [x.episode ? 'S' + String(x.episode.seasonNumber || 0).padStart(2, '0') + 'E' + String(x.episode.episodeNumber || 0).padStart(2, '0') : '', (x.quality && x.quality.quality && x.quality.quality.name) || ''].filter(Boolean).join(' · '), at: x.date, kind: 'tv' })); return { fields: [{ label: 'Queue', value: (r.queue && r.queue.totalRecords) || 0, kind: 'stat' }, { label: 'Missing', value: (r.missing && r.missing.totalRecords) || 0, kind: 'stat', state: ((r.missing && r.missing.totalRecords) || 0) > 0 ? 'warn' : 'good' }, { label: 'Cutoff unmet', value: (r.cutoff && r.cutoff.totalRecords) || 0, kind: 'stat', state: ((r.cutoff && r.cutoff.totalRecords) || 0) > 0 ? 'warn' : 'good' }], recentlyImported }; } },
    radarr: { id: 'radarr', title: 'Radarr', category: 'media', icon: 'radarr', defaultUrl: 'http://192.168.1.10:7878', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 120, testRequest: 'queue', requests: [{ id: 'queue', path: '/api/v3/queue?pageSize=1' }, { id: 'missing', path: '/api/v3/wanted/missing?pageSize=1', optional: true }, { id: 'cutoff', path: '/api/v3/wanted/cutoff?pageSize=1', optional: true }, { id: 'history', path: '/api/v3/history?page=1&pageSize=50&sortKey=date&sortDirection=descending&includeMovie=true', optional: true }], actions: [{ id: 'rss', label: 'RSS sync', method: 'POST', path: '/api/v3/command', body: { name: 'RssSync' } }, { id: 'search-missing', label: 'Search missing', method: 'POST', path: '/api/v3/command', body: { name: 'MissingMoviesSearch' } }], normalize: (r) => { const h = (r.history && Array.isArray(r.history.records)) ? r.history.records : []; const recentlyImported = h.filter(x => x.eventType === 'downloadFolderImported').slice(0, 12).map(x => ({ title: (x.movie && x.movie.title) || String(x.sourceTitle || 'import').replace(/\.[a-z0-9]{2,4}$/i, '').replace(/[._]+/g, ' ').slice(0, 80), sub: [(x.movie && x.movie.year) ? String(x.movie.year) : '', (x.quality && x.quality.quality && x.quality.quality.name) || ''].filter(Boolean).join(' · '), at: x.date, kind: 'movie' })); return { fields: [{ label: 'Queue', value: (r.queue && r.queue.totalRecords) || 0, kind: 'stat' }, { label: 'Missing', value: (r.missing && r.missing.totalRecords) || 0, kind: 'stat', state: ((r.missing && r.missing.totalRecords) || 0) > 0 ? 'warn' : 'good' }, { label: 'Cutoff unmet', value: (r.cutoff && r.cutoff.totalRecords) || 0, kind: 'stat', state: ((r.cutoff && r.cutoff.totalRecords) || 0) > 0 ? 'warn' : 'good' }], recentlyImported }; } },
    lidarr: { id: 'lidarr', title: 'Lidarr', category: 'media', icon: 'lidarr', defaultUrl: 'http://192.168.1.10:8686', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 300, testRequest: 'queue', requests: [{ id: 'queue', path: '/api/v1/queue?pageSize=1' }, { id: 'missing', path: '/api/v1/wanted/missing?pageSize=1', optional: true }, { id: 'cutoff', path: '/api/v1/wanted/cutoff?pageSize=1', optional: true }], normalize: (r) => ({ fields: [{ label: 'Queue', value: (r.queue && r.queue.totalRecords) || 0, kind: 'stat' }, { label: 'Missing', value: (r.missing && r.missing.totalRecords) || 0, kind: 'stat', state: ((r.missing && r.missing.totalRecords) || 0) > 0 ? 'warn' : 'good' }, { label: 'Cutoff unmet', value: (r.cutoff && r.cutoff.totalRecords) || 0, kind: 'stat', state: ((r.cutoff && r.cutoff.totalRecords) || 0) > 0 ? 'warn' : 'good' }] }) },
    prowlarr: { id: 'prowlarr', title: 'Prowlarr', category: 'media', icon: 'prowlarr', defaultUrl: 'http://192.168.1.10:9696', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 300, testRequest: 'indexers', requests: [{ id: 'indexers', path: '/api/v1/indexer' }, { id: 'stats', path: '/api/v1/indexerstats', optional: true }], normalize: (r) => { const ix = Array.isArray(r.indexers) ? r.indexers : []; const st = (r.stats && Array.isArray(r.stats.indexers)) ? r.stats.indexers : []; const grabs = st.reduce((a, x) => a + (x.numberOfGrabs || 0), 0); const queries = st.reduce((a, x) => a + (x.numberOfQueries || 0), 0); return { fields: [{ label: 'Indexers', value: ix.length, kind: 'stat' }, { label: 'Enabled', value: ix.filter(x => x.enable).length, kind: 'stat', state: 'good' }, { label: 'Grabs', value: grabs, kind: 'stat' }, { label: 'Queries', value: queries, kind: 'stat' }] }; } },
    bazarr: { id: 'bazarr', title: 'Bazarr', category: 'media', icon: 'bazarr', defaultUrl: 'http://192.168.1.10:6767', auth: { type: 'header', name: 'X-API-KEY', field: 'key' }, poll: 300, testRequest: 'badges', requests: [{ id: 'badges', path: '/api/badges' }], normalize: (r) => { const b = r.badges || {}; return { fields: [{ label: 'Missing eps', value: b.episodes || 0, kind: 'stat', state: (b.episodes || 0) > 0 ? 'warn' : 'good' }, { label: 'Missing films', value: b.movies || 0, kind: 'stat', state: (b.movies || 0) > 0 ? 'warn' : 'good' }, { label: 'Providers', value: b.providers || 0, kind: 'stat' }] }; } },
    tautulli: { id: 'tautulli', title: 'Tautulli', category: 'media', icon: 'tautulli', defaultUrl: 'http://192.168.1.10:8181', auth: { type: 'query', name: 'apikey', field: 'key' }, poll: 30, testRequest: 'activity', requests: [{ id: 'activity', path: '/api/v2?cmd=get_activity' }, { id: 'history', path: '/api/v2?cmd=get_history&length=12', optional: true }], normalize: (r) => { const d = (r.activity && r.activity.response && r.activity.response.data) || {}; const hd = (r.history && r.history.response && r.history.response.data && Array.isArray(r.history.response.data.data)) ? r.history.response.data.data : []; const title = (x) => x.full_title || x.title || [x.grandparent_title, x.title].filter(Boolean).join(' · ') || 'watched'; const at = (x) => (Number(x.date || x.stopped || x.started) || 0) * 1000 || null; const items = hd.slice(0, 8).map(x => ({ label: title(x), sub: x.friendly_name || x.user || '', at: at(x), state: x.transcode_decision === 'transcode' ? 'bad' : 'ok' })); const problems = hd.filter(x => x.transcode_decision === 'transcode').slice(0, 6).map(x => ({ label: title(x), sub: (x.friendly_name || x.user || '') + ' · transcode', at: at(x) })); return { fields: [{ label: 'Streams', value: d.stream_count || 0, kind: 'stat', state: d.stream_count ? 'good' : 'idle' }, { label: 'Bandwidth', value: d.total_bandwidth ? Math.round(d.total_bandwidth / 1000) + ' Mbps' : '—', kind: 'text' }, { label: 'Transcodes', value: d.stream_count_transcode || 0, kind: 'stat' }, { label: 'Direct play', value: d.stream_count_direct_play || 0, kind: 'stat' }], items, problems }; } },
    sabnzbd: { id: 'sabnzbd', title: 'SABnzbd', category: 'downloads', icon: 'sabnzbd', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'query', name: 'apikey', field: 'key' }, poll: 15, testRequest: 'queue', requests: [{ id: 'queue', path: '/api?mode=queue&output=json' }], actions: [{ id: 'pause', label: 'Pause', method: 'GET', path: '/api?mode=pause&output=json' }, { id: 'resume', label: 'Resume', method: 'GET', path: '/api?mode=resume&output=json' }], normalize: (r) => { const q = (r.queue && r.queue.queue) || {}; const busy = Number(q.kbpersec) > 0; return { fields: [{ label: 'Speed', value: q.kbpersec ? Math.round(Number(q.kbpersec)) + ' KB/s' : 'idle', kind: 'text', state: busy ? 'good' : 'idle' }, { label: 'Queue', value: q.noofslots || 0, kind: 'stat' }, { label: 'Left', value: q.sizeleft || '—', kind: 'text' }, { label: 'ETA', value: (busy && q.timeleft && q.timeleft !== '0:00:00') ? q.timeleft : '—', kind: 'text' }, { label: 'Status', value: q.paused ? 'Paused' : (q.status || (busy ? 'Downloading' : 'Idle')), kind: 'text', state: q.paused ? 'warn' : busy ? 'good' : 'idle' }] }; } },
    qui: { id: 'qui', title: 'qui', category: 'downloads', icon: 'qui', defaultUrl: 'http://192.168.1.10:7476', auth: { type: 'header', name: 'X-API-Key', field: 'key' }, poll: 60, testRequest: 'version', requests: [{ id: 'version', path: '/api/version' }, { id: 'instances', path: '/api/instances', optional: true }], postFetch: async (raw, { igGet }) => { const inst = Array.isArray(raw.instances) ? raw.instances : []; const conn = inst.filter(i => i && i.connected && i.id != null); if (!conn.length) return; const agg = { total: 0, downloading: 0, seeding: 0, paused: 0, error: 0, dl: 0, up: 0 }; await Promise.all(conn.map(async i => { try { const t = await igGet('/api/instances/' + encodeURIComponent(i.id) + '/torrents?limit=1'); const s = t && t.stats; if (s) { agg.total += s.total || 0; agg.downloading += s.downloading || 0; agg.seeding += s.seeding || 0; agg.paused += s.paused || 0; agg.error += s.error || 0; agg.dl += s.totalDownloadSpeed || 0; agg.up += s.totalUploadSpeed || 0; } } catch (e) {} })); raw.agg = agg; }, normalize: (r) => { const inst = Array.isArray(r.instances) ? r.instances : []; const connected = inst.filter(i => i && i.connected).length; const ver = r.version || {}; const fields = [{ label: 'Instances', value: inst.length, kind: 'stat' }, { label: 'Connected', value: inst.length ? (connected + '/' + inst.length) : '—', kind: 'text', state: inst.length ? (connected === inst.length ? 'good' : connected ? 'warn' : 'bad') : 'idle' }]; const a = r.agg; if (a) { fields.push({ label: 'Torrents', value: a.total, kind: 'stat' }, { label: 'Downloading', value: a.downloading, kind: 'stat', state: a.downloading ? 'good' : 'idle' }, { label: 'Seeding', value: a.seeding, kind: 'stat', state: a.seeding ? 'good' : 'idle' }); if (a.paused) fields.push({ label: 'Paused', value: a.paused, kind: 'stat', state: 'warn' }); if (a.error) fields.push({ label: 'Errored', value: a.error, kind: 'stat', state: 'bad' }); fields.push({ label: 'Down', value: a.dl, kind: 'rate', state: a.dl ? 'good' : 'idle' }, { label: 'Up', value: a.up, kind: 'rate' }); } if (ver.updateAvailable) fields.push({ label: 'Update', value: ver.latestVersion || 'available', kind: 'text', state: 'warn' }); const items = inst.slice(0, 6).map(i => ({ label: i.name || i.host || ('instance ' + i.id), sub: i.host || '', value: i.connected ? 'connected' : (i.connectionStatus || 'offline'), state: i.connected ? 'good' : 'bad' })); return { gauge: inst.length ? { label: 'Connected', value: Math.round(connected / inst.length * 100), max: 100, unit: '%', state: connected === inst.length ? 'good' : connected ? 'warn' : 'bad' } : undefined, fields, items, version: ver.version || undefined, ok: !!ver.version }; } },
    gatus: { id: 'gatus', title: 'Gatus', category: 'monitoring', icon: 'gatus', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 30, testRequest: 'statuses', requests: [{ id: 'statuses', path: '/api/v1/endpoints/statuses' }], normalize: (r) => { const e = Array.isArray(r.statuses) ? r.statuses : []; const last = x => x.results && x.results[x.results.length - 1]; const down = e.filter(x => { const l = last(x); return l && !l.success; }).length; return { fields: [{ label: 'Endpoints', value: e.length, kind: 'stat' }, { label: 'Up', value: e.length - down, kind: 'stat', state: 'good' }, { label: 'Down', value: down, kind: 'stat', state: down ? 'bad' : 'good' }], items: e.slice(0, 6).map(x => { const l = last(x); return { label: x.name || x.key, value: l && l.success ? 'up' : 'down', state: l && l.success ? 'good' : 'bad' }; }) }; } },
    scrutiny: { id: 'scrutiny', title: 'Scrutiny', category: 'storage', icon: 'scrutiny', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 300, testRequest: 'summary', requests: [{ id: 'summary', path: '/api/summary' }], normalize: (r) => { const d = (r.summary && r.summary.data && r.summary.data.summary) || {}; const disks = Object.values(d); const failed = disks.filter(x => x.device && x.device.device_status !== 0).length; const temps = disks.map(x => x.temp).filter(t => t != null); return { fields: [{ label: 'Disks', value: disks.length, kind: 'stat' }, { label: 'Failing', value: failed, kind: 'stat', state: failed ? 'bad' : 'good' }, { label: 'Hottest', value: temps.length ? Math.max.apply(null, temps) + '°' : '—', kind: 'text' }] }; } },
    alertmanager: { id: 'alertmanager', title: 'Alertmanager', category: 'monitoring', icon: 'prometheus', defaultUrl: 'http://192.168.1.10:9093', auth: { type: 'none' }, poll: 30, testRequest: 'alerts', requests: [{ id: 'alerts', path: '/api/v2/alerts?active=true' }], normalize: (r) => { const a = Array.isArray(r.alerts) ? r.alerts : []; const crit = a.filter(x => x.labels && x.labels.severity === 'critical').length; return { fields: [{ label: 'Firing', value: a.length, kind: 'stat', state: a.length ? 'bad' : 'good' }, { label: 'Critical', value: crit, kind: 'stat', state: crit ? 'bad' : 'good' }, { label: 'Warning', value: a.filter(x => x.labels && x.labels.severity === 'warning').length, kind: 'stat', state: 'warn' }], items: a.slice(0, 5).map(x => ({ label: (x.labels && (x.labels.alertname || x.labels.instance)) || 'alert', sub: (x.annotations && x.annotations.summary) || '', state: (x.labels && x.labels.severity === 'critical') ? 'bad' : 'warn' })) }; } },
    netdata: { id: 'netdata', title: 'Netdata', category: 'monitoring', icon: 'netdata', defaultUrl: 'http://192.168.1.10:19999', auth: { type: 'none' }, poll: 30, testRequest: 'alarms', requests: [{ id: 'alarms', path: '/api/v1/alarms?active=true' }, { id: 'info', path: '/api/v1/info', optional: true }], normalize: (r) => { const arr = Object.values((r.alarms && r.alarms.alarms) || {}); const crit = arr.filter(x => x.status === 'CRITICAL').length, warn = arr.filter(x => x.status === 'WARNING').length; const info = r.info || {}; return { fields: [{ label: 'Active', value: arr.length, kind: 'stat', state: arr.length ? 'warn' : 'good' }, { label: 'Critical', value: crit, kind: 'stat', state: crit ? 'bad' : 'good' }, { label: 'Warning', value: warn, kind: 'stat', state: warn ? 'warn' : 'good' }], version: info.version || undefined }; } },
    paperless: { id: 'paperless', title: 'Paperless-ngx', category: 'productivity', icon: 'paperless-ngx', defaultUrl: 'http://192.168.1.10:8000', auth: { type: 'token', field: 'token' }, poll: 300, testRequest: 'stats', requests: [{ id: 'stats', path: '/api/statistics/' }], normalize: (r) => { const s = r.stats || {}; return { fields: [{ label: 'Documents', value: s.documents_total || 0, kind: 'stat' }, { label: 'Inbox', value: s.documents_inbox || 0, kind: 'stat', state: (s.documents_inbox || 0) > 0 ? 'warn' : 'good' }, { label: 'Tags', value: s.tag_count || 0, kind: 'stat' }, { label: 'Correspondents', value: s.correspondent_count || 0, kind: 'stat' }] }; } },
    gitea: { id: 'gitea', title: 'Gitea / Forgejo', category: 'productivity', icon: 'gitea', defaultUrl: 'http://192.168.1.10:3000', auth: { type: 'token', field: 'token' }, poll: 120, testRequest: 'version', requests: [{ id: 'version', path: '/api/v1/version' }, { id: 'notif', path: '/api/v1/notifications?status-types=unread&limit=50', optional: true }], normalize: (r) => ({ fields: [{ label: 'Version', value: (r.version && r.version.version) || '—', kind: 'text' }, { label: 'Notifications', value: Array.isArray(r.notif) ? r.notif.length : 0, kind: 'stat', state: Array.isArray(r.notif) && r.notif.length ? 'warn' : 'good' }] }) },
    nextcloud: { id: 'nextcloud', title: 'Nextcloud', category: 'productivity', icon: 'nextcloud', defaultUrl: 'http://192.168.1.10', auth: { type: 'basic', userField: 'username', passField: 'password', headers: { 'OCS-APIRequest': 'true' } }, poll: 120, testRequest: 'info', requests: [{ id: 'info', path: '/ocs/v2.php/apps/serverinfo/api/v1/info?format=json' }], normalize: (r) => { const data = (r.info && r.info.ocs && r.info.ocs.data) || {}; const d = data.nextcloud || {}; const st = d.storage || {}; const sys = d.system || {}; const act = data.activeUsers || {}; return { fields: [{ label: 'Users', value: st.num_users || 0, kind: 'stat' }, { label: 'Active 24h', value: act.last24hours || 0, kind: 'stat', state: (act.last24hours || 0) > 0 ? 'good' : 'idle' }, { label: 'Files', value: st.num_files || 0, kind: 'stat' }, { label: 'Shares', value: st.num_shares || 0, kind: 'stat' }, { label: 'Load', value: (sys.cpuload && sys.cpuload[0] != null) ? sys.cpuload[0].toFixed(2) : '—', kind: 'text' }], version: sys.version || undefined }; } },
    traefik: { id: 'traefik', title: 'Traefik', category: 'network', icon: 'traefik', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 60, testRequest: 'overview', requests: [{ id: 'overview', path: '/api/overview' }, { id: 'services', path: '/api/http/services', optional: true }, { id: 'ver', path: '/api/version', optional: true }], normalize: (r) => { const h = (r.overview && r.overview.http) || {}; const rt = h.routers || {}, sv = h.services || {}, mw = h.middlewares || {}; const svcs = Array.isArray(r.services) ? r.services : []; let bU = 0, bT = 0; svcs.forEach(x => { const ss = x.serverStatus || {}; Object.keys(ss).forEach(k => { bT++; if (/up/i.test(String(ss[k]))) bU++; }); }); const fields = [{ label: 'Routers', value: rt.total || 0, kind: 'stat' }, { label: 'Services', value: sv.total || 0, kind: 'stat' }, { label: 'Middlewares', value: mw.total || 0, kind: 'stat' }, { label: 'Errors', value: (rt.errors || 0) + (sv.errors || 0), kind: 'stat', state: ((rt.errors || 0) + (sv.errors || 0)) ? 'bad' : 'good' }]; if (bT) fields.push({ label: 'Backends', value: bU + '/' + bT, kind: 'text', state: bU === bT ? 'good' : bU ? 'warn' : 'bad' }); return { fields, version: (r.ver && r.ver.Version) || undefined }; } },
    authentik: { id: 'authentik', title: 'Authentik', category: 'security', icon: 'authentik', defaultUrl: 'https://192.168.1.10:9443', allowInsecure: true, auth: { type: 'bearer', field: 'token' }, poll: 120, testRequest: 'users', requests: [{ id: 'users', path: '/api/v3/core/users/?page_size=1' }, { id: 'fails', path: '/api/v3/events/events/?action=login_failed&page_size=1', optional: true }, { id: 'sessions', path: '/api/v3/core/authenticated_sessions/?page_size=1', optional: true }, { id: 'apps', path: '/api/v3/core/applications/?page_size=1', optional: true }, { id: 'alerts', path: '/api/v3/events/notifications/?seen=false&page_size=1', optional: true }, { id: 'tasks', path: '/api/v3/tasks/tasks/status/', optional: true }, { id: 'workers', path: '/api/v3/tasks/workers/', optional: true }, { id: 'ver', path: '/api/v3/admin/version/', optional: true }], normalize: (r) => { const cnt = x => (x && x.pagination && x.pagination.count) || 0; const sess = cnt(r.sessions), fails = cnt(r.fails), alerts = cnt(r.alerts); const t = r.tasks || {}; const tErr = Number(t.error) || 0, tWarn = Number(t.warning) || 0; const workers = Array.isArray(r.workers) ? r.workers.length : null; const v = r.ver || {}; const fields = [{ label: 'Users', value: cnt(r.users), kind: 'stat' }, { label: 'Sessions', value: sess, kind: 'stat', state: sess ? 'good' : 'idle' }, { label: 'Applications', value: cnt(r.apps), kind: 'stat' }, { label: 'Failed logins', value: fails, kind: 'stat', state: fails > 0 ? 'warn' : 'good' }, { label: 'Alerts', value: alerts, kind: 'stat', state: alerts > 0 ? 'warn' : 'good' }, { label: 'Task errors', value: tErr, kind: 'stat', state: tErr ? 'bad' : tWarn ? 'warn' : 'good' }]; if (workers != null) fields.push({ label: 'Workers', value: workers, kind: 'stat', state: workers ? 'good' : 'bad' }); if (v.outdated) fields.push({ label: 'Update', value: v.version_latest || 'available', kind: 'text', state: 'warn' }); return { fields, version: v.version_current || undefined }; } },
    crowdsec: { id: 'crowdsec', title: 'CrowdSec', category: 'security', icon: 'crowdsec', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 60, testRequest: 'decisions', requests: [{ id: 'decisions', path: '/v1/decisions' }], normalize: (r) => { const d = Array.isArray(r.decisions) ? r.decisions : []; const bans = d.filter(x => x.type === 'ban').length; return { fields: [{ label: 'Decisions', value: d.length, kind: 'stat' }, { label: 'Bans', value: bans, kind: 'stat', state: bans ? 'warn' : 'good' }, { label: 'Unique IPs', value: new Set(d.map(x => x.value)).size, kind: 'stat' }], items: d.slice(0, 5).map(x => ({ label: x.value || x.scope, sub: (x.scenario || '').split('/').pop(), value: x.type, state: x.type === 'ban' ? 'bad' : 'warn' })) }; } },
    cloudflare: { id: 'cloudflare', title: 'Cloudflare Tunnels', category: 'network', icon: 'cloudflare', defaultUrl: 'https://api.cloudflare.com', auth: { type: 'bearer', field: 'token' }, poll: 120, configFields: [{ name: 'account', label: 'Account ID', kind: 'text' }], testRequest: 'tunnels', requests: [{ id: 'tunnels', path: '/client/v4/accounts/{{cfg.account}}/cfd_tunnel?is_deleted=false' }], normalize: (r) => { const t = (r.tunnels && r.tunnels.result) || []; const healthy = t.filter(x => x.status === 'healthy').length; return { fields: [{ label: 'Tunnels', value: t.length, kind: 'stat' }, { label: 'Healthy', value: healthy + '/' + t.length, kind: 'text', state: healthy === t.length ? 'good' : 'warn' }], items: t.slice(0, 5).map(x => ({ label: x.name, value: x.status, state: x.status === 'healthy' ? 'good' : x.status === 'degraded' ? 'warn' : 'bad' })) }; } },
    pbs: { id: 'pbs', title: 'Proxmox Backup', category: 'storage', icon: 'proxmox', defaultUrl: 'https://192.168.1.10:8007', allowInsecure: true, auth: { type: 'pveToken', scheme: 'PBSAPIToken', sep: ':', userField: 'user', tokenField: 'tokenid', secretField: 'secret' }, poll: 300, testRequest: 'usage', requests: [{ id: 'usage', path: '/api2/json/status/datastore-usage' }], normalize: (r) => { const d = (r.usage && r.usage.data) || []; const ds = d[0] || {}; const pct = ds.total ? Math.round(ds.used / ds.total * 100) : 0; return { gauge: { label: 'Datastore', value: pct, max: 100, unit: '%', state: pct >= 90 ? 'bad' : pct >= 75 ? 'warn' : 'good' }, fields: [{ label: 'Datastores', value: d.length, kind: 'stat' }, { label: 'Used', value: pct + '%', kind: 'text' }], items: d.slice(0, 6).map(x => ({ label: x.store || 'datastore', sub: x.total ? (Math.round(x.used / x.total * 100) + '% of ' + (x.total / 1e12).toFixed(1) + ' TB') : '', value: x.total ? Math.round(x.used / x.total * 100) + '%' : '', state: x.total && x.used / x.total >= 0.9 ? 'bad' : x.total && x.used / x.total >= 0.75 ? 'warn' : 'good' })) }; } },
    mealie: { id: 'mealie', title: 'Mealie', category: 'productivity', icon: 'mealie', defaultUrl: 'http://192.168.1.10:9000', auth: { type: 'bearer', field: 'token' }, poll: 600, testRequest: 'stats', requests: [{ id: 'stats', path: '/api/households/statistics' }], normalize: (r) => { const s = r.stats || {}; return { fields: [{ label: 'Recipes', value: s.totalRecipes || 0, kind: 'stat' }, { label: 'Users', value: s.totalUsers || 0, kind: 'stat' }, { label: 'Categories', value: s.totalCategories || 0, kind: 'stat' }, { label: 'Tags', value: s.totalTags || 0, kind: 'stat' }] }; } },
    audiobookshelf: { id: 'audiobookshelf', title: 'Audiobookshelf', category: 'media', icon: 'audiobookshelf', defaultUrl: 'http://192.168.1.10:13378', auth: { type: 'bearer', field: 'token' }, poll: 600, testRequest: 'libraries', requests: [{ id: 'libraries', path: '/api/libraries' }], normalize: (r) => { const libs = (r.libraries && r.libraries.libraries) || []; const books = libs.filter(l => l.mediaType === 'book').length; const pods = libs.filter(l => l.mediaType === 'podcast').length; return { fields: [{ label: 'Libraries', value: libs.length, kind: 'stat' }, { label: 'Books', value: books, kind: 'stat' }, { label: 'Podcasts', value: pods, kind: 'stat', state: pods ? 'good' : 'idle' }], items: libs.slice(0, 8).map(l => ({ label: l.name || 'library', sub: l.mediaType || '', state: 'idle' })) }; } },
    droppedneedle: {
        id: 'droppedneedle', title: 'Dropped Needle', category: 'media', icon: 'droppedneedle',
        defaultUrl: 'http://127.0.0.1:8688',
        // The native /api/v1 REST API authenticates with a session token from
        // POST /auth/login {username,password} → Bearer. (App-passwords only cover the
        // OpenSubsonic/Jellyfin compat surface, NOT this API — a pasted app-password
        // yields 401 here.) Response shapes from the instance's own OpenAPI 3.1 spec.
        auth: { type: 'session', userField: 'username', passField: 'password' },
        login: { path: '/api/v1/auth/login', method: 'POST', contentType: 'application/json', body: { username: '{{cred.username}}', password: '{{cred.password}}' }, tokenFrom: 'json', tokenPath: 'token', apply: 'header', applyName: 'Authorization', applyPrefix: 'Bearer ', skipIfCred: 'sessionToken' },
        poll: 30, testRequest: 'me',
        requests: [
            { id: 'health', path: '/health', optional: true },                                         // unauthenticated liveness
            { id: 'me', path: '/api/v1/auth/me' },                                                     // validates the app password
            { id: 'stats', path: '/api/v1/library/stats', optional: true },
            { id: 'integr', path: '/api/v1/home/integration-status', optional: true },
            { id: 'client', path: '/api/v1/download-client/status', optional: true },
            { id: 'pending', path: '/api/v1/requests/pending-approvals/count', optional: true },       // {count} — admin/trusted only
            { id: 'nowplaying', path: '/api/v1/now-playing', optional: true },
            { id: 'releases', path: '/api/v1/following/new-releases?limit=6&offset=0', optional: true },
            { id: 'downloads', path: '/api/v1/downloads?page=1&page_size=100&sortKey=date&sortDirection=descending', optional: true }
        ],
        normalize: (r, ctx) => {
            const ok = !!(r.health && String(r.health.status || '').toLowerCase() === 'ok');
            const stats = r.stats || {};
            const pending = r.pending && typeof r.pending.count === 'number' ? r.pending.count : null;
            const sessions = (r.nowplaying && Array.isArray(r.nowplaying.sessions)) ? r.nowplaying.sessions : [];
            const releases = (r.releases && Array.isArray(r.releases.items)) ? r.releases.items : [];
            const dls = (r.downloads && Array.isArray(r.downloads.items)) ? r.downloads.items : [];
            const dlStat = s => String(s || '').toLowerCase();
            const dlDownloading = dls.filter(d => /^(downloading|snatching|grabbing)$/.test(dlStat(d.status)));   // actually in flight
            const dlQueued = dls.filter(d => /^(queued|searching|pending|scheduled|retrying)$/.test(dlStat(d.status)));
            const dlProblems = dls.filter(d => /^(partial|failed|error)$/.test(dlStat(d.status)));                // stuck grabs — need attention
            const dlActionable = dls.filter(d => !/^(completed|imported|cancelled|canceled)$/.test(dlStat(d.status)));
            const client = r.client || null;                     // slskd download-client status
            const clientOk = client ? (client.configured && (!client.mount || client.mount.ok !== false)) : null;
            const integr = r.integr || null;                     // which DN sources are wired up
            const fields = [
                { label: 'Backend', value: ok ? 'Online' : 'Unreachable', kind: 'text', state: ok ? 'good' : 'bad' },
                typeof stats.total_artists === 'number' ? { label: 'Artists', value: stats.total_artists, kind: 'stat' } : null,
                typeof stats.total_albums === 'number' ? { label: 'Albums', value: stats.total_albums, kind: 'stat' } : null,
                pending != null ? { label: 'Pending requests', value: pending, kind: 'stat', state: pending > 0 ? 'warn' : 'good' } : null,
                sessions.length ? { label: 'Listening now', value: sessions.length, kind: 'stat', state: 'good' } : null,
                dlDownloading.length ? { label: 'Downloading', value: dlDownloading.length, kind: 'stat', state: 'good' } : (dlQueued.length ? { label: 'Queued', value: dlQueued.length, kind: 'stat' } : null),
                dlProblems.length ? { label: 'Stuck/failed', value: dlProblems.length, kind: 'stat', state: 'warn' } : null,
                clientOk != null ? { label: 'slskd', value: clientOk ? 'Connected' : (client.configured ? 'Mount problem' : 'Not configured'), kind: 'text', state: clientOk ? 'good' : 'warn' } : null
            ].filter(Boolean);
            const items = releases.slice(0, 6).map(x => ({
                label: String(x.title || 'release'),
                sub: [x.artist_name, x.primary_type, x.first_release_date].filter(Boolean).join(' · ')
            }));
            // `dn` rides the widget payload so the client's first-class Media lane can
            // render richer structure than the generic tile contract carries.
            return {
                fields, items,
                dn: {
                    ok, user: (r.me && (r.me.display_name || r.me.username)) || null, role: r.me && r.me.role,
                    pending,
                    nowPlaying: sessions.slice(0, 4).map(s => ({ track: s.track_name, artist: s.artist_name, album: s.album_name, user: s.user_name, device: s.device_name, paused: !!s.is_paused, source: s.source, cover: s.cover_url || null, progress: (s.progress_ms != null && s.duration_ms) ? Math.round(s.progress_ms / s.duration_ms * 100) : null })),
                    releases: releases.slice(0, 6).map(x => ({ title: x.title, artist: x.artist_name, date: x.first_release_date, type: x.primary_type, mbid: x.release_group_mbid })),
                    downloads: dlActionable.slice(0, 8).map(d => ({ id: d.id, album: d.album_title, artist: d.artist_name, status: d.status, progress: d.progress_percent, files: d.files_total ? `${d.files_completed}/${d.files_total}` : null, error: d.error_message || null })),
                    dlCounts: { downloading: dlDownloading.length, queued: dlQueued.length, problems: dlProblems.length },
                    stats: { artists: stats.total_artists, albums: stats.total_albums, tracks: stats.total_tracks, size: stats.total_size_bytes, unmatched: stats.unmatched_count },
                    recentlyAdded: Array.isArray(stats.recently_added) ? stats.recently_added.slice(0, 6).map(a => ({ title: a.album_title, artist: a.album_artist_name, mbid: a.release_group_mbid, cover: a.cover_url || null, year: a.year })) : [],
                    client: clientOk, integrations: integr, base: ctx.base
                }
            };
        }
    },
    // Only /alive, /api/version and /api/config are reachable without auth. The richer admin
    // reads (user counts, 2FA adoption, org/collection totals) sit behind an ADMIN_TOKEN form
    // login that mints a short-lived cookie — a session flow this generic runner can't express
    // yet, so they're deliberately absent rather than guessed at.
    vaultwarden: { id: 'vaultwarden', title: 'Vaultwarden', category: 'security', icon: 'vaultwarden', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 120, testRequest: 'alive', requests: [{ id: 'alive', path: '/alive' }, { id: 'version', path: '/api/version', optional: true }, { id: 'config', path: '/api/config', optional: true }], normalize: (r) => { const c = r.config || {}; const st = c.settings || {}; const fields = []; const ver = c.version || r.version; fields.push({ label: 'Version', value: ver || '—', kind: 'text' }); if (st.disableUserRegistration != null) fields.push({ label: 'Signups', value: st.disableUserRegistration ? 'Closed' : 'Open', kind: 'text', state: st.disableUserRegistration ? 'good' : 'warn' }); if (c.gitHash) fields.push({ label: 'Build', value: String(c.gitHash).slice(0, 7), kind: 'text' }); if (fields.length === 1) fields.push({ label: 'Status', value: 'Online', kind: 'text', state: 'good' }); return { fields, version: ver || undefined }; } },
    // /global takes no parameters, so the tile is useful before any coin IDs are configured —
    // the per-coin watchlist from /simple/price is layered on top when they are.
    coingecko: { id: 'coingecko', title: 'Crypto (CoinGecko)', category: 'feeds', icon: 'bitcoin', defaultUrl: 'https://api.coingecko.com', auth: { type: 'none' }, poll: 300, configFields: [{ name: 'coins', label: 'Coin IDs (comma)', kind: 'text' }], testRequest: 'global', requests: [{ id: 'global', path: '/api/v3/global' }, { id: 'price', path: '/api/v3/simple/price?ids={{cfg.coins}}&vs_currencies=usd&include_24hr_change=true', optional: true }], normalize: (r) => { const usd = n => { n = Number(n) || 0; return n >= 1e12 ? '$' + (n / 1e12).toFixed(2) + 'T' : n >= 1e9 ? '$' + (n / 1e9).toFixed(1) + 'B' : n >= 1e6 ? '$' + (n / 1e6).toFixed(1) + 'M' : '$' + Math.round(n); }; const d = (r.global && r.global.data) || {}; const cap = d.total_market_cap || {}, vol = d.total_volume || {}, dom = d.market_cap_percentage || {}; const chg = d.market_cap_change_percentage_24h_usd; const fields = []; if (cap.usd != null) fields.push({ label: 'Market cap', value: usd(cap.usd), kind: 'text' }); if (chg != null) fields.push({ label: '24h', value: (chg > 0 ? '+' : '') + Number(chg).toFixed(2) + '%', kind: 'text', state: chg > 0 ? 'good' : chg < 0 ? 'bad' : 'idle' }); if (vol.usd != null) fields.push({ label: 'Volume 24h', value: usd(vol.usd), kind: 'text' }); if (dom.btc != null) fields.push({ label: 'BTC dom.', value: Number(dom.btc).toFixed(1) + '%', kind: 'text' }); if (dom.eth != null) fields.push({ label: 'ETH dom.', value: Number(dom.eth).toFixed(1) + '%', kind: 'text' }); if (d.active_cryptocurrencies != null) fields.push({ label: 'Coins', value: d.active_cryptocurrencies, kind: 'stat' }); const p = r.price || {}; const items = Object.keys(p).map(k => { const o = p[k]; const ch = o.usd_24h_change; return { label: k, value: o.usd != null ? '$' + o.usd : '—', sub: ch != null ? ch.toFixed(1) + '%' : '', state: ch > 0 ? 'good' : ch < 0 ? 'bad' : 'idle' }; }); return { fields, items }; } },
    qbittorrent: { id: 'qbittorrent', title: 'qBittorrent', category: 'media', icon: 'qbittorrent', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'session', userField: 'username', passField: 'password' }, poll: 15, login: { path: '/api/v2/auth/login', method: 'POST', body: 'username={{enc:cred.username}}&password={{enc:cred.password}}', tokenFrom: 'cookie', cookieName: 'SID', apply: 'cookie' }, testRequest: 'xfer', requests: [{ id: 'xfer', path: '/api/v2/transfer/info' }, { id: 'torrents', path: '/api/v2/torrents/info', optional: true }], actions: [{ id: 'pause-all', label: 'Pause all', method: 'POST', path: '/api/v2/torrents/pause', body: 'hashes=all' }, { id: 'resume-all', label: 'Resume all', method: 'POST', path: '/api/v2/torrents/resume', body: 'hashes=all' }], normalize: (r) => { const x = r.xfer || {}; const ts = Array.isArray(r.torrents) ? r.torrents : []; const active = ts.filter(t => /dl|down|stalledUP|uploading|forcedUP/i.test(t.state || '')).length; return { fields: [{ label: 'Download', value: x.dl_info_speed || 0, kind: 'rate', state: 'good' }, { label: 'Upload', value: x.up_info_speed || 0, kind: 'rate' }, { label: 'Torrents', value: active + '/' + ts.length, kind: 'text' }], items: ts.filter(t => /dl|down|meta/i.test(t.state || '')).slice(0, 5).map(t => ({ label: t.name, sub: Math.round((t.progress || 0) * 100) + '%', state: 'good' })) }; } },
    synology: { id: 'synology', title: 'Synology DSM', category: 'storage', icon: 'synology', defaultUrl: 'http://192.168.1.10:5000', allowInsecure: true, auth: { type: 'session', userField: 'username', passField: 'password' }, poll: 60, login: { path: '/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&session=Core&format=sid&account={{enc:cred.username}}&passwd={{enc:cred.password}}', method: 'GET', tokenFrom: 'json', tokenPath: 'data.sid', apply: 'query', applyName: '_sid' }, testRequest: 'info', requests: [{ id: 'info', path: '/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info' }], normalize: (r) => { const d = (r.info && r.info.data) || {}; const up = Number(d.uptime) || 0, days = Math.floor(up / 86400), hrs = Math.floor((up % 86400) / 3600); const t = d.temperature; return { fields: [{ label: 'Model', value: d.model || '—', kind: 'text' }, { label: 'RAM', value: d.ram ? d.ram + ' MB' : '—', kind: 'text' }, { label: 'Temp', value: t != null ? t + '°C' : '—', kind: 'text', state: t >= 65 ? 'bad' : t >= 55 ? 'warn' : 'good' }, { label: 'Uptime', value: up ? (days + 'd ' + hrs + 'h') : '—', kind: 'text' }], version: d.firmware_ver || undefined }; } },
    emby: { id: 'emby', title: 'Emby', category: 'media', icon: 'emby', defaultUrl: 'http://localhost:8096', auth: { type: 'header', name: 'X-Emby-Token', field: 'apikey' }, poll: 30, testRequest: 'info', requests: [{ id: 'info', path: '/System/Info' }, { id: 'sessions', path: '/Sessions', optional: true }], normalize: (r) => { const info = r.info || {}; const sessions = Array.isArray(r.sessions) ? r.sessions : []; const total = sessions.length; const playing = sessions.filter(s => s && s.NowPlayingItem).length; const paused = sessions.filter(s => s && s.NowPlayingItem && s.PlayState && s.PlayState.IsPaused).length; const active = playing - paused; const updateAvail = info.HasUpdateAvailable === true; const fields = [{ label: 'Streams', value: playing, kind: 'stat', state: playing > 0 ? 'good' : undefined }, { label: 'Active', value: active < 0 ? 0 : active, kind: 'stat' }, { label: 'Sessions', value: total, kind: 'stat' }, { label: 'OS', value: info.OperatingSystemDisplayName || info.OperatingSystem || '—', kind: 'text' }, { label: 'Update', value: updateAvail ? 'Available' : 'Up to date', kind: 'text', state: updateAvail ? 'warn' : 'good' }]; return { gauge: { label: 'Streaming', value: total ? Math.round(playing / total * 100) : 0, max: 100, unit: '%', state: playing > 0 ? 'good' : 'idle' }, fields: fields, version: typeof info.Version === 'string' ? info.Version : undefined, ok: typeof info.Version === 'string' }; } },
    podman: { id: 'podman', title: 'Podman', category: 'containers', icon: 'podman', defaultUrl: 'http://127.0.0.1:8080', auth: { type: 'none' }, poll: 30, testRequest: 'info', requests: [{ id: 'info', path: '/v5.0.0/libpod/info' }, { id: 'containers', path: '/v5.0.0/libpod/containers/json?all=true', optional: true }], normalize: (r) => { const info = r.info || {}; const host = info.host || {}; const store = info.store || {}; const cs = store.containerStore || {}; const ver = info.version || {}; const memTotal = Number(host.memTotal) || 0; const memFree = Number(host.memFree) || 0; const memUsedPct = memTotal ? Math.round((memTotal - memFree) / memTotal * 100) : 0; const total = Number(cs.number) || 0; const running = Number(cs.running) || 0; const stopped = Number(cs.stopped) || 0; const list = Array.isArray(r.containers) ? r.containers : null; const runningCount = list ? list.filter(c => (c && c.State) === 'running').length : running; const totalCount = list ? list.length : total; return { gauge: { label: 'Memory Used', value: memUsedPct, max: 100, unit: '%', state: memUsedPct >= 90 ? 'bad' : memUsedPct >= 75 ? 'warn' : 'good' }, fields: [{ label: 'Containers', value: totalCount, kind: 'stat' }, { label: 'Running', value: runningCount, kind: 'stat', state: 'good' }, { label: 'Stopped', value: stopped, kind: 'stat', state: stopped > 0 ? 'warn' : undefined }, { label: 'CPUs', value: Number(host.cpus) || 0, kind: 'stat' }, { label: 'Storage', value: store.graphDriverName || '—', kind: 'text' }], version: ver.Version || undefined, ok: true }; } },
    kubernetes: { id: 'kubernetes', title: 'Kubernetes', category: 'containers', icon: 'kubernetes', defaultUrl: 'https://192.168.1.100:6443', allowInsecure: true, auth: { type: 'bearer', field: 'token' }, poll: 30, testRequest: 'version', requests: [{ id: 'version', path: '/version' }, { id: 'nodes', path: '/api/v1/nodes' }, { id: 'pods', path: '/api/v1/pods', optional: true }], normalize: (r) => { const nodeItems = (r.nodes && Array.isArray(r.nodes.items)) ? r.nodes.items : []; const podItems = (r.pods && Array.isArray(r.pods.items)) ? r.pods.items : []; const nodeTotal = nodeItems.length; let nodesReady = 0; for (const n of nodeItems) { const conds = (n && n.status && Array.isArray(n.status.conditions)) ? n.status.conditions : []; const ready = conds.find(c => c && c.type === 'Ready'); if (ready && ready.status === 'True') nodesReady++; } const podTotal = podItems.length; let podsRunning = 0; for (const p of podItems) { if (p && p.status && p.status.phase === 'Running') podsRunning++; } const readyPct = nodeTotal ? Math.round(nodesReady / nodeTotal * 100) : 0; const gitVersion = (r.version && r.version.gitVersion) ? String(r.version.gitVersion) : undefined; return { gauge: { label: 'Nodes Ready', value: readyPct, max: 100, unit: '%', state: readyPct === 100 ? 'good' : (readyPct >= 50 ? 'warn' : 'bad') }, fields: [{ label: 'Nodes', value: nodeTotal, kind: 'stat' }, { label: 'Nodes Ready', value: nodesReady, kind: 'stat', state: (nodeTotal && nodesReady === nodeTotal) ? 'good' : 'warn' }, { label: 'Pods', value: podTotal, kind: 'stat' }, { label: 'Pods Running', value: podsRunning, kind: 'stat', state: (podTotal && podsRunning === podTotal) ? 'good' : 'warn' }], version: gitVersion, ok: nodeTotal > 0 }; } },
    incus: { id: 'incus', title: 'Incus / LXD', category: 'virtualization', icon: 'incus', defaultUrl: 'https://incus.local:8443', allowInsecure: true, auth: { type: 'bearer', field: 'token' }, poll: 30, testRequest: 'instances', requests: [{ id: 'instances', path: '/1.0/instances?recursion=1' }, { id: 'server', path: '/1.0', optional: true }], normalize: (r) => { const inst = (r.instances && Array.isArray(r.instances.metadata)) ? r.instances.metadata : (Array.isArray(r.instances) ? r.instances : []); const total = inst.length; let running = 0, stopped = 0, frozen = 0, errored = 0, vms = 0, containers = 0; for (const i of inst) { const st = (i && i.status) || ''; if (st === 'Running') running++; else if (st === 'Stopped') stopped++; else if (st === 'Frozen') frozen++; else if (st === 'Error') errored++; const ty = (i && i.type) || ''; if (ty === 'virtual-machine') vms++; else if (ty === 'container') containers++; } const srv = (r.server && r.server.metadata) ? r.server.metadata : (r.server || {}); const env = (srv && srv.environment) || {}; const version = env.server_version || undefined; const auth = srv.auth; const pct = total ? Math.round(running / total * 100) : 0; return { gauge: { label: 'Running', value: pct, max: 100, unit: '%', state: (total === 0 ? 'warn' : (errored > 0 ? 'bad' : (running > 0 ? 'good' : 'warn'))) }, fields: [{ label: 'Instances', value: total, kind: 'stat' }, { label: 'Running', value: running, kind: 'stat', state: 'good' }, { label: 'Stopped', value: stopped, kind: 'stat', state: stopped > 0 ? 'warn' : undefined }, { label: 'Containers', value: containers, kind: 'stat' }, { label: 'VMs', value: vms, kind: 'stat' }], version, ok: auth ? (auth === 'trusted') : (total > 0) }; } },
    opnsense: { id: 'opnsense', title: 'OPNsense', category: 'network', icon: 'opnsense', defaultUrl: 'https://192.168.1.1', allowInsecure: true, auth: { type: 'basic', userField: 'key', passField: 'secret' }, poll: 30, testRequest: 'status', requests: [{ id: 'status', path: '/api/core/system/status' }, { id: 'info', path: '/api/diagnostics/system/system_information', optional: true }, { id: 'res', path: '/api/diagnostics/system/system_resources', optional: true }, { id: 'time', path: '/api/diagnostics/system/system_time', optional: true }], normalize: (r) => { const info = (r && r.info) || {}; const res = ((r && r.res) || {}).memory || {}; const time = (r && r.time) || {}; const st = (r && r.status) || {}; const versions = Array.isArray(info.versions) ? info.versions : []; const version = versions.length ? String(versions[0]) : undefined; const total = Number(res.total) || 0; const used = Number(res.used) || 0; const memPct = total > 0 ? Math.round(used / total * 100) : 0; const loadavg = time.loadavg && time.loadavg !== 'N/A' ? String(time.loadavg) : undefined; const uptime = time.uptime ? String(time.uptime) : undefined; const sysStatus = (st && (st.status || (st.System && st.System.status))) || ''; const statusStr = String(sysStatus).toLowerCase(); const overall = statusStr && statusStr !== 'ok' ? (statusStr.indexOf('error') >= 0 || statusStr.indexOf('critical') >= 0 ? 'bad' : 'warn') : 'good'; const updates = info.updates ? String(info.updates) : undefined; const fields = []; if (uptime) fields.push({ label: 'Uptime', value: uptime, kind: 'text' }); if (loadavg) fields.push({ label: 'Load avg', value: loadavg, kind: 'text' }); if (total > 0) fields.push({ label: 'Memory', value: (Math.round(used / 1024 / 1024)) + ' / ' + (Math.round(total / 1024 / 1024)) + ' MB', kind: 'stat' }); fields.push({ label: 'Health', value: sysStatus ? String(sysStatus) : 'OK', kind: 'text', state: overall }); if (updates) fields.push({ label: 'Updates', value: updates, kind: 'text' }); const out = { fields, version, ok: overall !== 'bad' }; if (total > 0) { out.gauge = { label: 'Memory', value: memPct, max: 100, unit: '%', state: memPct >= 90 ? 'bad' : (memPct >= 75 ? 'warn' : 'good') }; } return out; } },
    pfsense: { id: 'pfsense', title: 'pfSense', category: 'network', icon: 'pfsense', defaultUrl: 'https://192.168.1.1', allowInsecure: true, auth: { type: 'header', name: 'X-API-Key', field: 'apikey' }, note: 'Requires the community REST API package (pfSense-pkg-RESTAPI, API v2). Generate a key under System › REST API › Keys.', poll: 30, testRequest: 'version', requests: [{ id: 'version', path: '/api/v2/system/version' }, { id: 'status', path: '/api/v2/status/system', optional: true }], normalize: (r) => { const v = (r.version && r.version.data) || {}; const s = (r.status && r.status.data) || {}; const num = (x) => typeof x === 'number' && isFinite(x) ? x : null; const cpu = num(s.cpu_usage); const mem = num(s.mem_usage); const disk = num(s.disk_usage); const swap = num(s.swap_usage); const memState = mem == null ? undefined : (mem >= 90 ? 'bad' : mem >= 75 ? 'warn' : 'good'); const fields = []; if (cpu != null) fields.push({ label: 'CPU', value: Math.round(cpu) + '%', kind: 'stat', state: cpu >= 90 ? 'bad' : cpu >= 75 ? 'warn' : 'good' }); if (disk != null) fields.push({ label: 'Disk', value: Math.round(disk) + '%', kind: 'stat', state: disk >= 90 ? 'bad' : disk >= 80 ? 'warn' : 'good' }); if (swap != null) fields.push({ label: 'Swap', value: Math.round(swap) + '%', kind: 'stat', state: swap >= 50 ? 'warn' : 'good' }); if (s.cpu_count != null) fields.push({ label: 'CPU Cores', value: s.cpu_count, kind: 'stat' }); if (s.uptime) fields.push({ label: 'Uptime', value: String(s.uptime), kind: 'text' }); const out = { ok: true, version: v.version ? String(v.version) : undefined, fields }; if (mem != null) out.gauge = { label: 'Memory', value: Math.round(mem), max: 100, unit: '%', state: memState }; return out; } },
    unraid: { id: 'unraid', title: 'Unraid', category: 'storage', icon: 'unraid', defaultUrl: 'http://192.168.1.10', allowInsecure: true, auth: { type: 'header', name: 'x-api-key', field: 'key' }, poll: 30, testRequest: 'online', requests: [{ id: 'online', method: 'POST', path: '/graphql', body: { query: '{ online }' } }, { id: 'data', method: 'POST', path: '/graphql', optional: true, body: { query: '{ info { os { uptime hostname } versions { unraid api } } array { state capacity { kilobytes { free used total } } } }' } }], normalize: (r) => { const d = (r.data && r.data.data) || {}; const info = d.info || {}; const os = info.os || {}; const versions = info.versions || {}; const array = d.array || {}; const cap = (array.capacity && array.capacity.kilobytes) || {}; const totalKb = Number(cap.total) || 0; const usedKb = Number(cap.used) || 0; const freeKb = Number(cap.free) || 0; const pct = totalKb ? Math.round(usedKb / totalKb * 100) : 0; const toTB = (kb) => (kb / 1e9).toFixed(2); const state = array.state || ''; const started = state === 'STARTED'; const gaugeState = pct >= 95 ? 'bad' : (pct >= 85 ? 'warn' : 'good'); const isOnline = !!(r.online && r.online.data && r.online.data.online); const fields = [{ label: 'Array', value: state || (isOnline ? 'unknown' : 'offline'), kind: 'text', state: started ? 'good' : 'warn' }, { label: 'Used', value: totalKb ? (toTB(usedKb) + ' / ' + toTB(totalKb) + ' TB') : 'n/a', kind: 'stat' }, { label: 'Free', value: totalKb ? (toTB(freeKb) + ' TB') : 'n/a', kind: 'stat', state: 'good' }]; if (os.uptime) fields.push({ label: 'Uptime', value: os.uptime, kind: 'text' }); return { gauge: totalKb ? { label: 'Array Used', value: pct, max: 100, unit: '%', state: gaugeState } : undefined, fields, version: versions.unraid || undefined, ok: isOnline || started }; } }
};

/* ══════════ SSE hub — /api/stream ══════════
   The server samples the three hot sources (service status / host metrics / media
   sessions) on its own timers and fans the results out to every connected client:
   N tabs no longer cost N× probe sweeps, and a reconnecting client is instantly
   current from the last snapshot. Samplers run ONLY while ≥1 client is connected.
   Every event is a successful upstream read — failures emit nothing, so the
   client's per-source freshness ledger goes honestly stale instead of receiving
   a fabricated payload. */
const sse = { clients: new Set(), last: {}, timers: null, nextId: 1 };
function sseSend(client, event, payload) {
    try { client.res.write(`id: ${sse.nextId++}\nevent: ${event}\ndata: ${JSON.stringify(payload)}\n\n`); }
    catch (e) { /* dead socket — the close handler cleans up */ }
}
function sseBroadcast(event, payload) {
    sse.last[event] = payload;
    for (const c of sse.clients) sseSend(c, event, payload);
}
async function sseSampleStatus() {
    try {
        const list = visibleServices();
        const results = await Promise.all(list.map(async (svc) => ({ ...svc, ...(await checkPort(svc.host, svc.port)) })));
        // Keep the /api/status poll cache warm too — fallback pollers ride the same sweep.
        _statusCache.body = JSON.stringify({ services: results, timestamp: Date.now() });
        _statusCache.at = Date.now();
        sseBroadcast('status', { services: results, ts: Date.now() });
    } catch (e) { /* skip this tick */ }
}
async function sseSampleHost() {
    try {
        const probe = LIVE_PROBES['Node Exporter'];
        const baseUrl = serviceProbeBase('Node Exporter');
        if (!baseUrl) return;   // not configured — never probe a loopback default
        const r = await liveFetch({ baseUrl, path: probe.path, key: '', probe });
        if (r.ok && r.body && r.body.raw) sseBroadcast('host', { raw: r.body.raw, ts: Date.now() });
    } catch (e) { /* skip this tick */ }
}
async function sseSampleMedia() {
    try {
        const probe = LIVE_PROBES['Tracearr'];
        const baseUrl = serviceProbeBase('Tracearr');
        if (!baseUrl) return;   // not configured — never probe a loopback default
        const r = await queryTracearr(baseUrl, storedCredential('Tracearr', 'key'), probe);
        if (r.status >= 200 && r.status < 300 && r.body) sseBroadcast('media', { body: r.body, ts: Date.now() });
    } catch (e) { /* skip this tick */ }
}
function sseStart() {
    if (sse.timers) return;
    sse.timers = [
        setInterval(sseSampleStatus, 10000),
        setInterval(sseSampleHost, 15000),
        setInterval(sseSampleMedia, 5000),
        // comment-frame heartbeat keeps proxies/browsers from timing the stream out
        setInterval(() => { for (const c of sse.clients) { try { c.res.write(': hb\n\n'); } catch (e) {} } }, 20000)
    ];
    sseSampleStatus(); sseSampleHost(); sseSampleMedia();
}
function sseStop() { if (sse.timers) { sse.timers.forEach(clearInterval); sse.timers = null; } }

/* ══════════ Security gate — rate limiting, CSRF/origin rejection, optional auth, audit log ══════════
   Additive hardening: default behaviour on a trusted LAN is unchanged, but abuse paths close.
   Set DASHBOARD_PASSWORD in the environment to require a login session on every /api route. */
const AUDIT_PATH = path.join(DATA_DIR, 'dashboard-audit.log');
const _statusCache = { body: null, at: 0, inflight: null };   // /api/status single-flight cache
// Per-provider widget cache: the client polls every enabled integration every
// few seconds (and on every nav), so without this each poll re-hit the upstream.
// Success is cached briefly; a FAILURE is cached longer so one unreachable
// provider stops timing out on every single poll cycle (the "everything laggy"
// cause). Cleared whenever settings change; bypassed by an explicit Test.
const _widgetCache = new Map();   // id -> { at, ok, out }
const WIDGET_TTL_OK = 6000, WIDGET_TTL_FAIL = 20000;
function auditLog(req, action, target, outcome) {
    // Sensitive-action journal: who did what, never the values. Append-only JSONL; must never break a request.
    try {
        const line = JSON.stringify({ ts: new Date().toISOString(), ip: (req && req.socket && req.socket.remoteAddress) || '', action, target: String(target || '').slice(0, 200), outcome: outcome || 'ok' }) + '\n';
        fs.appendFile(AUDIT_PATH, line, () => {});
    } catch (e) { /* never throw from audit */ }
}
const _rlBuckets = new Map();   // ip -> { tokens, ts }
const RL_CAPACITY = 300, RL_REFILL_PER_SEC = 5;   // generous for dashboard polling; stops abuse loops/scanners
function rateLimited(ip) {
    const now = Date.now();
    let b = _rlBuckets.get(ip);
    if (!b) { b = { tokens: RL_CAPACITY, ts: now }; _rlBuckets.set(ip, b); }
    b.tokens = Math.min(RL_CAPACITY, b.tokens + (now - b.ts) / 1000 * RL_REFILL_PER_SEC);
    b.ts = now;
    if (_rlBuckets.size > 5000) _rlBuckets.clear();   // hard bound on tracked IPs
    if (b.tokens < 1) return true;
    b.tokens -= 1;
    return false;
}
// Auth password can come from the environment (DASHBOARD_PASSWORD, for GitOps /
// container secrets) OR be set once during first-run setup (stored as a SHA-256
// hash in the encrypted vault). Both are honored; env wins if both are present.
// Auth is entirely optional — if neither is set, the dashboard is open.
const SESSION_TTL_MS = 12 * 3600 * 1000;
// Sessions are STATELESS: the cookie is `<expiryMs>.<HMAC-SHA256(vaultKey, expiry)>`,
// validated by re-signing — there is no in-memory session store. So a session
// survives a container restart (and works across multiple replicas) instead of
// being wiped on every restart, which otherwise reads as an endless login loop.
// The HMAC key is the persistent secret-vault key (stable across restarts).
const _sessionKey = dashboardSecretKey();
function signSession(exp) {
    return String(exp) + '.' + crypto.createHmac('sha256', _sessionKey).update('cc-session|' + String(exp)).digest('base64url');
}
function sha256hex(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
// Password hashing uses Node's built-in scrypt — a slow, memory-hard, salted KDF
// (no invented crypto, no dependency). Stored as a self-describing string
// `scrypt$N$saltB64$hashB64`. A legacy 64-hex sha256 digest is still verifiable and
// is transparently re-hashed to scrypt on the next successful login.
const SCRYPT_N = 1 << 15, SCRYPT_R = 8, SCRYPT_P = 1, SCRYPT_KEYLEN = 32;
function hashPassword(pw) {
    const salt = crypto.randomBytes(16);
    const dk = crypto.scryptSync(String(pw), salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 128 * 1024 * 1024 });
    return `scrypt$${SCRYPT_N}$${salt.toString('base64')}$${dk.toString('base64')}`;
}
function verifyPassword(pw, stored) {
    try {
        stored = String(stored || '');
        if (/^[0-9a-f]{64}$/i.test(stored)) {   // legacy sha256 digest
            const a = Buffer.from(sha256hex(pw), 'hex'), b = Buffer.from(stored, 'hex');
            return a.length === b.length && crypto.timingSafeEqual(a, b);
        }
        const [scheme, nStr, saltB64, hashB64] = stored.split('$');
        if (scheme !== 'scrypt' || !saltB64 || !hashB64) return false;
        const N = Number(nStr) || SCRYPT_N;
        const salt = Buffer.from(saltB64, 'base64'), target = Buffer.from(hashB64, 'base64');
        const dk = crypto.scryptSync(String(pw), salt, target.length, { N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 256 * 1024 * 1024 });
        return dk.length === target.length && crypto.timingSafeEqual(dk, target);
    } catch (e) { return false; }
}
function storedAuthTarget() { try { return (readSecretVault().auth || {}).passwordHash || ''; } catch (e) { return ''; } }
// Hash the env password once at boot with a per-process salt so login is slow +
// constant-time without persisting a salt for a value that lives in the environment.
const _envAuthTarget = process.env.DASHBOARD_PASSWORD ? hashPassword(process.env.DASHBOARD_PASSWORD) : '';
function authTarget() { return _envAuthTarget || storedAuthTarget(); }
function authEnabled() { return !!authTarget(); }
function authPasswordFromEnv() { return !!process.env.DASHBOARD_PASSWORD; }
function setVaultAuthPassword(pw) {
    const v = readSecretVault(); v.auth = v.auth || {};
    if (pw) v.auth.passwordHash = hashPassword(pw); else delete v.auth.passwordHash;
    writeSecretVault(v);
}
function issueSession(req, res, extra) {
    const exp = Date.now() + SESSION_TTL_MS;
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(req, 'cc_session', signSession(exp), SESSION_TTL_MS / 1000) });
    res.end(JSON.stringify(Object.assign({ ok: true }, extra || {})));
}
function parseCookies(req) { const out = {}; String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return out; }
function hasSession(req) {
    const tok = parseCookies(req).cc_session || '';
    const dot = tok.indexOf('.');
    if (dot < 1) return false;
    const exp = Number(tok.slice(0, dot));
    if (!Number.isFinite(exp) || exp <= Date.now()) return false;
    const expected = signSession(exp);
    if (tok.length !== expected.length) return false;
    try { return crypto.timingSafeEqual(Buffer.from(tok), Buffer.from(expected)); } catch (e) { return false; }
}
function timingSafeMatch(a, b) {
    // Hash both sides so lengths are equal, then constant-time compare.
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

/* ═══════════════════ Reverse-proxy / HTTPS awareness ═══════════════════
   Command Center runs HTTP internally and is meant to sit behind a TLS-
   terminating reverse proxy (Caddy, Traefik, nginx). These helpers let it
   detect the real external scheme/host from forwarded headers and mint correct
   absolute URLs + Secure cookies — so it never has to be served over plain HTTP
   to work. Set TRUST_PROXY=1 to honor X-Forwarded-* (default on; harmless on a
   direct LAN bind). PUBLIC_URL pins the canonical external origin when known. */
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
// Outbound TLS verification is ON by default. Many homelab services (UniFi,
// TrueNAS, Proxmox) use self-signed certs; set ALLOW_INSECURE_TLS=1 to skip
// verification for those upstreams, or supply a CA bundle via NODE_EXTRA_CA_CERTS.
const ALLOW_INSECURE_TLS = process.env.ALLOW_INSECURE_TLS === '1';
function reqScheme(req) {
    if (PUBLIC_URL) { try { return new URL(PUBLIC_URL).protocol.replace(':', ''); } catch (e) {} }
    if (TRUST_PROXY) {
        const xf = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
        if (xf) return xf;
        if ((req.headers['x-forwarded-ssl'] || '') === 'on') return 'https';
        if (req.headers['forwarded'] && /proto=https/i.test(req.headers['forwarded'])) return 'https';
    }
    return (req.socket && req.socket.encrypted) ? 'https' : 'http';
}
function reqHost(req) {
    if (PUBLIC_URL) { try { return new URL(PUBLIC_URL).host; } catch (e) {} }
    if (TRUST_PROXY) { const xh = (req.headers['x-forwarded-host'] || '').split(',')[0].trim(); if (xh) return xh; }
    return req.headers.host || 'localhost';
}
// Whether THIS request actually arrived over TLS — used for the session cookie's
// Secure flag and HSTS. Deliberately independent of PUBLIC_URL: PUBLIC_URL sets
// the canonical scheme for building absolute links, but it must NOT force
// `Secure` onto a cookie handed back over a real http:// connection (e.g. a
// direct http://LAN-IP hit while PUBLIC_URL is https). A Secure cookie received
// over http is silently dropped by the browser, so every login would bounce
// straight back to the lock screen. Transport = the socket is TLS, or a trusted
// proxy says so via a forwarded-proto header.
function reqIsTls(req) {
    if (req && req.socket && req.socket.encrypted) return true;
    if (TRUST_PROXY && req && req.headers) {
        const xf = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
        if (xf) return xf === 'https';
        if ((req.headers['x-forwarded-ssl'] || '') === 'on') return true;
        if (req.headers['forwarded'] && /proto=https/i.test(req.headers['forwarded'])) return true;
    }
    return false;
}
function isSecureRequest(req) { return reqIsTls(req); }
function publicOrigin(req) { return PUBLIC_URL || `${reqScheme(req)}://${reqHost(req)}`; }
// Build a Set-Cookie that upgrades to Secure automatically behind TLS.
// SameSite=Lax (not Strict): behind an authenticating reverse proxy (Pangolin,
// Authelia, Authentik…) the user reaches the dashboard via a cross-site redirect
// from the proxy's own login domain. Strict withholds the session cookie on that
// top-level navigation, so the session never "sticks" and login loops forever.
// Lax still omits the cookie on cross-site sub-requests and POSTs, and CSRF is
// independently closed by the same-origin Origin/Referer gate — so relaxing to
// Lax fixes the proxy loop without widening the CSRF surface.
// Whether the session cookie carries the `Secure` attribute. Auto by default
// (follows the real transport). A cookie marked Secure is silently DROPPED by the
// browser over http — so if a proxy's scheme handling is off, the session never
// sticks and login loops. `COOKIE_SECURE=0` forces it off (fixes the loop);
// `COOKIE_SECURE=1` forces it on.
function cookieSecure(req) {
    const f = String(process.env.COOKIE_SECURE || '').trim().toLowerCase();
    if (f === '0' || f === 'false' || f === 'off' || f === 'no') return false;
    if (f === '1' || f === 'true' || f === 'on' || f === 'yes') return true;
    return isSecureRequest(req);
}
function sessionCookie(req, name, value, maxAgeSec) {
    const secure = cookieSecure(req) ? '; Secure' : '';
    return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${secure}`;
}
// Diagnostic (throttled to one line / 4s): a protected request was rejected for
// lack of a session. THE tell for a login loop — was the cookie even sent back?
let _last401Log = 0;
function log401(url, hadCookie) {
    const now = Date.now();
    if (now - _last401Log < 4000) return;
    _last401Log = now;
    console.log(`[auth] 401 ${url} — cc_session cookie ${hadCookie ? 'WAS sent but is not a valid session (did the container restart, or the token expire?)' : 'was NOT sent back by the browser — it dropped it; behind a proxy, try COOKIE_SECURE=0'}`);
}
// Security/hardening headers for the HTML document + static responses. CSP allows
// 'unsafe-inline' for now (app.html inlines its scripts/handlers); everything else
// is same-origin. Images allow data: (inline SVG fallbacks) and https: (proxied).
function securityHeaders(req) {
    const h = {
        'Content-Security-Policy': "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'same-origin',
    };
    if (isSecureRequest(req)) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    return h;
}

/* ══════════ PWA — installable home-screen app + real icons ══════════
   Phones don't pick up a JS-injected SVG favicon and need PNG app icons + a web
   manifest to install. We rasterize the Command Center mark to PNG with a tiny
   zero-dependency software renderer (supersampled shape SDFs → a hand-rolled PNG
   encoder over zlib), generated once per size and cached. */
let _crcTable;
function crc32(buf) {
    if (!_crcTable) { _crcTable = new Int32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); _crcTable[n] = c; } }
    let c = -1; for (let i = 0; i < buf.length; i++) c = _crcTable[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ -1) >>> 0;
}
function pngEncode(N, rgba) {
    const rowLen = N * 4 + 1, raw = Buffer.alloc(N * rowLen);
    for (let y = 0; y < N; y++) { raw[y * rowLen] = 0; rgba.copy(raw, y * rowLen + 1, y * N * 4, (y + 1) * N * 4); }
    const idat = zlib.deflateSync(raw, { level: 9 });
    const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0); const body = Buffer.concat([Buffer.from(type, 'ascii'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body), 0); return Buffer.concat([len, body, crc]); };
    const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6;   // 8-bit RGBA
    return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}
function _segDist(px, py, ax, ay, bx, by) { const dx = bx - ax, dy = by - ay, L = dx * dx + dy * dy; let t = L ? ((px - ax) * dx + (py - ay) * dy) / L : 0; t = t < 0 ? 0 : t > 1 ? 1 : t; return Math.hypot(px - (ax + t * dx), py - (ay + t * dy)); }
function ccIconPng(N, inset) {
    inset = inset || 0;
    const sc = (N - 2 * inset) / 120;
    const bg = [11, 15, 20], ink = [255, 255, 255], teal = [45, 212, 191], gray = [128, 140, 146];
    const brackets = [[57, 42, 41, 51], [41, 51, 41, 69], [41, 69, 57, 78], [63, 42, 79, 51], [79, 51, 79, 69], [79, 69, 63, 78]];
    const ticks = [[60, 2, 60, 13], [107, 60, 118, 60], [60, 107, 60, 118], [2, 60, 13, 60]];
    const buf = Buffer.alloc(N * N * 4), AA = 3, nA = AA * AA;
    for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
        let r = 0, g = 0, b = 0;
        for (let sy = 0; sy < AA; sy++) for (let sx = 0; sx < AA; sx++) {
            const vx = (x + (sx + 0.5) / AA - inset) / sc, vy = (y + (sy + 0.5) / AA - inset) / sc;
            let col = bg;
            const dc = Math.hypot(vx - 60, vy - 60);
            if (Math.abs(dc - 46) < 2) col = gray;
            for (let k = 0; k < 4; k++) { const t = ticks[k]; if (_segDist(vx, vy, t[0], t[1], t[2], t[3]) < 3) { col = teal; break; } }
            for (let k = 0; k < 6; k++) { const s = brackets[k]; if (_segDist(vx, vy, s[0], s[1], s[2], s[3]) < 5.5) { col = ink; break; } }
            if (dc < 6.5) col = teal;
            r += col[0]; g += col[1]; b += col[2];
        }
        const i = (y * N + x) * 4; buf[i] = Math.round(r / nA); buf[i + 1] = Math.round(g / nA); buf[i + 2] = Math.round(b / nA); buf[i + 3] = 255;
    }
    return pngEncode(N, buf);
}
const _iconCache = {};
function ccIcon(key) {
    if (!_iconCache[key]) _iconCache[key] = key === '512' ? ccIconPng(512, 0) : key === 'maskable' ? ccIconPng(512, 52) : key === 'apple' ? ccIconPng(180, 0) : ccIconPng(192, 0);
    return _iconCache[key];
}
const CC_ICON_SVG = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 120' fill='none'><style>.ink{stroke:#0b0f12}@media(prefers-color-scheme:dark){.ink{stroke:#ffffff}}</style><circle cx='60' cy='60' r='46' class='ink' stroke-opacity='0.4' stroke-width='4' stroke-dasharray='38 22'/><g stroke='#2DD4BF' stroke-width='6' stroke-linecap='round'><path d='M60 1 V13'/><path d='M119 60 H107'/><path d='M60 119 V107'/><path d='M1 60 H13'/></g><g class='ink' stroke-width='11' stroke-linecap='round' stroke-linejoin='round'><path d='M57 42 L41 51 L41 69 L57 78'/><path d='M63 42 L79 51 L79 69 L63 78'/></g><circle cx='60' cy='60' r='6.5' fill='#2DD4BF'/></svg>";
const CC_MANIFEST = JSON.stringify({
    name: 'Command Center', short_name: 'Command Center', description: 'Mission control for your homelab',
    start_url: '/', scope: '/', display: 'standalone', orientation: 'any', background_color: '#0b0f14', theme_color: '#0b0f14',
    icons: [
        { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
        { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
        { src: '/icon-maskable.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
    ],
});
const CC_SW = "const C='cc-shell-v1';\nself.addEventListener('install',function(e){self.skipWaiting();});\nself.addEventListener('activate',function(e){e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==C;}).map(function(k){return caches.delete(k);}));}).then(function(){return self.clients.claim();}));});\nself.addEventListener('fetch',function(e){var req=e.request;if(req.method!=='GET')return;var u=new URL(req.url);if(u.origin!==self.location.origin)return;if(u.pathname.indexOf('/api/')===0)return;e.respondWith(fetch(req).then(function(r){if(r&&r.ok){var rc=r.clone();caches.open(C).then(function(c){c.put(req,rc);}).catch(function(){});}return r;}).catch(function(){return caches.match(req).then(function(m){return m||caches.match('/');});}));});";

/* ═══════════════════════════ DEMO MODE ═══════════════════════════
   `DEMO=1` serves a realistic, fully synthetic homelab so the UI is explorable
   with zero configuration — and so documentation screenshots contain no real
   infrastructure. Generic instance names, RFC-5737 documentation IPs, invented
   clients. Values drift slightly over time so charts and the live badge move. */
const DEMO = process.env.DEMO === '1';
const DEMO_T0 = Date.now();
function dwave(period, amp, base, phase) { return base + amp * Math.sin((Date.now() - DEMO_T0) / period + (phase || 0)); }
function demoSilentWav() {
    // A silent 30s mono 16-bit WAV so the DEMO player can actually play + seek — same-origin
    // (not a data: URI, which CSP media-src 'self' would block). Zeros = silence.
    const sr = 8000, secs = 30, dataLen = sr * secs * 2, b = Buffer.alloc(44 + dataLen);
    b.write('RIFF', 0); b.writeUInt32LE(36 + dataLen, 4); b.write('WAVE', 8);
    b.write('fmt ', 12); b.writeUInt32LE(16, 16); b.writeUInt16LE(1, 20); b.writeUInt16LE(1, 22);
    b.writeUInt32LE(sr, 24); b.writeUInt32LE(sr * 2, 28); b.writeUInt16LE(2, 32); b.writeUInt16LE(16, 34);
    b.write('data', 36); b.writeUInt32LE(dataLen, 40);
    return b;
}
function demoServices() {
    const S = (name, port, type, url) => ({ name, host: '198.51.100.10', port, type, url: url || `https://demo.example.com` });
    return [
        S('Plex Media Server', 32400, 'Media Server', 'https://plex.demo.example.com'),
        S('Jellyfin', 8096, 'Media Server', 'https://jellyfin.demo.example.com'),
        S('Sonarr', 8989, '*Arr'), S('Radarr', 7878, '*Arr'), S('Prowlarr', 9696, '*Arr'), S('Bazarr', 6767, '*Arr'),
        S('qBittorrent', 8080, 'Downloader'), S('SABnzbd', 8081, 'Downloader'),
        S('Overseerr', 5055, 'Requests'),
        S('Grafana', 3000, 'Monitor'), S('Prometheus', 9090, 'Monitor'), S('Node Exporter', 9100, 'Monitor'), S('Loki', 3100, 'Monitor'),
        S('Home Assistant', 8123, 'Automation'), S('AdGuard Home', 3001, 'Network'),
        S('Vaultwarden', 8222, 'Security'), S('Nginx Proxy Manager', 81, 'Gateway'),
        S('Portainer', 9000, 'Applications'), S('Immich', 2283, 'Applications'),
        S('TrueNAS', 443, 'TrueNAS', 'https://nas.demo.example.com')
    ];
}
function demoStatus() {
    // Everything up except one deliberately-degraded service, so screenshots show
    // both the healthy state AND how the deck surfaces an issue.
    return demoServices().map((s, i) => {
        const down = s.name === 'Bazarr';
        const slow = s.name === 'Immich';
        return { ...s, status: down ? 'offline' : 'online', responseTime: down ? 0 : Math.round(slow ? 640 + dwave(9000, 60, 0) : 8 + (i % 7) * 4 + dwave(7000, 5, 0, i)) };
    });
}
function demoHostProm() {
    const cores = 16;
    const memTotal = 135291469824, arc = 92 * 1024 * 1024 * 1024;
    const memAvail = Math.round(19 * 1024 * 1024 * 1024 + dwave(30000, 1.5e9, 0));
    const load = (dwave(45000, 3, 9.2)).toFixed(2);
    const boot = Math.round((DEMO_T0 - 4 * 86400e3 - 11 * 3600e3) / 1000);
    const nowSec = Date.now() / 1000;
    let out = '';
    const L = (k, v, lbl) => { out += `${k}${lbl ? '{' + lbl + '}' : ''} ${v}\n`; };
    L('node_memory_MemTotal_bytes', memTotal);
    L('node_memory_MemAvailable_bytes', memAvail);
    L('node_memory_Cached_bytes', arc);
    L('node_memory_SReclaimable_bytes', 2.1e9);
    L('node_zfs_arc_size', arc);
    L('node_memory_SwapTotal_bytes', 8589934592); L('node_memory_SwapFree_bytes', 8589934592);
    L('node_load1', load); L('node_load5', (dwave(60000, 2.4, 10.8)).toFixed(2)); L('node_load15', (dwave(90000, 1.8, 10.7)).toFixed(2));
    L('node_procs_running', 3 + (Math.floor(dwave(11000, 2, 2)) % 4));
    L('node_boot_time_seconds', boot);
    // per-core cpu counters (monotonic-ish so the client's delta yields a % band)
    const busyFrac = 0.38 + dwave(12000, 0.12, 0) / 1;
    for (let c = 0; c < cores; c++) {
        const total = nowSec * 1;
        L('node_cpu_seconds_total', (total * (1 - busyFrac)).toFixed(1), `cpu="${c}",mode="idle"`);
        L('node_cpu_seconds_total', (total * busyFrac * 0.7).toFixed(1), `cpu="${c}",mode="user"`);
        L('node_cpu_seconds_total', (total * busyFrac * 0.3).toFixed(1), `cpu="${c}",mode="system"`);
    }
    // disk io (monotonic)
    L('node_disk_read_bytes_total', Math.round(9.2e11 + (Date.now() - DEMO_T0) / 1000 * 4.1e6), 'device="nvme0n1"');
    L('node_disk_written_bytes_total', Math.round(4.4e11 + (Date.now() - DEMO_T0) / 1000 * 5.8e7), 'device="nvme0n1"');
    // pool filesystem
    L('node_filesystem_size_bytes', 40000000000000, 'mountpoint="/mnt/tank",device="tank"');
    L('node_filesystem_avail_bytes', Math.round(7600000000000 + dwave(40000, 2e10, 0)), 'mountpoint="/mnt/tank",device="tank"');
    // thermals
    const tz = [['coretemp', 'temp1', 70], ['coretemp', 'temp2', 66], ['coretemp', 'temp3', 65], ['nvme', 'temp1', 52], ['drivetemp', 'temp1', 39], ['acpitz', 'temp1', 76]];
    tz.forEach(([chip, sensor, base]) => { L('node_hwmon_temp_celsius', Math.round(base + dwave(15000, 3, 0, base)), `chip="${chip}",sensor="${sensor}"`); L('node_hwmon_temp_crit_celsius', 95, `chip="${chip}",sensor="${sensor}"`); });
    return out;
}
function demoUnifi() {
    const dev = (name, kind, model, clients, uplinkName, uplinkPort, port, spd, online = true) => ({ name, kind, model, clients, online, throughput: Math.round(dwave(8000, 4e5, 8e5, clients)), satisfaction: online ? 96 + (clients % 4) : 0, uptime: 4 * 86400 + 11 * 3600, uplinkName, uplinkPort, uplinkSpeed: spd });
    const gw = dev('Gateway', 'gateway', 'UXG', 1, '', 0, 0, 0);
    const sw = dev('Core Switch', 'switch', 'USW-Pro-24', 6, 'Gateway', 1, 1, 1000);
    const apUp = dev('Living Room AP', 'ap', 'U6-Pro', 14, 'Core Switch', 6, -1, 0);
    const apDn = dev('Office AP', 'ap', 'U6-Lite', 5, 'Core Switch', 7, -1, 0);
    const names = ['Living Room TV', 'Office Desktop', 'Kitchen Tablet', 'Guest Laptop', 'Thermostat', 'Robot Vacuum', 'Game Console', 'Work Phone', 'Backup NAS', 'Doorbell Cam', 'Smart Speaker', 'eReader'];
    const clients = names.map((n, i) => ({ name: n, hostname: n.replace(/ /g, '-').toLowerCase(), ip: '198.51.100.' + (20 + i), mac: '00:11:22:33:44:' + (16 + i).toString(16).padStart(2, '0'), wired: i % 4 === 0, radio: i % 2 ? 'na' : 'ng', channel: i % 2 ? 149 : 6, signal: i % 4 === 0 ? null : -(48 + (i * 5) % 40), vendor: ['Apple', 'Samsung', 'Google', 'Ubiquiti', 'Sonos'][i % 5], uplink: i % 3 ? 'Living Room AP' : 'Office AP', rxRate: Math.round(Math.max(0, dwave(6000, 3e6, 3e6, i))), txRate: Math.round(Math.max(0, dwave(9000, 1e6, 8e5, i))) }));
    return {
        configured: true, ok: true,
        gateway: { total: 1, online: 1, devices: [gw] },
        switches: { total: 1, online: 1, devices: [sw] },
        aps: { total: 2, online: 2, devices: [apUp, apDn] },
        offline: [],
        clients: { total: clients.length, list: clients },
        wan: { up: true, isp: 'Example ISP', ip: '203.0.113.10', rate: Math.round(dwave(5000, 6e6, 9e6)), rxRate: Math.round(dwave(5000, 6e6, 9e6)), txRate: Math.round(dwave(7000, 1e6, 1.5e6)), latency: Math.round(dwave(8000, 4, 11)), availability: 100, speedtestDown: 940, speedtestUp: 42, speedtestPing: 9 }
    };
}
function demoTracearr() {
    // Flat shape matching the client's streamMeta() parser (Plex/Tautulli/Tracearr fields).
    const movie = (mediaTitle, year, username, platform, device, mode, resolution, videoCodec, audioCodec, bitrate, ip, prog) =>
        ({ mediaType: 'movie', mediaTitle, year, username, platform, device, ipAddress: ip, serverName: 'Plex', resolution, videoCodec, audioCodec, bitrate, progressPercent: prog,
           videoDecision: mode === 'Transcode' ? 'transcode' : mode === 'Direct Stream' ? 'copy' : 'direct play', state: 'playing' });
    const episode = (showTitle, s, e, mediaTitle, username, platform, device, mode, resolution, videoCodec, audioCodec, bitrate, ip, prog) =>
        ({ mediaType: 'episode', showTitle, seasonNumber: s, episodeNumber: e, mediaTitle, username, platform, device, ipAddress: ip, serverName: 'Jellyfin', resolution, videoCodec, audioCodec, bitrate, progressPercent: prog,
           videoDecision: mode === 'Transcode' ? 'transcode' : mode === 'Direct Stream' ? 'copy' : 'direct play', state: 'playing' });
    const data = [
        movie('Interstellar', 2014, 'alex', 'Apple TV', 'Living Room TV', 'Direct Play', '4K', 'hevc', 'truehd', 42000, '198.51.100.31', 37),
        episode('Pipeline', 3, 4, 'The Reset', 'sam', 'iOS', 'iPad', 'Transcode', '1080p', 'h264', 'aac', 6800, '198.51.100.34', 61),
        movie('Blade Runner 2049', 2017, 'guest', 'Chrome', 'Web', 'Direct Stream', '1080p', 'h264', 'eac3', 12000, '198.51.100.37', 14)
    ];
    return { summary: { total: data.length, directPlays: 1, directStreams: 1, transcodes: 1, totalBitrate: '60.8 Mbps', byServer: [{ server: 'Plex', count: 2 }, { server: 'Jellyfin', count: 1 }] }, data };
}
function demoContainers() {
    const c = (name, image, memMB, cpu, netKB, days) => ({ name, image, mem: memMB * 1024 * 1024, memLimit: 4 * 1024 * 1024 * 1024, cpuPct: cpu, netRx: netKB * 1024, netTx: netKB * 512, started: Math.round((DEMO_T0 - days * 86400e3) / 1000), running: true });
    const list = [
        c('ix-plex-plex-1', 'plexinc/pms-docker:latest', 840, dwave(9000, 12, 22), 3900, 30),
        c('ix-jellyfin-jellyfin-1', 'jellyfin/jellyfin:latest', 610, dwave(8000, 8, 6), 420, 18),
        c('ix-immich-server-1', 'ghcr.io/immich-app/immich-server', 760, 2.1, 60, 1),
        c('ix-sonarr-sonarr-1', 'linuxserver/sonarr', 280, 0.4, 40, 30),
        c('ix-radarr-radarr-1', 'linuxserver/radarr', 300, 0.5, 44, 30),
        c('ix-prometheus-1', 'prom/prometheus', 810, 0.7, 90, 9),
        c('ix-grafana-1', 'grafana/grafana', 250, 0.3, 30, 9),
        c('ix-qbittorrent-1', 'linuxserver/qbittorrent', 248, 1.1, 2200, 9),
        c('ix-vaultwarden-1', 'vaultwarden/server', 131, 0.1, 3, 2),
        c('ix-homeassistant-1', 'homeassistant/home-assistant', 420, 1.4, 120, 12)
    ];
    return { list, count: list.length, cores: 16, ts: Date.now() };
}
// Synthetic catalog-widget + Docker data so DEMO mode showcases every concept —
// AI (Ollama), Smart Home (Home Assistant), the *Arr pipeline, media, and the
// live container log floor — with no real upstream. These ids read as "enabled".
const DEMO_ENABLED = new Set(['ollama', 'homeassistant', 'sonarr', 'radarr', 'sabnzbd', 'qbittorrent', 'plex', 'jellyfin', 'tautulli', 'proxmox', 'adguard', 'prometheus', 'immich', 'droppedneedle', 'tailscale']);
function demoDockerContainers() {
    const rows = demoContainers().list.map((c, i) => ({
        id: 'demo' + ('0' + (i + 10)).slice(-2) + c.name.replace(/[^a-z0-9]/gi, '').slice(0, 12),
        name: c.name, image: c.image, state: 'running', status: 'Up ' + (2 + i) + ' day' + (i === 0 ? '' : 's'),
        cpuPct: c.cpuPct, mem: c.mem, memLimit: c.memLimit, netRx: c.netRx, netTx: c.netTx
    }));
    rows.push({ id: 'demo99resticbak', name: 'ix-backup-restic-1', image: 'restic/restic:latest', state: 'exited', status: 'Exited (0) 3 hours ago', cpuPct: 0, mem: 0, memLimit: 4 * 1024 * 1024 * 1024, netRx: 0, netTx: 0 });
    return rows;
}
function demoDockerLogs() {
    const now = Date.now();
    const T = (s) => new Date(now - s * 1000).toISOString().replace('T', ' ').slice(0, 19);
    return [
        [420, 'INFO ', 'starting up — version 1.42.0 (build 8f3c1a)'],
        [372, 'INFO ', 'configuration loaded from /config'],
        [318, 'INFO ', 'listening on 0.0.0.0'],
        [244, 'INFO ', 'connected to database in 42ms'],
        [176, 'WARN ', 'slow query (318ms): SELECT * FROM history ORDER BY ts DESC LIMIT 500'],
        [120, 'INFO ', 'scheduled task complete: 128 items processed'],
        [64, 'INFO ', 'health check ok'],
        [28, 'INFO ', 'request GET /api/status -> 200 in 3ms'],
        [6, 'INFO ', 'request GET /api/health -> 200 in 1ms']
    ].map(([s, lvl, msg]) => `[${T(s)}] ${lvl} ${msg}`).join('\n');
}
function demoWidget(type) {
    type = String(type || '').split('#')[0];   // instance "sonarr#2" shares the base type's demo data
    const W = {
        ollama: { fields: [{ label: 'Models', value: 5, kind: 'stat' }, { label: 'Loaded', value: 2, kind: 'stat', state: 'good' }, { label: 'On disk', value: '28.4 GB', kind: 'text' }, { label: 'VRAM in use', value: '11.2 GB', kind: 'text', state: 'good' }], items: [{ label: 'llama3.1:8b', sub: '8.0B · Q4_K_M', value: 'loaded', state: 'good' }, { label: 'qwen2.5-coder:14b', sub: '14.8B · Q4_K_M', value: 'loaded', state: 'good' }, { label: 'mistral-small:24b', sub: '24B · Q4_K_M', value: '14.3 GB', state: 'idle' }, { label: 'nomic-embed-text:latest', sub: '137M · F16', value: '0.3 GB', state: 'idle' }, { label: 'llava:13b', sub: '13B · Q4_0', value: '8.0 GB', state: 'idle' }], version: '0.5.4' },
        homeassistant: { gauge: { label: 'Available', value: 99, max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Lights on', value: '4/11', kind: 'text', state: 'good' }, { label: 'Switches on', value: 3, kind: 'stat', state: 'good' }, { label: 'Climate', value: 2, kind: 'stat' }, { label: 'Locks', value: '2/2', kind: 'text', state: 'good' }, { label: 'People home', value: 2, kind: 'stat', state: 'good' }, { label: 'Entities', value: 214, kind: 'stat' }], items: [{ label: 'Garage Door', sub: 'open', value: 'open', state: 'warn' }], version: '2026.6.1' },
        sonarr: { fields: [{ label: 'Queue', value: 2, kind: 'stat' }, { label: 'Missing', value: 5, kind: 'stat', state: 'warn' }], recentlyImported: [{ title: 'The Bear', sub: 'S03E01 · WEBDL-1080p', at: new Date(Date.now() - 2 * 3600e3).toISOString(), kind: 'tv' }, { title: 'Shōgun', sub: 'S01E10 · Bluray-1080p', at: new Date(Date.now() - 9 * 3600e3).toISOString(), kind: 'tv' }] },
        radarr: { fields: [{ label: 'Queue', value: 1, kind: 'stat' }, { label: 'Missing', value: 3, kind: 'stat', state: 'warn' }], recentlyImported: [{ title: 'Dune: Part Two', sub: '2024 · Bluray-2160p', at: new Date(Date.now() - 5 * 3600e3).toISOString(), kind: 'movie' }] },
        sabnzbd: { fields: [{ label: 'Speed', value: Math.round(dwave(6000, 4000, 6000)) + ' KB/s', kind: 'text', state: 'good' }, { label: 'Queue', value: 3, kind: 'stat' }, { label: 'Left', value: '2.4 GB', kind: 'text' }] },
        qbittorrent: { fields: [{ label: 'Download', value: Math.max(0, Math.round(dwave(9000, 3e6, 5e6))), kind: 'rate', state: 'good' }, { label: 'Upload', value: Math.max(0, Math.round(dwave(7000, 8e5, 1.2e6))), kind: 'rate' }, { label: 'Torrents', value: '3/24', kind: 'text' }], items: [{ label: 'ubuntu-24.04.1-desktop-amd64.iso', sub: '68%', state: 'good' }, { label: 'debian-12.7.0-amd64-DVD-1.iso', sub: '31%', state: 'good' }] },
        qui: { gauge: { label: 'Connected', value: 100, max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Instances', value: 2, kind: 'stat' }, { label: 'Connected', value: '2/2', kind: 'text', state: 'good' }], items: [{ label: 'Main', sub: 'qbittorrent:8080', value: 'connected', state: 'good' }, { label: 'Seedbox', sub: 'seedbox:8080', value: 'connected', state: 'good' }], version: '1.14.0' },
        plex: { fields: [{ label: 'Streams', value: 3, kind: 'stat', state: 'good' }], items: [{ label: 'The Shining', sub: 'alex · direct play', state: 'good' }, { label: 'Dune: Part Two', sub: 'sam · transcode', state: 'good' }, { label: 'Severance — S01E03', sub: 'jodie · direct play', state: 'good' }] },
        jellyfin: { fields: [{ label: 'Streams', value: 1, kind: 'stat', state: 'good' }, { label: 'Devices', value: 6, kind: 'stat' }] },
        tautulli: { fields: [{ label: 'Streams', value: 3, kind: 'stat', state: 'good' }, { label: 'Bandwidth', value: '48 Mbps', kind: 'text' }, { label: 'Transcodes', value: 1, kind: 'stat' }], items: [{ label: 'Severance · S01E03', sub: 'alex', at: Date.now() - 2 * 3600e3, state: 'ok' }, { label: 'Dune: Part Two', sub: 'sam', at: Date.now() - 5 * 3600e3, state: 'bad' }, { label: 'The Bear · S03E01', sub: 'jodie', at: Date.now() - 9 * 3600e3, state: 'ok' }, { label: 'Shōgun · S01E10', sub: 'you', at: Date.now() - 26 * 3600e3, state: 'ok' }], problems: [{ label: 'Dune: Part Two', sub: 'sam · transcode', at: Date.now() - 5 * 3600e3 }] },
        proxmox: { gauge: { label: 'CPU', value: Math.max(0, Math.round(dwave(11000, 12, 24))), max: 100, unit: '%', state: 'good' }, fields: [{ label: 'VMs/LXC', value: '11/12', kind: 'text', state: 'warn' }, { label: 'Nodes', value: '3/3', kind: 'text' }, { label: 'Memory', value: '61%', kind: 'text' }] },
        adguard: { gauge: { label: 'Blocked', value: 18, max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Queries', value: 84213, kind: 'stat' }, { label: 'Blocked', value: 15380, kind: 'stat', state: 'warn' }, { label: 'Protection', value: 'On', kind: 'text', state: 'good' }] },
        prometheus: { gauge: { label: 'Targets up', value: 96, max: 100, unit: '%', state: 'warn' }, fields: [{ label: 'Targets', value: '24/25', kind: 'text', state: 'warn' }] },
        tailscale: { fields: [{ label: 'Devices', value: 4, kind: 'stat' }, { label: 'Online', value: 3, kind: 'stat', state: 'good' }], items: [{ label: 'homeserver', sub: '100.64.0.1 · linux', value: 'online', state: 'good' }, { label: 'macbook', sub: '100.64.0.2 · macOS', value: 'online', state: 'good' }, { label: 'pixel-8', sub: '100.64.0.3 · android', value: 'online', state: 'good' }, { label: 'old-nas', sub: '100.64.0.4 · linux', value: 'offline', state: 'idle' }], tailscale: { devices: [{ name: 'homeserver', ip: '100.64.0.1', os: 'linux', online: true, lastSeen: new Date().toISOString(), update: false }, { name: 'macbook', ip: '100.64.0.2', os: 'macOS', online: true, lastSeen: new Date().toISOString(), update: false }, { name: 'pixel-8', ip: '100.64.0.3', os: 'android', online: true, lastSeen: new Date().toISOString(), update: true }, { name: 'old-nas', ip: '100.64.0.4', os: 'linux', online: false, lastSeen: new Date(Date.now() - 3 * 86400e3).toISOString(), update: false }] } },
        immich: { fields: [{ label: 'Photos', value: 48210, kind: 'stat' }, { label: 'Videos', value: 3120, kind: 'stat' }, { label: 'Users', value: 4, kind: 'stat' }] },
        droppedneedle: {
            fields: [
                { label: 'Backend', value: 'Online', kind: 'text', state: 'good' },
                { label: 'Artists', value: 214, kind: 'stat' },
                { label: 'Albums', value: 1893, kind: 'stat' },
                { label: 'Pending requests', value: 2, kind: 'stat', state: 'warn' },
                { label: 'Listening now', value: 2, kind: 'stat', state: 'good' },
                { label: 'Downloading', value: 1, kind: 'stat', state: 'good' },
                { label: 'slskd', value: 'Connected', kind: 'text', state: 'good' }
            ],
            items: [],
            dn: {
                ok: true, user: 'demo', role: 'admin', pending: 2,
                nowPlaying: [
                    { track: 'The Less I Know the Better', artist: 'Tame Impala', album: 'Currents', user: 'you', device: 'Web', paused: false, source: 'navidrome', cover: null, progress: Math.round(dwave(9000, 8, 48)) },
                    { track: 'Self Care', artist: 'Mac Miller', album: 'Swimming', user: 'sam', device: 'Web', paused: true, source: 'jellyfin', cover: null, progress: 71 }
                ],
                downloads: [
                    { id: 'demo-dl-1', album: 'In These Parts', artist: 'Tom MacDonald', status: 'downloading', progress: Math.round(dwave(6000, 8, 68)), files: '1/1', error: null },
                    { id: 'demo-dl-2', album: 'Heavydirtysoul', artist: 'twenty one pilots', status: 'partial', progress: 100, files: '1/5', error: '4 files failed' },
                    { id: 'demo-dl-3', album: 'Bandito', artist: 'twenty one pilots', status: 'failed', progress: 0, files: '0/12', error: 'no source found' }
                ],
                dlCounts: { downloading: 1, queued: 0, problems: 2 },
                releases: [
                    { title: 'Tomorrow’s Boxes', artist: 'Thom Yorke', date: '2026-07-02', type: 'Album', mbid: null },
                    { title: 'New Single', artist: 'Followed Artist', date: '2026-07-06', type: 'Single', mbid: null }
                ],
                stats: { artists: 214, albums: 1893, tracks: 24107, size: 372e9, unmatched: 12 },
                recentlyAdded: [
                    { title: 'Swimming', artist: 'Mac Miller', mbid: null, cover: null, year: 2018 },
                    { title: 'Currents', artist: 'Tame Impala', mbid: null, cover: null, year: 2015 }
                ],
                client: true, integrations: null, base: ''
            }
        }
    };
    const w = W[type];
    if (!w) return { ok: false, error: 'demo: no synthetic data for ' + type };
    return Object.assign({ ok: true }, w);
}
async function demoRoute(req, res) {
    const send = obj => { res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
    const u = req.url.split('?')[0];
    if (u === '/api/status') { send({ services: demoStatus(), timestamp: Date.now() }); return true; }
    if (u === '/api/unifi/status') { send(demoUnifi()); return true; }
    if (u === '/api/containers/summary') { send(demoContainers()); return true; }
    if (u === '/api/docker/containers') { send({ configured: true, containers: demoDockerContainers() }); return true; }
    if (u === '/api/docker/logs') { send({ logs: demoDockerLogs() }); return true; }
    if (u === '/api/widget' && req.method === 'POST') {
        const body = await readJsonBody(req).catch(() => ({}));
        const w = demoWidget(body && body.type);
        if (body && body.test) { send({ type: body && body.type, ok: w.ok !== false, sample: { demo: true } }); return true; }
        send(Object.assign({ type: body && body.type }, w, { updatedAt: Date.now() })); return true;
    }
    if (u === '/api/integration/action' && req.method === 'POST') {
        const body = await readJsonBody(req).catch(() => ({}));
        send({ type: body && body.type, ok: true, status: 200, demo: true }); return true;
    }
    if (u === '/api/dn/action' && req.method === 'POST') {
        await readJsonBody(req).catch(() => ({}));
        send({ ok: true, status: 'queued', demo: true }); return true;
    }
    if (u === '/api/dn/stream' && (req.method === 'GET' || req.method === 'HEAD')) {
        const buf = demoSilentWav();
        res.writeHead(200, { 'Content-Type': 'audio/wav', 'Accept-Ranges': 'bytes', 'Content-Length': buf.length, 'Cache-Control': 'no-store' });
        if (req.method === 'HEAD') { res.end(); return true; }
        res.end(buf); return true;
    }
    if (u === '/api/dn/query' && req.method === 'POST') {
        const body = await readJsonBody(req).catch(() => ({}));
        const what = body && body.what;
        if (what === 'search') {
            send({ ok: true, artists: [{ title: 'Tame Impala', mbid: null, inLibrary: true }, { title: 'Mac Miller', mbid: null, inLibrary: false }], albums: [
                { title: 'Currents', artist: 'Tame Impala', year: 2015, mbid: '00000000-0000-4000-8000-000000000001', inLibrary: true, requested: false, cover: null },
                { title: 'Swimming', artist: 'Mac Miller', year: 2018, mbid: '00000000-0000-4000-8000-000000000002', inLibrary: false, requested: false, cover: null },
                { title: 'Circles', artist: 'Mac Miller', year: 2020, mbid: '00000000-0000-4000-8000-000000000003', inLibrary: false, requested: true, cover: null }
            ] }); return true;
        }
        if (what === 'requests') { send({ ok: true, active: [{ album: 'Swimming', artist: 'Mac Miller', status: 'downloading', progress: 42, by: 'you' }], history: [{ album: 'Currents', artist: 'Tame Impala', status: 'completed', by: 'you' }], total: 1 }); return true; }
        if (what === 'downloads') { send({ ok: true, counts: { downloading: 1, queued: 0, problems: 2, done: 23 }, items: [{ id: 'demo-dl-1', album: 'In These Parts', artist: 'Tom MacDonald', status: 'downloading', progress: 64, files: '1/1' }, { id: 'demo-dl-2', album: 'Heavydirtysoul', artist: 'twenty one pilots', status: 'partial', progress: 100, files: '1/5', error: '4 files failed' }, { id: 'demo-dl-3', album: 'Bandito', artist: 'twenty one pilots', status: 'failed', progress: 0, files: '0/12', error: 'no source found' }] }); return true; }
        if (what === 'play-album') {
            const s = n => '/api/dn/stream?u=' + encodeURIComponent('/api/v1/stream/local/demo' + n);
            send({ ok: true, album: String(body.album || 'Currents'), cover: null, queue: [
                { title: 'Let It Happen', artist: 'Tame Impala', album: 'Currents', duration: 30, source: 'local', src: s(1) },
                { title: 'The Less I Know the Better', artist: 'Tame Impala', album: 'Currents', duration: 30, source: 'local', src: s(2) },
                { title: 'Eventually', artist: 'Tame Impala', album: 'Currents', duration: 30, source: 'local', src: s(3) }
            ] }); return true;
        }
        if (what === 'playlists') {
            send({ ok: true, playlists: [
                { id: '00000000-0000-4000-9000-000000000001', name: 'Your Weekly Mix', count: 57, duration: 12960, cover: null, isOwner: true, owner: 'You', isPublic: false, redacted: false },
                { id: '00000000-0000-4000-9000-000000000002', name: 'Focus', count: 24, duration: 5400, cover: null, isOwner: true, owner: 'You', isPublic: true, redacted: false },
                { id: '00000000-0000-4000-9000-000000000003', name: 'Road Trip', count: 40, duration: 9600, cover: null, isOwner: false, owner: 'Alexander', isPublic: true, redacted: false },
                { id: '00000000-0000-4000-9000-000000000004', name: 'Late Night', count: 31, duration: 7200, cover: null, isOwner: false, owner: 'Sam', isPublic: true, redacted: false }
            ] }); return true;
        }
        if (what === 'play-playlist') {
            const s = n => '/api/dn/stream?u=' + encodeURIComponent('/api/v1/stream/local/demo' + n);
            send({ ok: true, album: String(body.name || 'Your Weekly Mix'), cover: null, queue: [
                { title: 'Dress', artist: 'Taylor Swift', album: 'reputation', duration: 30, source: 'local', cover: null, src: s(1) },
                { title: 'Nikes', artist: 'Frank Ocean', album: 'Blonde', duration: 30, source: 'local', cover: null, src: s(2) },
                { title: 'Redbone', artist: 'Childish Gambino', album: 'Awaken, My Love!', duration: 30, source: 'local', cover: null, src: s(3) }
            ] }); return true;
        }
        send({ ok: true, items: [] }); return true;
    }
    if (u === '/api/live' && req.method === 'POST') {
        const body = await readJsonBody(req).catch(() => ({}));
        const svc = body && body.service;
        if (svc === 'Node Exporter') { send({ raw: demoHostProm() }); return true; }
        if (svc === 'Tracearr') { send(demoTracearr()); return true; }
        if (svc === 'TrueNAS Web UI') { send({ pools: [{ name: 'tank', used: 32400000000000, size: 40000000000000, usedPct: 81, status: 'ONLINE', healthy: true }], configured: true }); return true; }
        send({ error: 'demo: provider not simulated' }); return true;
    }
    if (u === '/api/stream') {
        // Minimal SSE in demo: one status frame so the Live badge lights up.
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive' });
        res.write('retry: 3000\n\n');
        const push = () => { try { res.write(`event: status\ndata: ${JSON.stringify({ services: demoStatus(), ts: Date.now() })}\n\n`); res.write(`event: media\ndata: ${JSON.stringify({ body: demoTracearr(), ts: Date.now() })}\n\n`); } catch (e) {} };
        push();
        const iv = setInterval(push, 5000);
        req.on('close', () => clearInterval(iv));
        return true;
    }
    return false;   // everything else (settings, static UI, meta) uses the real handler
}

const LOG_REQUESTS = /^(1|true|on|yes)$/i.test((process.env.LOG_REQUESTS || '').trim());
const server = http.createServer(async (req, res) => {
    // Opt-in access log (LOG_REQUESTS=1): one line per request — method, path,
    // status, timing, whether a session cookie rode along, and whether the
    // response issued one. Enough to watch a login/session problem unfold request
    // by request (e.g. `POST /api/login -> 200 set-cookie=yes` then a bounced
    // `GET /api/status -> 401 cc_session=sent` means the browser kept the old cookie).
    if (LOG_REQUESTS) {
        const _t0 = Date.now();
        res.on('finish', () => {
            try {
                const sent = parseCookies(req).cc_session ? 'sent' : 'none';
                const set = res.getHeader('Set-Cookie') ? ' set-cookie=yes' : '';
                const extra = req._logExtra ? ` (${req._logExtra})` : '';   // e.g. which provider a /api/live or /api/widget call was for
                console.log(`[req] ${req.method} ${req.url}${extra} -> ${res.statusCode} ${Date.now() - _t0}ms cc_session=${sent}${set}`);
            } catch (e) {}
        });
    }
    // ── gate 1: rate limit (loopback exempt so local tooling can't lock itself out) ──
    const clientIp = (req.socket && req.socket.remoteAddress) || '';
    if (!/^(::1$|127\.|::ffff:127\.)/.test(clientIp) && rateLimited(clientIp)) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '10' });
        res.end(JSON.stringify({ error: 'rate limited' }));
        return;
    }
    // ── gate 2: cross-origin state-changing requests are rejected (CSRF defense) ──
    const origin = req.headers.origin || '';
    const host = req.headers.host || '';
    const clientIsLoopback = /^(::1$|127\.|::ffff:127\.)/.test(clientIp);
    const originOk = o => o === `http://${host}` || o === `https://${host}` || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(o);
    const sameOrigin = origin ? originOk(origin) : true;
    // CSRF: reject cross-origin POSTs. A POST with NEITHER Origin NOR a same-origin
    // Referer is only trusted from loopback (local tooling) — a browser always sends
    // at least one, so this closes the missing-Origin bypass. The session cookie is
    // also SameSite=Strict, so a cross-site request can't carry a session regardless.
    if (req.method === 'POST') {
        const referer = req.headers.referer || '';
        const refererOk = referer && (() => { try { return originOk(new URL(referer).origin); } catch (e) { return false; } })();
        const trusted = origin ? originOk(origin) : (refererOk || clientIsLoopback);
        if (!trusted) {
            auditLog(req, 'csrf.reject', req.url, 'blocked');
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'cross-origin request rejected' }));
            return;
        }
    }
    // ── gate 3: optional password gate (env DASHBOARD_PASSWORD or a setup password) ──
    if (authEnabled()) {
        if (req.url === '/api/login' && req.method === 'POST') {
            const body = await readJsonBody(req).catch(() => ({}));
            const pw = (body && body.password) || '';
            const target = authTarget();
            const ok = verifyPassword(pw, target);
            auditLog(req, 'auth.login', '', ok ? 'ok' : 'denied');
            console.log(`[auth] login ${ok ? 'OK' : 'DENIED'} — source=${_envAuthTarget ? 'env DASHBOARD_PASSWORD' : 'password set in UI'}, scheme=${reqScheme(req)} (x-forwarded-proto=${req.headers['x-forwarded-proto'] || 'none'}), host=${reqHost(req)}, issuing cookie Secure=${cookieSecure(req) ? 'yes' : 'no'}`);
            if (!ok) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid password' })); return; }
            // Transparently upgrade a legacy sha256 vault hash to scrypt on success.
            if (!_envAuthTarget && /^[0-9a-f]{64}$/i.test(String(target))) { try { setVaultAuthPassword(pw); } catch (e) {} }
            issueSession(req, res);
            return;
        }
        if (req.url === '/api/logout' && req.method === 'POST') {
            // Stateless tokens can't be revoked server-side; clearing the cookie
            // logs this browser out (the token self-expires at its 12h TTL).
            auditLog(req, 'auth.logout', '', 'ok');
            res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `cc_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` });
            res.end(JSON.stringify({ ok: true }));
            return;
        }
        // Endpoints reachable WITHOUT a session even when auth is on:
        //   /api/login (above), /api/stream handshake, /api/meta (liveness).
        const open = req.url === '/api/stream' || req.url === '/api/meta';
        if (req.url.startsWith('/api/') && !open && !hasSession(req)) {
            log401(req.url, !!parseCookies(req).cc_session);
            // WWW-Authenticate marks this as a SESSION 401. Provider proxies
            // (/api/live, /api/widget) relay upstream 401s without it — the client
            // only shows the lock screen when this header is present, so a
            // misconfigured provider can no longer masquerade as a logged-out user.
            res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': 'CC-Session' });
            res.end(JSON.stringify({ error: 'authentication required', login: '/api/login' }));
            return;
        }
    }
    // ── first-run setup: set (or clear) the optional dashboard password ──
    // Open while no auth exists yet (first run); requires a session once auth is on.
    if (req.url === '/api/setup/password' && req.method === 'POST') {
        if (authEnabled() && !hasSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': 'CC-Session' }); res.end(JSON.stringify({ error: 'authentication required' })); return; }
        if (authPasswordFromEnv()) { res.writeHead(409, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'password is managed by DASHBOARD_PASSWORD in the environment' })); return; }
        const body = await readJsonBody(req).catch(() => ({}));
        const pw = String((body && body.password) || '');
        if (pw && pw.length < 12) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'password must be at least 12 characters' })); return; }
        setVaultAuthPassword(pw || '');
        auditLog(req, 'auth.set-password', '', pw ? 'set' : 'cleared');
        if (pw) { issueSession(req, res, { enabled: true }); return; }   // issue a fresh session token for the new password
        res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true, enabled: false }));
        return;
    }

    // ── demo mode: synthetic data endpoints, real handler for everything else ──
    if (DEMO) { try { if (await demoRoute(req, res)) return; } catch (e) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'demo: ' + e.message })); return; } }

    // Same-origin by default. Only echo trusted local origins for browser tooling.
    if (sameOrigin) {
        if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }

    // Transparent gzip for large text/JSON responses (e.g. the ~500KB Node
    // Exporter /metrics payload). Buffers headers until end so we can add
    // Content-Encoding; skips streamed (res.write) and binary responses.
    if (/\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
        const rawWriteHead = res.writeHead.bind(res), rawEnd = res.end.bind(res), rawWrite = res.write.bind(res);
        let hStatus = 200, hHeaders = {}, flushed = false, streaming = false;
        const flush = () => { if (!flushed) { flushed = true; rawWriteHead(hStatus, hHeaders); } };
        res.writeHead = (code, headers) => { if (!flushed) { hStatus = code; if (headers) for (const k in headers) hHeaders[k] = headers[k]; } return res; };
        res.write = (chunk, enc) => { streaming = true; flush(); return rawWrite(chunk, enc); };
        res.end = (body, enc) => {
            if (!streaming && !flushed && typeof body === 'string' && body.length > 1400) {
                const ct = String(hHeaders['Content-Type'] || hHeaders['content-type'] || 'text/html');
                if (!/image|octet-stream|font|zip/i.test(ct)) {
                    try { const gz = zlib.gzipSync(body); hHeaders['Content-Encoding'] = 'gzip'; hHeaders['Content-Length'] = gz.length; flush(); return rawEnd(gz, enc); } catch (e) { }
                }
            }
            flush();
            return rawEnd(body, enc);
        };
    }

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (req.url === '/' || req.url === '/index.html') {
        // The GAUGE UI is the dashboard, served with CSP + hardening headers.
        fs.readFile(path.join(__dirname, 'app.html'), (err, data) => {
            if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('app.html not found'); return; }
            res.writeHead(200, Object.assign({ 'Content-Type': 'text/html', 'Cache-Control': 'no-cache, no-store, must-revalidate', 'Pragma': 'no-cache', 'Expires': '0' }, securityHeaders(req)));
            res.end(injectDashboardSettings(data.toString('utf8')));
        });
    } else if (['/v2', '/v2.html', '/app-v2.html', '/app', '/app.html', '/classic', '/classic.html'].includes(req.url)) {
        // Every old surface URL collapses to the one canonical dashboard.
        res.writeHead(302, { 'Location': '/' });
        res.end();
    } else if (req.url.startsWith('/icons/') && req.method === 'GET') {
        // Self-hosted dashboard-icons: served from the local cache so page paint never
        // waits on a CDN. On a cache miss the ONE icon is fetched from jsDelivr (fixed
        // host, sanitized slug — no caller-controlled URLs), written to disk, served.
        const im = /^\/icons\/([a-z0-9-]{1,60})\.svg$/.exec(req.url);
        if (!im) { res.writeHead(400, { 'Content-Type': 'text/plain' }); res.end('bad icon path'); return; }
        const iconFile = path.join(ICON_DIR, im[1] + '.svg');
        fs.readFile(iconFile, (err, data) => {
            if (!err) { res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=604800, immutable' }); res.end(data); return; }
            fetchTextUrl(`https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/${im[1]}.svg`).then(svg => {
                // Accept an optional XML prolog / doctype / comments before <svg>
                // (many icons ship a "<?xml …?>" header) — but stay anchored so an
                // error page that merely contains <svg> somewhere can't slip through.
                if (!/^\s*(?:<\?xml[^>]*\?>\s*|<!doctype[^>]*>\s*|<!--[\s\S]*?-->\s*)*<svg[\s>]/i.test(svg)) throw new Error('not an svg');
                try { fs.mkdirSync(ICON_DIR, { recursive: true }); fs.writeFileSync(iconFile, svg); } catch (e) { /* cache best-effort */ }
                res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=604800, immutable' });
                res.end(svg);
            }).catch(() => { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('icon not found'); });
        });
    } else if (req.url.startsWith('/fonts/') && req.method === 'GET') {
        // Self-hosted webfonts — no fonts.googleapis.com on the critical path.
        const fm = /^\/fonts\/([A-Za-z0-9._-]{1,80}\.woff2)$/.exec(req.url);
        if (!fm) { res.writeHead(400, { 'Content-Type': 'text/plain' }); res.end('bad font path'); return; }
        fs.readFile(path.join(FONT_DIR, fm[1]), (err, data) => {
            if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('font not found'); return; }
            res.writeHead(200, { 'Content-Type': 'font/woff2', 'Cache-Control': 'public, max-age=2592000, immutable' });
            res.end(data);
        });
    } else if ((req.url === '/manifest.webmanifest' || req.url === '/manifest.json') && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/manifest+json', 'Cache-Control': 'public, max-age=3600' });
        res.end(CC_MANIFEST);
    } else if (req.url === '/icon.svg' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=604800' });
        res.end(CC_ICON_SVG);
    } else if (req.url === '/sw.js' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/' });
        res.end(CC_SW);
    } else if ((req.url === '/icon-192.png' || req.url === '/icon-512.png' || req.url === '/icon-maskable.png' || req.url === '/apple-touch-icon.png') && req.method === 'GET') {
        try {
            const key = req.url === '/icon-512.png' ? '512' : req.url === '/icon-maskable.png' ? 'maskable' : req.url === '/apple-touch-icon.png' ? 'apple' : '192';
            const png = ccIcon(key);
            res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800, immutable' });
            res.end(png);
        } catch (e) { res.writeHead(500, { 'Content-Type': 'text/plain' }); res.end('icon error'); }
    } else if (req.url === '/api/meta') {
        // Live system metadata for Settings → About / Automation / intelligence.
        // Everything here is measured, not configured — no fabricated values.
        let iconCount = 0, auditBytes = 0;
        try { iconCount = fs.readdirSync(ICON_DIR).filter(f => /\.(svg|png)$/.test(f)).length; } catch (e) {}
        try { auditBytes = fs.statSync(AUDIT_PATH).size; } catch (e) {}
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({
            version: APP_VERSION, startedAt: SERVER_STARTED_AT,
            uptimeSec: Math.round((Date.now() - SERVER_STARTED_AT) / 1000),
            node: process.version, platform: process.platform, pid: process.pid, port: PORT,
            authEnabled: authEnabled(), authFromEnv: authPasswordFromEnv(),
            insecureTls: ALLOW_INSECURE_TLS,
            sse: { clients: sse.clients.size, samplersActive: !!sse.timers },
            catalog: Object.keys(INTEGRATIONS).length,
            services: visibleServices().length,
            iconCache: iconCount, auditLogBytes: auditBytes,
            statusCacheAge: _statusCache.at ? Date.now() - _statusCache.at : null
        }));
    } else if (req.url.startsWith('/api/audit') && req.method === 'GET') {
        // Audit journal viewer: tail of the append-only JSONL (~64KB window), newest first.
        try {
            const q = new URL(req.url, 'http://x').searchParams;
            const limit = Math.min(300, Math.max(1, Number(q.get('limit')) || 100));
            let entries = [];
            try {
                const st = fs.statSync(AUDIT_PATH);
                const start = Math.max(0, st.size - 65536);
                const fd = fs.openSync(AUDIT_PATH, 'r');
                const buf = Buffer.alloc(st.size - start);
                fs.readSync(fd, buf, 0, buf.length, start);
                fs.closeSync(fd);
                entries = buf.toString('utf8').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
            } catch (e) { /* no journal yet — empty is honest */ }
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify({ entries: entries.slice(-limit).reverse(), total: entries.length }));
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ entries: [], error: e.message }));
        }
    } else if (req.url === '/api/settings/full' && req.method === 'GET') {
        // Full backup — includes decrypted secrets. Auth-gated like every /api
        // route (gate 3 above already 401s an unauthenticated caller).
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(fullDashboardSettings()));
    } else if (req.url === '/api/settings' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(redactDashboardSettings(readDashboardSettings())));
    } else if (req.url === '/api/settings' && req.method === 'POST') {
        try {
            const payload = await readJsonBody(req);
            if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid settings payload' }));
                return;
            }
            writeDashboardSettings(mergeSensitiveSettings(payload, readDashboardSettings()));
            _widgetCache.clear(); _statusCache.at = 0;   // config changed — next poll is fresh
            auditLog(req, 'settings.save', Object.keys(payload).join(','), 'ok');
            // If UniFi settings changed, drop the cached login session so the next
            // status fetch re-authenticates with the new URL / username / password.
            if (payload && payload.unifi && typeof payload.unifi === 'object') {
                _unifiCookies = ''; _unifiCookieAt = 0; _unifiLastGood = null; _unifiLastGoodAt = 0;
            }
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify({ ok: true }));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message || 'Failed to save settings' }));
        }
    } else if (req.url === '/api/discover' && req.method === 'POST') {
        // Active service discovery: TCP-probe ONE host across every port the
        // catalog knows, so whatever answers becomes a one-click add with its
        // URL prefilled. LAN-only by design — the target must resolve to a
        // private/loopback address (this is a homelab finder, not a scanner).
        try {
            const body = await readJsonBody(req).catch(() => ({}));
            const host = String((body && body.host) || '').trim();
            if (!host || !/^[a-z0-9_.\-]+$/i.test(host)) { jsonRes(res, 400, { error: 'give a host or IP to scan' }); return; }
            let ip = host;
            if (!net.isIP(host)) {
                try { ip = (await require('dns').promises.lookup(host)).address; }
                catch (e) { jsonRes(res, 400, { error: `cannot resolve ${host}` }); return; }
            }
            const zone = ipZone(ip);
            if (zone !== 'private' && zone !== 'loopback') { jsonRes(res, 400, { error: 'discovery is limited to private LAN addresses' }); return; }
            // Candidate ports: every catalog integration with a port in its default
            // URL, plus the native providers. Shared ports list every possibility —
            // the user picks (e.g. 8096 could be Emby or Jellyfin).
            const candidates = new Map();
            const addCand = (port, scheme, c) => { const k = Number(port); if (!k) return; if (!candidates.has(k)) candidates.set(k, { scheme, list: [] }); candidates.get(k).list.push(c); };
            for (const def of Object.values(INTEGRATIONS)) {
                try {
                    const u = new URL(def.defaultUrl);
                    if (!u.port) continue;
                    if (!isPrivateHostname(u.hostname) && u.hostname !== 'localhost') continue;   // hosted APIs aren't scannable
                    addCand(u.port, u.protocol.replace(':', ''), { id: def.id, title: def.title, kind: 'integration' });
                } catch (e) {}
            }
            addCand(30316, 'http',  { id: 'tracearr', title: 'Tracearr',      kind: 'native' });
            addCand(9100,  'http',  { id: 'nodeexp',  title: 'Node Exporter', kind: 'native' });
            addCand(8089,  'http',  { id: 'cadvisor', title: 'cAdvisor',      kind: 'native' });
            addCand(2375,  'http',  { id: 'docker',   title: 'Docker API',    kind: 'native' });
            addCand(443,   'https', { id: 'truenasscale', title: 'TrueNAS SCALE', kind: 'integration' });
            const ports = [...candidates.keys()];
            const openPorts = [];
            const CHUNK = 16;
            for (let i = 0; i < ports.length; i += CHUNK) {
                const hits = await Promise.all(ports.slice(i, i + CHUNK).map(p => new Promise(ok => {
                    const sock = net.connect({ host: ip, port: p, timeout: 900 });
                    sock.on('connect', () => { sock.destroy(); ok(p); });
                    sock.on('timeout', () => { sock.destroy(); ok(null); });
                    sock.on('error', () => ok(null));
                })));
                hits.forEach(p => { if (p) openPorts.push(p); });
            }
            const found = [];
            for (const p of openPorts.sort((a, b) => a - b)) {
                const { scheme, list } = candidates.get(p);
                for (const c of list) found.push(Object.assign({}, c, { port: p, url: `${scheme}://${host}${(scheme === 'https' && p === 443) ? '' : ':' + p}` }));
            }
            auditLog(req, 'discover.scan', host, `${found.length} found`);
            jsonRes(res, 200, { host, scanned: ports.length, found });
        } catch (err) { jsonRes(res, 500, { error: err.message }); }
    } else if (req.url === '/api/factory-reset' && req.method === 'POST') {
        // Wipe ALL persisted state (settings, encrypted vault + its key, audit
        // journal) and exit — the supervisor (docker restart: unless-stopped /
        // systemd) brings the process back to a pristine first-run. Session- and
        // CSRF-gated like every POST; the body must confirm intent explicitly.
        const body = await readJsonBody(req).catch(() => ({}));
        if (!body || body.confirm !== 'ERASE') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'confirmation missing' }));
            return;
        }
        auditLog(req, 'factory.reset', '', 'ok');
        console.log('[reset] factory reset requested — wiping data and restarting');
        for (const p of [SETTINGS_PATH, SECRETS_PATH, SECRET_KEY_PATH, AUDIT_PATH]) {
            try { fs.unlinkSync(p); } catch (e) { /* absent is fine */ }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, restarting: true }));
        setTimeout(() => process.exit(0), 400);   // supervisor restarts a clean instance
    } else if (req.url === '/api/unifi/status') {
        try {
            const out = await queryUnifiStatus();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(out));
        } catch (err) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ configured: true, ok: false, error: err.message || 'UniFi status unavailable', alerts: ['UniFi status unavailable.'] }));
        }
    } else if (req.url === '/api/unifi/led' && req.method === 'POST') {
        // Device control (LED override / flash-to-locate). Off unless the user opted in.
        const settings = readDashboardSettings();
        if (settings.unifiControl !== true) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'Device control is off. Enable it on the Networking page.' })); return; }
        const uni = storedUnifiSettings();
        if (!uni.url) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'UniFi is not configured.' })); return; }
        if (!uni.username || !uni.password) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: "LED and locate control need username & password auth — the API key uses UniFi's Integration API, which can't control LEDs." })); return; }
        const payload = await readJsonBody(req);
        const action = String(payload.action || '');
        const cmd = { action };
        if (action === 'locate') {
            cmd.mac = String(payload.mac || '');
            cmd.on = payload.on !== false;
            if (!/^[0-9a-f:]{12,17}$/i.test(cmd.mac)) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid mac' })); return; }
        } else if (action === 'led') {
            cmd.id = String(payload.id || '');
            if (payload.mode) cmd.mode = ['on', 'off', 'default'].includes(String(payload.mode)) ? String(payload.mode) : 'default';
            if (payload.color && /^#[0-9a-f]{6}$/i.test(String(payload.color))) cmd.color = String(payload.color);
            if (payload.brightness != null) cmd.brightness = Math.max(0, Math.min(100, Math.round(Number(payload.brightness)) || 0));
            if (!cmd.id) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid device id' })); return; }
            if (!cmd.mode && !cmd.color && cmd.brightness == null) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'nothing to change' })); return; }
        } else if (action === 'restart') {
            cmd.mac = String(payload.mac || '');
            if (!/^[0-9a-f:]{12,17}$/i.test(cmd.mac)) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid mac' })); return; }
            if (payload.confirm !== true) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'restart needs confirmation' })); return; }
        } else if (action === 'client') {
            cmd.mac = String(payload.mac || '');
            cmd.op = ['block', 'unblock', 'kick', 'forget'].includes(String(payload.op)) ? String(payload.op) : '';
            if (!/^[0-9a-f:]{12,17}$/i.test(cmd.mac)) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid mac' })); return; }
            if (!cmd.op) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid client op' })); return; }
            if ((cmd.op === 'block' || cmd.op === 'forget') && payload.confirm !== true) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'this action needs confirmation' })); return; }
        } else { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'unknown action' })); return; }
        try {
            const r = await unifiControlCmd(uni, cmd);
            auditLog(req, 'unifi.' + action, cmd.mac || cmd.id || '', r.ok ? 'ok' : 'failed');
            if (r.ok) { _unifiLastGoodAt = 0; }   // force a fresh status fetch so the new LED state shows
            res.writeHead(r.ok ? 200 : 502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(r));
        } catch (err) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: err.message || 'command failed' }));
        }
    } else if (req.url === '/api/docker/containers') {
        const host = getDockerHost();
        if (!host) { res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ configured: false })); return; }
        const nowTs = Date.now();
        if (_dockerList.body && _dockerList.host === host && (nowTs - _dockerList.at) < 12000) {
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(_dockerList.body); return;
        }
        if (!_dockerList.inflight || _dockerList.host !== host) {
            _dockerList.host = host;
            _dockerList.inflight = dockerListContainers(host).then(containers => {
                _dockerList.body = JSON.stringify({ configured: true, containers });
                _dockerList.at = Date.now();
                _dockerList.inflight = null;
                return _dockerList.body;
            }).catch(err => { _dockerList.inflight = null; throw err; });
        }
        try {
            const body = await _dockerList.inflight || _dockerList.body;
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(body);
        } catch (err) {
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify({ configured: true, error: err.message || 'Docker API unreachable' }));
        }
    } else if (req.url === '/api/docker/action' && req.method === 'POST') {
        const host = getDockerHost();
        const payload = await readJsonBody(req);
        const id = String(payload.id || '');
        const action = String(payload.action || '');
        if (!host) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'Docker host not configured (Settings → Docker host).' })); return; }
        if (!['start', 'stop', 'restart'].includes(action) || !id) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'Invalid container action' })); return; }
        try {
            const r = await dockerRequest('POST', `/containers/${encodeURIComponent(id)}/${action}`, host);
            const ok = (r.status >= 200 && r.status < 300) || r.status === 304;
            // Bust the container-list cache so the client's ~1s confirmation
            // refetch reflects the new state instead of a stale pre-action body.
            if (ok) { _dockerList.body = null; _dockerList.at = 0; _dockerList.inflight = null; _dockerList.host = ''; }
            auditLog(req, 'docker.' + action, id, ok ? 'ok' : 'failed');
            res.writeHead(ok ? 200 : 502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok, status: r.status, error: ok ? undefined : ((r.body && r.body.message) || ('Docker HTTP ' + r.status)) }));
        } catch (err) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: err.message || 'Docker action failed' }));
        }
    } else if (req.url.startsWith('/api/docker/logs')) {
        const host = getDockerHost();
        const parsed = new URL(req.url, 'http://127.0.0.1');
        const id = parsed.searchParams.get('id') || '';
        const tail = Math.min(800, Number(parsed.searchParams.get('tail')) || 200);
        if (!host) { res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ configured: false })); return; }
        if (!id) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'container id required' })); return; }
        try {
            const r = await dockerRequest('GET', `/containers/${encodeURIComponent(id)}/logs?stdout=1&stderr=1&tail=${tail}`, host);
            const ok = r.status >= 200 && r.status < 300;
            res.writeHead(ok ? 200 : 502, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify(ok ? { logs: stripDockerFrames(r.raw || '') } : { error: 'Docker HTTP ' + r.status }));
        } catch (err) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message || 'log fetch failed' }));
        }
    } else if (req.url.startsWith('/api/unifi/device-image')) {
        try {
            const parsed = new URL(req.url, 'http://127.0.0.1');
            const url = await resolveUnifiImage(parsed.searchParams.get('model') || '');
            if (!url) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('no image'); return; }
            res.writeHead(302, { 'Location': url, 'Cache-Control': 'public, max-age=86400' });
            res.end();
        } catch (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('device image error');
        }
    } else if (req.url === '/api/stream') {
        // SSE realtime: status/host/media channels. The gate above already applied
        // rate-limiting + (opt-in) auth, same as every other /api route.
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        });
        res.write('retry: 3000\n\n');   // EventSource reconnect hint
        const client = { res };
        sse.clients.add(client);
        sseStart();   // idempotent; samplers only run while ≥1 client is connected
        // Replay the latest snapshot per channel so a new client is instantly current.
        for (const ev of ['status', 'host', 'media']) if (sse.last[ev]) sseSend(client, ev, sse.last[ev]);
        req.on('close', () => { sse.clients.delete(client); if (!sse.clients.size) sseStop(); });
    } else if (req.url === '/api/containers/summary') {
        // Server-parsed cAdvisor summary (single-flight, 15s TTL — under the 20s
        // route tick; cAdvisor's own scrape is CPU-heavy, so don't hammer it).
        // Errors return 200 + {error} so the client renders an honest empty state.
        const nowTs = Date.now();
        if (_ctrSummary.body && (nowTs - _ctrSummary.at) < 15000) {
            res.writeHead(200, { 'Content-Type': 'application/json', 'X-Status-Cache': 'hit' });
            res.end(_ctrSummary.body);
            return;
        }
        if (!_ctrSummary.inflight) {
            _ctrSummary.inflight = queryContainerSummary().then(out => {
                _ctrSummary.body = JSON.stringify(out);
                _ctrSummary.at = Date.now();
                _ctrSummary.inflight = null;
                return _ctrSummary.body;
            }).catch(err => { _ctrSummary.inflight = null; throw err; });
        }
        try {
            const body = await _ctrSummary.inflight || _ctrSummary.body;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(body);
        } catch (err) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ list: [], count: 0, error: err.message || 'cAdvisor unreachable' }));
        }
    } else if (req.url === '/api/status') {
        // Short-TTL cache with single-flight: N tabs share ONE probe sweep instead of
        // N × 25 TCP connects. 8s TTL is under the 20s poll so data stays fresh.
        const nowTs = Date.now();
        if (_statusCache.body && (nowTs - _statusCache.at) < 8000) {
            res.writeHead(200, { 'Content-Type': 'application/json', 'X-Status-Cache': 'hit' });
            res.end(_statusCache.body);
            return;
        }
        if (!_statusCache.inflight) {
            _statusCache.inflight = (async () => {
                const serviceList = visibleServices();
                const results = await Promise.all(serviceList.map(async (svc) => ({ ...svc, ...(await checkPort(svc.host, svc.port)) })));
                _statusCache.body = JSON.stringify({ services: results, timestamp: Date.now() });
                _statusCache.at = Date.now();
                _statusCache.inflight = null;
                return _statusCache.body;
            })().catch(err => { _statusCache.inflight = null; throw err; });
        }
        try {
            const body = await _statusCache.inflight || _statusCache.body;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(body);
        } catch (err) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ services: [], error: err.message || 'status sweep failed', timestamp: Date.now() }));
        }
    } else if (req.url === '/api/tracearr/discover') {
        // Try to discover Tracearr API endpoints — at the ADDRESS the user gave
        // the Tracearr service (Fleet & probes / endpoints), never a loopback default.
        const TRACEARR_BASE = serviceProbeBase('Tracearr');
        if (!TRACEARR_BASE) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ configured: false, error: 'Tracearr has no address — open its card in Settings → Providers and set the URL' }));
            return;
        }
        const pathsToTry = [
            '/api-docs',
            '/api-docs/swagger.json',
            '/swagger.json',
            '/api/swagger.json',
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/sessions',
            '/api/sessions/active',
            '/api/v1/sessions',
            '/api/v1/sessions/active',
            '/api/status',
            '/api/health'
        ];
        
        const results = [];
        let completed = 0;
        
        pathsToTry.forEach(path => {
            const url = `${TRACEARR_BASE}${path}`;
            try {
                const proxyReq = require(TRACEARR_BASE.startsWith('https:') ? 'https' : 'http').get(url, {
                    headers: { 'Accept': 'application/json' },
                    timeout: 5000
                }, (proxyRes) => {
                    results.push({ path, status: proxyRes.statusCode, url });
                    completed++;
                    if (completed === pathsToTry.length) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ 
                            base: TRACEARR_BASE,
                            results: results.sort((a,b) => a.path.localeCompare(b.path))
                        }));
                    }
                });
                proxyReq.on('error', (err) => {
                    results.push({ path, status: 'error', error: err.message });
                    completed++;
                    if (completed === pathsToTry.length) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ 
                            base: TRACEARR_BASE,
                            results: results.sort((a,b) => a.path.localeCompare(b.path))
                        }));
                    }
                });
                proxyReq.on('timeout', () => {
                    results.push({ path, status: 'timeout' });
                    completed++;
                    if (completed === pathsToTry.length) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ 
                            base: TRACEARR_BASE,
                            results: results.sort((a,b) => a.path.localeCompare(b.path))
                        }));
                    }
                });
            } catch (err) {
                results.push({ path, status: 'error', error: err.message });
                completed++;
            }
        });
    } else if (req.url.startsWith('/api/integrations')) {
        // Catalog metadata for the Settings integration browser — NO secrets.
        const settings = readDashboardSettings();
        const igCfg = settings.integrations || {};
        // One entry per instance: the catalog default (id = type) plus any user-added
        // "type#N" instances. `baseType` selects the definition; `title` carries the
        // per-instance custom name so the provider shows up named accordingly.
        const mk = (id, d) => ({
            id, baseType: d.id, title: (igCfg[id] && igCfg[id].name) || d.title, category: d.category, icon: d.icon || d.id, defaultUrl: d.defaultUrl || '', note: d.note || '',
            authFields: igAuthFields(d.auth), configFields: d.configFields || [],
            // Expose write-actions (metadata only — never how they authenticate) so the
            // provider card can render control buttons.
            actions: (d.actions || []).map(a => ({ id: a.id, label: a.label, confirm: !!a.confirm, danger: !!a.danger, params: a.params || [] })),
            enabled: (DEMO && DEMO_ENABLED.has(id)) || !!(igCfg[id] && igCfg[id].enabled),
            url: (DEMO && DEMO_ENABLED.has(id)) ? (d.defaultUrl || '') : (storedEndpoint(id) || ''),
            // Optional second address (e.g. a public domain via reverse proxy) so the
            // service is reachable from anywhere. Not a secret and not used for the
            // server-side fetch — purely a user-facing link.
            externalUrl: ((settings.endpoints || {})[id] || {}).externalUrl || ''
        });
        const cat = Object.values(INTEGRATIONS).map(d => mk(d.id, d));
        for (const id of Object.keys(igCfg)) { if (id.includes('#') && INTEGRATIONS[baseType(id)]) cat.push(mk(id, INTEGRATIONS[baseType(id)])); }
        jsonRes(res, 200, cat);
    } else if (req.url === '/api/widget' && req.method === 'POST') {
        try {
            const payload = await readJsonBody(req);
            req._logExtra = (payload && payload.type) || '?';   // name the provider in the request log
            const instId = (payload && payload.type) || '';
            const def = integrationDef(instId);   // "sonarr#2" -> the Sonarr definition
            if (!def) { jsonRes(res, 404, { ok: false, error: 'unknown integration' }); return; }
            const settings = readDashboardSettings();
            const cfg = (settings.integrations && settings.integrations[instId]) || {};   // config keyed by instance
            const base = ((storedEndpoint(instId) || cfg.url || def.defaultUrl) || '').replace(/\/+$/, '');
            if (!base) { jsonRes(res, 400, { ok: false, error: 'No URL configured' }); return; }
            // Serve a fresh cached result (skip for an explicit Test).
            const cached = _widgetCache.get(instId);
            if (!payload.test && cached && (Date.now() - cached.at) < (cached.ok ? WIDGET_TTL_OK : WIDGET_TTL_FAIL)) {
                jsonRes(res, cached.ok ? 200 : 502, Object.assign({ type: instId, cached: true }, cached.out, { updatedAt: cached.at }));
                return;
            }
            const cred = integrationCred(instId);
            const out = await runIntegration(def, base, cred, cfg, payload.test);
            if (!payload.test) _widgetCache.set(instId, { at: Date.now(), ok: out.ok !== false, out });
            jsonRes(res, out.ok === false && payload.test ? 200 : (out.ok === false ? 502 : 200), Object.assign({ type: instId }, out, { updatedAt: Date.now() }));
        } catch (e) { jsonRes(res, 500, { ok: false, error: e.message }); }
    } else if (req.url === '/api/integration/action' && req.method === 'POST') {
        // Run a named write-action on an enabled provider. Same auth/CSRF/session
        // gates as every POST route; the action must be declared in the provider's
        // `actions` array (no arbitrary path is ever accepted from the client).
        try {
            const payload = await readJsonBody(req);
            const instId = (payload && payload.type) || '';
            const def = integrationDef(instId);
            if (!def) { jsonRes(res, 404, { ok: false, error: 'unknown integration' }); return; }
            const settings = readDashboardSettings();
            const cfg = (settings.integrations && settings.integrations[instId]) || {};
            if (!(cfg && cfg.enabled)) { jsonRes(res, 400, { ok: false, error: 'provider not enabled' }); return; }
            const base = ((storedEndpoint(instId) || cfg.url || def.defaultUrl) || '').replace(/\/+$/, '');
            if (!base) { jsonRes(res, 400, { ok: false, error: 'No URL configured' }); return; }
            const out = await runIntegrationAction(def, base, integrationCred(instId), cfg, String(payload.action || ''), payload.params || {});
            auditLog(req, 'integration.action', instId + ':' + (payload.action || ''), out.ok ? 'ok' : 'failed');
            jsonRes(res, out.ok ? 200 : (out.status || 502), Object.assign({ type: instId }, out));
        } catch (e) { jsonRes(res, 500, { ok: false, error: e.message }); }
    } else if (req.url.startsWith('/api/dn/img') && req.method === 'GET') {
        // Authenticated image proxy for Dropped Needle cover art — DN's covers need a
        // Bearer token, which never reaches the browser. Path is allowlisted to the
        // covers/thumb endpoints only; bytes stream through with long cache headers.
        try {
            const q = new URL(req.url, 'http://x').searchParams;
            const p = q.get('path') || '';
            if (!/^\/api\/v1\/(covers\/(artist|release-group)\/[0-9a-fA-F-]{8,40}|jellyfin\/image\/[A-Za-z0-9-]{1,64}|plex\/thumb\/[A-Za-z0-9%/-]{1,120})(\?[A-Za-z0-9=&_]{0,60})?$/.test(p)) {
                res.writeHead(400, { 'Content-Type': 'text/plain' }); res.end('bad image path'); return;
            }
            const headers = await dnAuthHeaders();
            const u = new URL(dnBaseUrl() + p);
            const lib2 = u.protocol === 'https:' ? require('https') : require('http');
            const preq = lib2.get(u, { headers, timeout: 12000 }, (pr) => {
                if (pr.statusCode !== 200) { res.writeHead(pr.statusCode === 404 ? 404 : 502, { 'Content-Type': 'text/plain' }); res.end('cover unavailable'); pr.resume(); return; }
                res.writeHead(200, { 'Content-Type': pr.headers['content-type'] || 'image/jpeg', 'Cache-Control': 'public, max-age=86400' });
                pr.pipe(res);
            });
            preq.on('timeout', () => preq.destroy(new Error('timeout')));
            preq.on('error', () => { try { res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('cover fetch failed'); } catch (e) {} });
        } catch (e) { jsonRes(res, 200, { ok: false, error: e.message }); }
    } else if (req.url.startsWith('/api/dn/stream') && (req.method === 'GET' || req.method === 'HEAD')) {
        // Authenticated audio proxy — this is what makes Command Center a Dropped Needle
        // *player*. The browser <audio> streams from here; we attach the vaulted Bearer
        // token (never exposed) and forward the Range header so the browser can seek.
        // Path is allowlisted to DN's /api/v1/stream/* endpoints; bytes pipe straight
        // through and the upstream is dropped the moment the client aborts (skip/seek).
        try {
            const p = new URL(req.url, 'http://x').searchParams.get('u') || '';
            const okPath = /^\/api\/v1\/stream\/(jellyfin|navidrome|local)\/[A-Za-z0-9._~-]{1,128}$/.test(p)
                || /^\/api\/v1\/stream\/plex\/[A-Za-z0-9%._~/-]{1,200}$/.test(p);
            if (!okPath) { res.writeHead(400, { 'Content-Type': 'text/plain' }); res.end('bad stream path'); return; }
            const auth = await dnAuthHeaders();
            const u = new URL(dnBaseUrl() + p);
            const hdrs = { Authorization: auth.Authorization, 'User-Agent': 'command-center/player' };
            if (req.headers.range) hdrs['Range'] = req.headers.range;
            const lib3 = u.protocol === 'https:' ? require('https') : require('http');
            const opts = { method: req.method, headers: hdrs, timeout: 20000 };
            if (u.protocol === 'https:' && tlsRelaxedFor(u)) opts.rejectUnauthorized = false;
            const preq = lib3.request(u, opts, (pr) => {
                if (pr.statusCode >= 400) { res.writeHead(pr.statusCode === 404 ? 404 : pr.statusCode === 416 ? 416 : 502, { 'Content-Type': 'text/plain' }); res.end('stream unavailable'); pr.resume(); return; }
                const h = { 'Content-Type': pr.headers['content-type'] || 'audio/mpeg', 'Accept-Ranges': pr.headers['accept-ranges'] || 'bytes', 'Cache-Control': 'no-store' };
                if (pr.headers['content-length']) h['Content-Length'] = pr.headers['content-length'];
                if (pr.headers['content-range']) h['Content-Range'] = pr.headers['content-range'];
                res.writeHead(pr.statusCode, h);
                if (req.method === 'HEAD') { res.end(); pr.resume(); return; }
                pr.pipe(res);
            });
            preq.on('timeout', () => preq.destroy(new Error('timeout')));
            preq.on('error', () => { try { res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('stream fetch failed'); } catch (e) {} });
            req.on('close', () => preq.destroy());   // client aborted (skip / seek) — drop upstream
            preq.end();
        } catch (e) { try { res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('stream error'); } catch (_) {} }
    } else if (req.url === '/api/dn/query' && req.method === 'POST') {
        // In-dashboard Dropped Needle data: a strict allowlist of read-only queries the
        // Media lane renders inline (search / requests / downloads / releases) — the
        // vaulted session token stays server-side.
        try {
            const payload = await readJsonBody(req);
            const what = String(payload && payload.what || '');
            const headers = await dnAuthHeaders();
            const base = dnBaseUrl();
            const get = async p => { const r = await igFetch(base + p, { headers }); if (r.status === 401) throw new Error('session expired — sign in with Plex again in Settings'); if (r.status < 200 || r.status >= 300) throw new Error((r.body && r.body.error && r.body.error.message) || ('HTTP ' + r.status)); return r.body || {}; };
            const coverRef = (x) => x.cover_url ? (String(x.cover_url).startsWith('http') ? x.cover_url : '/api/dn/img?path=' + encodeURIComponent(x.cover_url)) : (x.musicbrainz_id ? '/api/dn/img?path=' + encodeURIComponent('/api/v1/covers/release-group/' + x.musicbrainz_id + '?size=250') : null);
            if (what === 'search') {
                const q = String(payload.q || '').slice(0, 120);
                if (!q) { jsonRes(res, 200, { ok: false, error: 'empty query' }); return; }
                const r = await get('/api/v1/search?q=' + encodeURIComponent(q) + '&limit_artists=6&limit_albums=18');
                const slim = x => ({ title: x.title, artist: x.artist, mbid: x.musicbrainz_id, year: x.year, inLibrary: !!x.in_library, requested: !!x.requested, cover: coverRef(x), type: x.type_info || x.type || null });
                jsonRes(res, 200, { ok: true, artists: (r.artists || []).map(slim), albums: (r.albums || []).map(slim) });
            } else if (what === 'requests') {
                const [act, hist] = await Promise.all([get('/api/v1/requests/active'), get('/api/v1/requests/history?page=1&page_size=10&sort=newest').catch(() => ({ items: [] }))]);
                const slimA = x => ({ album: x.album_title, artist: x.artist_name, status: x.status, progress: x.progress, eta: x.eta, by: x.requested_by_name, error: x.error_message, cover: coverRef(x) });
                const slimH = x => ({ album: x.album_title, artist: x.artist_name, status: x.status, at: x.completed_at || x.requested_at, by: x.requested_by_name, inLibrary: !!x.in_library });
                jsonRes(res, 200, { ok: true, active: (act.items || []).map(slimA), history: (hist.items || []).map(slimH), total: act.count || 0 });
            } else if (what === 'downloads') {
                const r = await get('/api/v1/downloads?page=1&page_size=100&sortKey=date&sortDirection=descending');
                const all = r.items || [];
                const st = s => String(s || '').toLowerCase();
                const counts = { downloading: 0, queued: 0, problems: 0, done: 0 };
                all.forEach(d => { const s = st(d.status); if (/^(downloading|snatching|grabbing)$/.test(s)) counts.downloading++; else if (/^(queued|searching|pending|scheduled|retrying)$/.test(s)) counts.queued++; else if (/^(partial|failed|error)$/.test(s)) counts.problems++; else counts.done++; });
                const items = all.filter(d => !/^(completed|imported|cancelled|canceled)$/.test(st(d.status))).slice(0, 60).map(d => ({ id: d.id, album: d.album_title, artist: d.artist_name, track: d.track_title, status: d.status, progress: d.progress_percent, files: d.files_total ? d.files_completed + '/' + d.files_total : null, error: d.error_message, source: d.source }));
                jsonRes(res, 200, { ok: true, items, counts });
            } else if (what === 'releases') {
                const r = await get('/api/v1/following/new-releases?limit=24&offset=0');
                jsonRes(res, 200, { ok: true, items: (r.items || []).map(x => ({ title: x.title, artist: x.artist_name, date: x.first_release_date, type: x.primary_type, mbid: x.release_group_mbid, cover: coverRef({ musicbrainz_id: x.release_group_mbid }) })) });
            } else if (what === 'play-album') {
                // Build a playable queue for a LIBRARY album: fetch its tracks, resolve each
                // to a concrete stream (source + id), and hand back proxied URLs the browser
                // can play directly. Only downloaded music resolves — the rest is skipped.
                const mbid = String(payload.mbid || '').trim();
                if (!/^[0-9a-fA-F-]{8,40}$/.test(mbid)) { jsonRes(res, 200, { ok: false, error: 'invalid album id' }); return; }
                const at = await get('/api/v1/library/albums/' + mbid + '/tracks');
                const tracks = Array.isArray(at.items) ? at.items : [];
                if (!tracks.length) { jsonRes(res, 200, { ok: false, error: 'no tracks in your library for this album' }); return; }
                const rr = await igFetch(base + '/api/v1/library/resolve-tracks', { method: 'POST', headers, body: { items: tracks.map(t => ({ release_group_mbid: mbid, disc_number: t.disc_number || 1, track_number: t.track_number })) } });
                const resolved = (rr.body && Array.isArray(rr.body.items)) ? rr.body.items : [];
                const keyOf = x => (x.disc_number || 1) + ':' + x.track_number;
                const rmap = {}; resolved.forEach(x => { rmap[keyOf(x)] = x; });
                const queue = tracks.map(t => {
                    const rv = rmap[keyOf(t)] || {};
                    const path = (rv.stream_url && /^\/api\/v1\/stream\//.test(rv.stream_url)) ? rv.stream_url : (rv.source && rv.track_source_id ? '/api/v1/stream/' + rv.source + '/' + rv.track_source_id : null);
                    return path ? {
                        title: t.track_title || ('Track ' + t.track_number), artist: t.artist_name || '',
                        album: String(payload.album || ''), duration: t.duration_seconds || rv.duration || null,
                        source: rv.source || 'local', src: '/api/dn/stream?u=' + encodeURIComponent(path)
                    } : null;
                }).filter(Boolean);
                if (!queue.length) { jsonRes(res, 200, { ok: false, error: 'these tracks aren\'t streamable yet — still downloading?' }); return; }
                jsonRes(res, 200, { ok: true, queue, album: String(payload.album || ''), cover: payload.cover || null });
            } else if (what === 'playlists') {
                // Your playlists + others' public ones (DN scopes this to what you may see).
                // Each carries is_owner / owner_name so the client can offer a "whose" filter.
                const r = await get('/api/v1/playlists');
                const arr = Array.isArray(r.playlists) ? r.playlists : (Array.isArray(r) ? r : []);
                jsonRes(res, 200, { ok: true, playlists: arr.map(pl => ({
                    id: pl.id, name: pl.name || 'Playlist', count: pl.track_count || 0, duration: pl.total_duration || null,
                    cover: (Array.isArray(pl.cover_urls) && pl.cover_urls[0]) ? coverRef({ cover_url: pl.cover_urls[0] }) : (pl.custom_cover_url ? coverRef({ cover_url: pl.custom_cover_url }) : null),
                    isOwner: !!pl.is_owner, owner: pl.is_owner ? 'You' : (pl.owner_name || 'Shared'), isPublic: !!pl.is_public, redacted: !!pl.is_redacted
                })) });
            } else if (what === 'play-playlist') {
                // Playlist detail tracks already carry source_type + track_source_id, so we can
                // build the stream queue straight away (no resolve step). Unplayable/redacted skip.
                const id = String(payload.id || '').trim();
                if (!/^[0-9a-fA-F-]{8,40}$/.test(id)) { jsonRes(res, 200, { ok: false, error: 'invalid playlist id' }); return; }
                const d = await get('/api/v1/playlists/' + id);
                const tracks = Array.isArray(d.tracks) ? d.tracks : [];
                if (!tracks.length) { jsonRes(res, 200, { ok: false, error: d.is_redacted ? 'this playlist is private' : 'playlist has no tracks' }); return; }
                const queue = tracks.map(t => {
                    const src = String(t.source_type || '').toLowerCase();
                    if (!t.track_source_id || !/^(local|navidrome|jellyfin|plex)$/.test(src)) return null;
                    const path = '/api/v1/stream/' + src + '/' + t.track_source_id;
                    return { title: t.track_name || 'Track', artist: t.artist_name || '', album: t.album_name || '', duration: t.duration || null, source: src, cover: t.cover_url ? coverRef({ cover_url: t.cover_url }) : null, src: '/api/dn/stream?u=' + encodeURIComponent(path) };
                }).filter(Boolean);
                if (!queue.length) { jsonRes(res, 200, { ok: false, error: 'no streamable tracks in this playlist' }); return; }
                jsonRes(res, 200, { ok: true, queue, album: String(d.name || payload.name || 'Playlist'), cover: payload.cover || ((Array.isArray(d.cover_urls) && d.cover_urls[0]) ? coverRef({ cover_url: d.cover_urls[0] }) : null) });
            } else jsonRes(res, 400, { ok: false, error: 'unknown query' });
        } catch (e) { jsonRes(res, 200, { ok: false, error: e.message }); }
    } else if (req.url === '/api/dn/plex/pin' && req.method === 'POST') {
        // Start Dropped Needle's own "Sign in with Plex" flow: DN mints a Plex PIN and
        // hands back the plex.tv approval URL. Nothing is authorized until the user
        // approves it in their own Plex account.
        try {
            await readJsonBody(req);
            const base = (storedEndpoint('droppedneedle') || INTEGRATIONS.droppedneedle.defaultUrl).replace(/\/+$/, '');
            const r = await igFetch(base + '/api/v1/auth/plex/pin', { method: 'POST', body: {} });
            if (r.status >= 200 && r.status < 300 && r.body && r.body.auth_url) jsonRes(res, 200, { ok: true, pin_id: r.body.pin_id, auth_url: r.body.auth_url });
            else jsonRes(res, 200, { ok: false, error: (r.body && r.body.error && r.body.error.message) || r.error || ('HTTP ' + r.status) });
        } catch (e) { jsonRes(res, 500, { ok: false, error: e.message }); }
    } else if (req.url === '/api/dn/plex/poll' && req.method === 'POST') {
        // Poll DN for the PIN result; on success the DN session token goes straight
        // into the encrypted vault (apiKeys.droppedneedle.sessionToken) — it never
        // reaches the browser.
        try {
            const payload = await readJsonBody(req);
            const pinId = Number(payload && payload.pin_id);
            if (!pinId) { jsonRes(res, 400, { ok: false, error: 'missing pin_id' }); return; }
            const base = (storedEndpoint('droppedneedle') || INTEGRATIONS.droppedneedle.defaultUrl).replace(/\/+$/, '');
            const r = await igFetch(base + '/api/v1/auth/plex/poll?pin_id=' + encodeURIComponent(pinId), {});
            if (r.status < 200 || r.status >= 300) { jsonRes(res, 200, { ok: false, error: (r.body && r.body.error && r.body.error.message) || r.error || ('HTTP ' + r.status) }); return; }
            const b = r.body || {};
            if (!b.completed) { jsonRes(res, 200, { ok: false, completed: false }); return; }
            if (!b.token) { jsonRes(res, 200, { ok: false, completed: true, error: 'Plex approved but Dropped Needle returned no session token' }); return; }
            const vault = readSecretVault();
            putSecret(vault, 'apiKeys.droppedneedle', 'sessionToken', String(b.token));
            writeSecretVault(vault);
            auditLog(req, 'droppedneedle.plexlogin', b.user && b.user.display_name, 'ok');
            jsonRes(res, 200, { ok: true, completed: true, user: (b.user && (b.user.display_name || b.user.username)) || 'Plex user' });
        } catch (e) { jsonRes(res, 500, { ok: false, error: e.message }); }
    } else if (req.url === '/api/dn/action' && req.method === 'POST') {
        // Control Dropped Needle from the dashboard — request music without opening the
        // app. Server-side only: the vaulted session token never reaches the browser and
        // every action is audited. (DN's player transport — play / pause / skip / seek —
        // is a client-side heartbeat with no server API, so there is nothing to proxy.)
        try {
            const payload = await readJsonBody(req);
            const action = String(payload && payload.action || '');
            const headers = await dnAuthHeaders();               // Bearer <vaulted token>
            const base = dnBaseUrl();
            const mbid = String(payload && payload.mbid || '').trim();
            const validMbid = /^[0-9a-fA-F-]{8,40}$/.test(mbid);
            let r, label = '';
            if (action === 'request-album') {
                if (!validMbid) { jsonRes(res, 400, { ok: false, error: 'a release-group MusicBrainz ID is required' }); return; }
                label = String(payload.album || mbid);
                r = await igFetch(base + '/api/v1/requests/new', { method: 'POST', headers, body: {
                    musicbrainz_id: mbid,
                    artist: payload.artist || undefined,
                    album: payload.album || undefined,
                    year: (payload.year != null && payload.year !== '') ? (Number(payload.year) || undefined) : undefined,
                    artist_mbid: payload.artistMbid || undefined,
                    monitor_artist: false, auto_download_artist: false
                } });
            } else if (action === 'request-track') {
                if (!validMbid) { jsonRes(res, 400, { ok: false, error: 'a recording MusicBrainz ID is required' }); return; }
                label = String(payload.track || mbid);
                r = await igFetch(base + '/api/v1/tracks/' + encodeURIComponent(mbid) + '/request', { method: 'POST', headers, body: {
                    artist_name: payload.artist || undefined,
                    track_title: payload.track || undefined,
                    album_title: payload.album || undefined,
                    release_group_mbid: payload.rgMbid || undefined,
                    artist_mbid: payload.artistMbid || undefined
                } });
            } else if (action === 'report-nowplaying') {
                // Reflect the dashboard's own playback in DN's now-playing broadcast (so it
                // appears in the floor and to other DN users). Best-effort, not audited —
                // this fires on every play/pause/heartbeat and must never break playback.
                const rp = await igFetch(base + '/api/v1/now-playing', { method: 'POST', headers, body: {
                    device: 'command-center', source: payload.source || 'local',
                    track_name: payload.track || undefined, artist_name: payload.artist || undefined,
                    album_name: payload.album || undefined, cover_url: payload.cover || undefined,
                    is_paused: !!payload.paused,
                    progress_ms: payload.progressMs != null ? Math.round(Number(payload.progressMs) || 0) : undefined,
                    duration_ms: payload.durationMs != null ? Math.round(Number(payload.durationMs) || 0) : undefined
                } });
                jsonRes(res, 200, { ok: rp.status >= 200 && rp.status < 300 }); return;
            } else if (action === 'clear-nowplaying') {
                const rc = await igFetch(base + '/api/v1/now-playing?device=command-center', { method: 'DELETE', headers });
                jsonRes(res, 200, { ok: rc.status >= 200 && rc.status < 300 }); return;
            } else if (action === 'download-cancel' || action === 'download-retry') {
                // Cancel or retry a single download task, straight from the dashboard.
                const tid = String(payload.taskId || '').trim();
                if (!/^[A-Za-z0-9_-]{6,64}$/.test(tid)) { jsonRes(res, 400, { ok: false, error: 'invalid task id' }); return; }
                const rr = await igFetch(base + '/api/v1/downloads/' + encodeURIComponent(tid) + (action === 'download-retry' ? '/retry' : '/cancel'), { method: 'POST', headers });
                const okk = rr.status >= 200 && rr.status < 300;
                auditLog(req, 'droppedneedle.' + action, tid, okk ? 'ok' : 'failed');
                jsonRes(res, 200, { ok: okk, error: okk ? null : ((rr.body && rr.body.error && rr.body.error.message) || ('HTTP ' + rr.status)) }); return;
            } else if (action === 'downloads-clear' || action === 'downloads-retry-failed' || action === 'downloads-stop-retries') {
                // Bulk maintenance on the queue: clear finished, retry all failed, stop auto-retries.
                const map = { 'downloads-clear': '/api/v1/downloads/clear', 'downloads-retry-failed': '/api/v1/downloads/retry-all-failed', 'downloads-stop-retries': '/api/v1/downloads/stop-all-retries' };
                const rr = await igFetch(base + map[action], { method: 'POST', headers });
                const okk = rr.status >= 200 && rr.status < 300;
                const b = rr.body || {};
                auditLog(req, 'droppedneedle.' + action, '', okk ? 'ok' : 'failed');
                jsonRes(res, 200, { ok: okk, count: (b.cleared != null ? b.cleared : (b.retried != null ? b.retried : (b.stopped != null ? b.stopped : null))), error: okk ? null : ('HTTP ' + rr.status) }); return;
            } else { jsonRes(res, 400, { ok: false, error: 'unknown action' }); return; }
            const ok = r.status >= 200 && r.status < 300;
            auditLog(req, 'droppedneedle.' + action, label, ok ? 'ok' : 'failed');
            if (r.status === 401) { jsonRes(res, 200, { ok: false, error: 'session expired — sign in with Plex again in Settings' }); return; }
            const b = r.body || {};
            const status = ok ? String(b.status || b.state || 'queued') : null;
            const err = ok ? null : ((b.error && b.error.message) || (typeof b.detail === 'string' ? b.detail : null) || r.error || ('HTTP ' + r.status));
            jsonRes(res, 200, { ok, status, error: err });
        } catch (e) { jsonRes(res, 200, { ok: false, error: e.message }); }
    } else if (req.url === '/api/customwidget' && req.method === 'POST') {
        // Generic "custom API" escape-hatch tile: fetch a user-defined JSON URL and
        // extract dot-path fields. Config (incl. optional header) lives in settings.
        try {
            const payload = await readJsonBody(req);
            const settings = readDashboardSettings();
            const tiles = Array.isArray(settings.customTiles) ? settings.customTiles : [];
            const tile = tiles.find(t => t.id === (payload && payload.id));
            if (!tile || tile.type !== 'customapi') { jsonRes(res, 404, { ok: false, error: 'unknown tile' }); return; }
            // Custom-tile proxy: resolve + reject loopback (Docker socket / own admin
            // API), link-local/cloud-metadata and unspecified. LAN (private) is allowed —
            // hitting a JSON endpoint on the network is the feature.
            try { await assertFetchTarget(tile.url, { allowLoopback: false, allowPrivate: true }); }
            catch (e) { jsonRes(res, 400, { ok: false, error: 'blocked host: ' + e.message }); return; }
            const headers = {};
            // Header value lives in the encrypted vault (settings only ever hold the
            // sentinel); tolerate a not-yet-migrated plaintext value as fallback.
            const headerVal = ((readSecretVault().customTiles || {})[String(tile.id)])
                || ((tile.headerVal && !isSecretPlaceholder(tile.headerVal)) ? tile.headerVal : '');
            if (tile.headerName && headerVal) headers[tile.headerName] = headerVal;
            const r = await igFetch(tile.url, { headers, insecure: !!tile.allowInsecure });
            if (r.status < 200 || r.status >= 300) { jsonRes(res, 200, { ok: false, error: r.error || ('HTTP ' + r.status) }); return; }
            const dig = (obj, path) => { let v = obj; (path || '').split('.').filter(Boolean).forEach(k => { v = (v == null) ? v : v[/^\d+$/.test(k) ? Number(k) : k]; }); return v; };
            const fields = (Array.isArray(tile.mappings) ? tile.mappings : []).map(m => { const v = dig(r.body, m.path); return { label: m.label || m.path, value: (v == null || typeof v === 'object') ? '—' : v, kind: m.kind || 'text' }; });
            jsonRes(res, 200, { ok: true, fields, updatedAt: Date.now() });
        } catch (e) { jsonRes(res, 500, { ok: false, error: e.message }); }
    } else if (req.url.startsWith('/api/grafana/status')) {
        const base = storedEndpoint('grafana');
        const token = storedCredential('Grafana', 'token');
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ configured: !!(base && token) }));
    } else if (req.url.startsWith('/api/grafana/render')) {
        // Server-side render-proxy: token never reaches the browser; target built
        // only from the admin-set stored base URL + a sanitized uid + allowlisted params.
        const base = storedEndpoint('grafana');
        const token = storedCredential('Grafana', 'token');
        if (!base || !token) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Grafana not configured. Add the URL and a service-account token in Settings.' })); return; }
        const q = new URL(req.url, 'http://127.0.0.1').searchParams;
        const uid = (q.get('uid') || '').replace(/[^a-zA-Z0-9_-]/g, '');
        const slug = (q.get('slug') || 'd').replace(/[^a-zA-Z0-9_-]/g, '') || 'd';
        if (!uid) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'missing panel uid' })); return; }
        let target;
        try { target = new URL('/render/d-solo/' + uid + '/' + slug, base.replace(/\/+$/, '') + '/'); }
        catch (err) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'invalid Grafana base URL' })); return; }
        const allow = ['panelId', 'from', 'to', 'width', 'height', 'theme', 'orgId', 'tz', 'timezone', 'refresh'];
        allow.forEach(k => { const v = q.get(k); if (v != null && v !== '') target.searchParams.set(k, v); });
        for (const [k, v] of q) { if (k.startsWith('var-')) target.searchParams.set(k, v); }
        if (!target.searchParams.get('panelId')) target.searchParams.set('panelId', '1');
        if (!target.searchParams.get('width')) target.searchParams.set('width', '600');
        if (!target.searchParams.get('height')) target.searchParams.set('height', '280');
        if (!target.searchParams.get('theme')) target.searchParams.set('theme', 'dark');
        if (!target.searchParams.get('from')) target.searchParams.set('from', 'now-6h');
        if (!target.searchParams.get('to')) target.searchParams.set('to', 'now');
        const lib = target.protocol === 'https:' ? require('https') : require('http');
        const opts = { headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'image/png' }, timeout: 25000 };
        if (target.protocol === 'https:') opts.rejectUnauthorized = !tlsRelaxedFor(target);
        const gReq = lib.get(target, opts, (gRes) => {
            if (gRes.statusCode < 200 || gRes.statusCode >= 300) {
                gRes.resume();
                res.writeHead(gRes.statusCode || 502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Grafana render failed', status: gRes.statusCode, hint: gRes.statusCode === 404 ? 'Install the grafana-image-renderer plugin and verify the panel uid/panelId.' : 'Check the Grafana URL, token, and that the service account has Viewer access.' }));
                return;
            }
            res.writeHead(200, { 'Content-Type': gRes.headers['content-type'] || 'image/png', 'Cache-Control': 'private, max-age=20' });
            gRes.pipe(res);
        });
        gReq.on('timeout', () => gReq.destroy(new Error('render timeout')));
        gReq.on('error', (err) => { res.writeHead(502, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Grafana proxy error', message: err.message })); });
    } else if (req.url.startsWith('/api/tracearr-image')) {
        const parsed = new URL(req.url, 'http://127.0.0.1');
        const rawSrc = parsed.searchParams.get('src') || '';
        if (!rawSrc) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'missing src' }));
            return;
        }

        // Resolve against the CONFIGURED Tracearr address; absolute srcs may only
        // point at that same host (the proxy attaches the Tracearr bearer token).
        const trBase = serviceProbeBase('Tracearr');
        if (!trBase) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ configured: false, error: 'Tracearr has no address — add it in Settings → Fleet & probes' }));
            return;
        }
        let target;
        try {
            const baseHost = new URL(trBase).hostname;
            if (/^https?:\/\//i.test(rawSrc)) {
                target = new URL(rawSrc);
                if (target.hostname !== baseHost) throw new Error('blocked external image proxy target');
            } else {
                const rel = rawSrc.startsWith('/') ? rawSrc : `/${rawSrc}`;
                target = new URL(rel, trBase);
            }
        } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid src' }));
            return;
        }

        const lib = target.protocol === 'https:' ? require('https') : require('http');
        const imgReq = lib.get(target, {
            headers: {
                'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                'User-Agent': 'dashboard-server/1.0',
                ...(storedCredential('Tracearr', 'key') && { 'Authorization': `Bearer ${storedCredential('Tracearr', 'key')}` })
            },
            timeout: 10000
        }, (imgRes) => {
            if (imgRes.statusCode < 200 || imgRes.statusCode >= 300) {
                imgRes.resume();
                res.writeHead(imgRes.statusCode || 502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'image fetch failed', status: imgRes.statusCode }));
                return;
            }
            res.writeHead(200, {
                'Content-Type': imgRes.headers['content-type'] || 'image/jpeg',
                'Cache-Control': 'private, max-age=300'
            });
            imgRes.pipe(res);
        });
        imgReq.on('timeout', () => imgReq.destroy(new Error('timeout')));
        imgReq.on('error', (err) => {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'image proxy error', message: err.message }));
        });
    } else if (req.url.startsWith('/api/tracearr/')) {
        // Proxy Tracearr API requests — to the CONFIGURED address only.
        const trProxyBase = serviceProbeBase('Tracearr');
        if (!trProxyBase) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ configured: false, error: 'Tracearr has no address — open its card in Settings → Providers and set the URL' }));
            return;
        }
        const tracearrPath = req.url.replace('/api/tracearr/', '');

        // Tracearr public API lives under /api/v1/public/* and requires Bearer auth.
        // Try the public-v1 prefix first to avoid falling through to legacy /api/* routes.
        const possiblePaths = [
            `/api/v1/public/${tracearrPath}`,
            `/api/${tracearrPath}`,
            `/api/v1/${tracearrPath}`,
            `/${tracearrPath}`,
            `/api/v2/${tracearrPath}`
        ];
        
        let attempts = 0;
        const tryPaths = () => {
            if (attempts >= possiblePaths.length) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    error: 'Tracearr API endpoint not found', 
                    message: 'Tried paths: ' + possiblePaths.join(', '),
                    tried: possiblePaths
                }));
                return;
            }
            
            const path = possiblePaths[attempts];
            const TRACEARR_URL = `${trProxyBase}${path}`;
            attempts++;

            try {
                const proxyReq = require(trProxyBase.startsWith('https:') ? 'https' : 'http').get(TRACEARR_URL, {
                    headers: {
                        'Accept': 'application/json',
                        ...(storedCredential('Tracearr', 'key') && { 'Authorization': `Bearer ${storedCredential('Tracearr', 'key')}` })
                    }
                }, (proxyRes) => {
                    if (proxyRes.statusCode === 404) {
                        tryPaths(); // Try next path
                        return;
                    }
                    
                    // Pass through the response (including 401)
                    let data = '';
                    proxyRes.on('data', chunk => data += chunk);
                    proxyRes.on('end', () => {
                        res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
                        res.end(data);
                    });
                });
                
                proxyReq.on('error', (err) => {
                    if (attempts < possiblePaths.length) {
                        tryPaths();
                    } else {
                        res.writeHead(401, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ 
                            error: 'Authentication failed', 
                            message: 'Invalid API token. Check Tracearr Settings → API Keys.'
                        }));
                    }
                });
            } catch (err) {
                tryPaths(); // Try next path
            }
        };
        
        tryPaths();
    } else if (req.url === '/api/live' && req.method === 'POST') {
        // Live data probe for a service. Body: { service, key? }.
        // SECURITY: fetch targets resolve ONLY from server-side config (storedEndpoint /
        // LIVE_PROBES) — caller-supplied `endpoint`/`custom` were an SSRF + credential-
        // exfiltration pivot (CWE-918) and are no longer honoured.
        const payload = await readJsonBody(req);
        const svc = payload.service;
        req._logExtra = svc || '?';   // name the probed service in the request log
        const key = (!payload.key || isSecretPlaceholder(payload.key)) ? storedCredential(svc, 'key') : payload.key;
        const override = storedEndpoint(svc) || '';
        if (svc === 'Qbt') {
            payload.qbt = {
                ...(payload.qbt || {}),
                username: (!payload.qbt?.username || isSecretPlaceholder(payload.qbt.username)) ? storedCredential('Qbt', 'username') : payload.qbt.username,
                password: (!payload.qbt?.password || isSecretPlaceholder(payload.qbt.password)) ? storedCredential('Qbt', 'password') : payload.qbt.password
            };
        }
        const built = LIVE_PROBES[svc];
        const custom = null;   // caller-supplied probe descriptors removed (SSRF surface)
        if (svc === 'TrueNAS Web UI') {
            const endpoint = serviceProbeBase('TrueNAS Web UI');
            if (!endpoint) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ pools: [], configured: false, error: 'TrueNAS has no address — open its card in Settings → Providers and set the URL' }));
                return;
            }
            try {
                const out = await queryTrueNasPools(key, endpoint);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(out));
            } catch (err) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    pools: [],
                    configured: Boolean(key),
                    error: err.message || 'TrueNAS API error'
                }));
            }
            return;
        }
        const probe = built || (custom ? {
            defaultUrl: custom.defaultUrl,
            authHeader: custom.authHeader,
            path: custom.probePath || '/'
        } : null);
        if (!probe) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unknown service' }));
            return;
        }
        // Probe the address the user configured (endpoints override, else the
        // service's own host/port from Fleet & probes). A loopback default is
        // "not configured", never a probe of the container itself.
        const baseUrl = serviceProbeBase(svc);
        if (!baseUrl) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ configured: false, error: `${svc} has no address — open its card in Settings → Providers and set the URL` }));
            return;
        }
        try {
            if (svc === 'Qbt') {
                const out = await queryQbt(baseUrl, payload.qbt || {});
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(out));
                return;
            }
            if (svc === 'Tracearr') {
                const tracearrResp = await queryTracearr(baseUrl, key, probe);
                res.writeHead(tracearrResp.status, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(tracearrResp.body));
                return;
            }
            // Always do the auth probe first.
            const probeResp = await liveFetch({ baseUrl, path: probe.path, key, probe });
            let out = { ...probeResp.body };
            // Fetch a few additional stats where the service exposes them.
            for (const extra of (probe.extras || [])) {
                try {
                    const r = await liveFetch({ baseUrl, path: extra.path, key, probe });
                    if (r.ok) out[extra.key] = r.body;
                } catch (_) { /* ignore extras; base probe is enough */ }
            }
            res.writeHead(probeResp.status, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(out));
        } catch (err) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message || 'Upstream error' }));
        }
    } else if (req.url === '/api/network' && req.method === 'POST') {
        // SECURITY: target resolves from server config only — no caller-supplied endpoint.
        await readJsonBody(req);
        try {
            const out = await queryNetworkTotal(storedEndpoint('Node Exporter') || '');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(out));
        } catch (err) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message || 'Network metrics unavailable' }));
        }
    } else if (req.url === '/api/health/custom' && req.method === 'POST') {
        const payload = await readJsonBody(req);
        const host = String(payload.host || '').trim();
        const port = Number(payload.port);
        if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'offline', error: 'Invalid host or port' }));
            return;
        }
        // SECURITY: this is a caller-driven port probe — restrict it to the homelab.
        // Resolve the host and require every address to be loopback/LAN; a raw-string
        // pattern let bare labels (via the DNS search domain) and 10.evil.com through.
        let probeIps = [];
        try { const h = host.replace(/^\[|\]$/g, ''); probeIps = net.isIP(h) ? [h] : (await dns.lookup(h, { all: true })).map(a => a.address); } catch (e) { probeIps = []; }
        const zoneOk = probeIps.length > 0 && probeIps.every(ip => ipZone(ip) === 'loopback' || ipZone(ip) === 'private');
        if (!zoneOk) {
            auditLog(req, 'portcheck.reject', host + ':' + port, 'blocked');
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'offline', error: 'Only private/LAN hosts can be probed' }));
            return;
        }
        const result = await checkPort(host, port);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
    } else if (req.url.startsWith('/api/health/')) {
        const serviceName = decodeURIComponent(req.url.replace('/api/health/', ''));
        const service = services.find(s => s.name === serviceName);
        
        if (!service) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Service not found' }));
            return;
        }
        
        try {
            const result = await checkPort(service.host, service.port);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'offline', error: err.message }));
        }
    } else {
        res.writeHead(404);
        res.end('Not found');
    }
});

// Bind the port and start background samplers only when run directly
// (`node server.js`). Requiring this module — e.g. from the smoke-test suite —
// must have no side effects, so the server never binds during tests.
if (require.main === module) {
    server.listen(PORT, '0.0.0.0', () => {
        // Bound to 0.0.0.0 (all interfaces) — reachable via the mapped port and
        // any reverse proxy. Show the real external URL when PUBLIC_URL is set so
        // a container log never looks like it's stuck on localhost.
        console.log(`🐉 Command Center listening on 0.0.0.0:${PORT}${PUBLIC_URL ? ` — ${PUBLIC_URL}` : ` — http://localhost:${PORT}/`}`);
        // Print the access-relevant config so a glance at the logs answers "is
        // sign-in on, and how?" and "what will the session cookie look like?".
        const authMode = _envAuthTarget ? 'ON — env DASHBOARD_PASSWORD' : (storedAuthTarget() ? 'ON — password set in the UI' : 'OFF — no sign-in (open on the network)');
        const cs = String(process.env.COOKIE_SECURE || '').trim() || 'auto (follows request scheme)';
        console.log(`   sign-in: ${authMode}`);
        console.log(`   proxy:   TRUST_PROXY=${TRUST_PROXY ? 'on' : 'off'}  PUBLIC_URL=${PUBLIC_URL || '(none)'}  COOKIE_SECURE=${cs}`);
        console.log(`   logging: request log ${LOG_REQUESTS ? 'ON (LOG_REQUESTS=1) — one [req] line per request' : 'off — set LOG_REQUESTS=1 for a full access log'}`);
        if (_envAuthTarget && !PUBLIC_URL) console.log(`   hint:    behind an https proxy, set PUBLIC_URL so cookies/links match; if sign-in loops, set COOKIE_SECURE=0`);
    });

    // Graceful shutdown. In a container node runs as PID 1, which gets NO default
    // signal handling — without this, `docker stop` waits out its 10s grace period
    // and SIGKILLs (exit 137) on every stop/update. Exit promptly and cleanly.
    for (const sig of ['SIGTERM', 'SIGINT']) {
        process.on(sig, () => {
            console.log(`received ${sig} — shutting down`);
            try { server.close(() => process.exit(0)); } catch (e) { process.exit(0); }
            setTimeout(() => process.exit(0), 3000).unref();   // don't wait on open SSE streams
        });
    }

    // Continuously sample WAN throughput in the background so the dashboard
    // sparkline is already populated on first paint (reuses the cached session).
    setInterval(() => {
        const s = safeUnifiSettings(storedUnifiSettings());
        if (!s.url || !s.username || !s.password) return;
        queryUnifiStatus().catch(() => {});
    }, 8 * 1000).unref();
}

// Pure/utility functions surfaced for the smoke-test suite (test/smoke.test.js).
// Thanks to the require.main guard above, importing this module starts nothing.
module.exports = { INTEGRATIONS, hashPassword, verifyPassword, igApplyTpl, securityHeaders, isSecretPlaceholder, SECRET_SENTINEL, escapeJsonForScript, ipZone, assertFetchTarget, sessionCookie, isSecureRequest, SECRET_FIELDS, signSession, hasSession, serviceProbeBase, isLoopbackUrl, isPrivateHostname, tlsRelaxedFor, describeNetErr, storedCredential, summarizeUnifi, unifiDeviceKind, summarizeUnifiDevice, ccIcon, CC_MANIFEST, CC_SW, CC_ICON_SVG };
