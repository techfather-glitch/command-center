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
const APP_VERSION = '2.0.0-gauge';
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
const SECRET_FIELDS = new Set(['key', 'username', 'password', 'token', 'secret']);
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
        for (const field of ['username', 'password']) {
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
function mergeSensitiveSettings(incoming, existing) {
    const vault = readSecretVault();
    const { clean, vault: nextVault } = pullSecretsIntoVault(incoming, vault);
    writeSecretVault(nextVault);
    return clean;
}
function storedCredential(service, key) {
    const vault = readSecretVault();
    return ((vault[`apiKeys.${service}`] || {})[key]) || '';
}
function storedEndpoint(service) { return ((readDashboardSettings().endpoints || {})[service] || {}).url || ''; }
function storedUnifiSettings() {
    const settings = readDashboardSettings();
    const u = (settings && settings.unifi && typeof settings.unifi === 'object') ? settings.unifi : {};
    const secrets = readSecretVault().unifi || {};
    return { ...u, username: secrets.username || '', password: secrets.password || '' };
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

function unifiRequest(baseUrl, requestPath, { method = 'GET', body = null, cookies = '' } = {}) {
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
        if (payload) headers['Content-Length'] = Buffer.byteLength(payload);
        const options = {
            method,
            headers,
            timeout: 10000,
            ...(target.protocol === 'https:' ? { agent: new (require('https').Agent)({ rejectUnauthorized: !ALLOW_INSECURE_TLS }) } : {})
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
    return {
        url: String(u.url || '').trim().replace(/\/+$/, ''),
        username: String(u.username || '').trim(),
        password: String(u.password || ''),
        site: String(u.site || 'default').trim() || 'default'
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
        mac: d.mac,
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
const _wanHist = [];                        // rolling WAN throughput (bytes/s) for the dashboard sparkline
const WAN_HIST_MAX = 120;
// Only store when the rate actually changes — the controller reports the same
// smoothed value several samples in a row, which would flatten the chart.
function pushWanHist(rate) { const n = Number(rate); if (!isFinite(n)) return; const v = Math.max(0, n); if (_wanHist.length && _wanHist[_wanHist.length - 1] === v) return; _wanHist.push(v); if (_wanHist.length > WAN_HIST_MAX) _wanHist.shift(); }
const UNIFI_COOKIE_TTL = 25 * 60 * 1000;   // reuse a session for 25 minutes
const UNIFI_STALE_OK   = 6 * 60 * 1000;    // serve last-good data up to 6 min during a blip

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
                    if (cookies) return { cookies };
                } else {
                    loginError = typeof resp.body === 'string' ? resp.body : (resp.body?.meta?.msg || resp.body?.error || `login ${resp.status}`);
                }
            } catch (err) { loginError = err.message; }
        }
    }
    return { cookies: '', error: loginError || `UniFi login failed (${loginStatus || 'no response'})` };
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
        for (const p of paths) {
            try {
                const resp = await unifiRequest(settings.url, p, { cookies });
                if (resp.status === 401 || resp.status === 403) { unauthorized = true; continue; }
                if (resp.status >= 200 && resp.status < 300) {
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

async function queryUnifiStatus() {
    const settings = safeUnifiSettings(storedUnifiSettings());
    if (!settings.url || !settings.username || !settings.password) {
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
    try {
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
    return [
        ...services.filter(svc => !hidden.has(svc.name)),
        ...normalizedCustom.filter(svc => !hidden.has(svc.name))
    ];
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
        const req = lib.get(url, { headers, timeout: 8000 }, (r) => {
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
    let firstOk = null;
    let lastResp = null;
    const paths = [probe.path, ...(probe.fallbacks || [])];
    for (const path of paths) {
        const resp = await liveFetch({ baseUrl, path, key, probe });
        lastResp = resp;
        if (resp.ok) {
            const out = {
                status: resp.status,
                ok: true,
                body: {
                    ...resp.body,
                    _tracearrPath: path
                }
            };
            const sessions = Array.isArray(out.body) ? out.body
                : Array.isArray(out.body?.data) ? out.body.data
                : Array.isArray(out.body?.streams) ? out.body.streams
                : Array.isArray(out.body?.sessions) ? out.body.sessions
                : Array.isArray(out.body?.activeSessions) ? out.body.activeSessions
                : Array.isArray(out.body?.active) ? out.body.active
                : Array.isArray(out.body?.items) ? out.body.items
                : Array.isArray(out.body?.records) ? out.body.records
                : [];
            if (sessions.length) return out;
            if (!firstOk) firstOk = out;
            continue;
        }
        if (resp.status === 401 || resp.status === 403) {
            // Tracearr public tokens can access /api/v1/public/* but not the
            // private session fallbacks. If the public endpoint already worked
            // (even with zero active streams), do not report a false auth error.
            if (firstOk) continue;
            return resp;
        }
    }
    if (firstOk) return firstOk;
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
    const baseUrl = (endpoint || probe.defaultUrl).replace(/\/+$/, '');
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
    const baseUrl = (storedEndpoint('cAdvisor') || LIVE_PROBES['cAdvisor'].defaultUrl).replace(/\/+$/, '');
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

function trueNasRpc(apiKey, endpoint, method, params = [], retryPlainWs = true) {
    return new Promise((resolve, reject) => {
        let rpcUrl;
        let plainFallbackUrl = null;
        try {
            const base = new URL(endpoint || LIVE_PROBES['TrueNAS Web UI'].defaultUrl);
            const scheme = base.protocol === 'https:' ? 'wss:' : 'ws:';
            rpcUrl = `${scheme}//${base.host}/api/current`;
            if (scheme === 'wss:') plainFallbackUrl = `ws://${base.hostname}/api/current`;
        } catch (_) {
            reject(new Error('Invalid TrueNAS endpoint'));
            return;
        }
        const ws = new WebSocket(rpcUrl);
        const pending = new Map();
        let nextId = 1;
        const timer = setTimeout(() => {
            try { ws.close(); } catch (_) {}
            reject(new Error('TrueNAS API timeout'));
        }, 10000);

        const call = (rpcMethod, rpcParams = []) => new Promise((res, rej) => {
            const id = nextId++;
            pending.set(id, { res, rej });
            ws.send(JSON.stringify({ jsonrpc: '2.0', id, method: rpcMethod, params: rpcParams }));
        });

        ws.addEventListener('open', async () => {
            try {
                const authed = await call('auth.login_with_api_key', [apiKey]);
                if (!authed) throw new Error('TrueNAS API authentication failed');
                const result = await call(method, params);
                clearTimeout(timer);
                ws.close();
                resolve(result);
            } catch (err) {
                clearTimeout(timer);
                try { ws.close(); } catch (_) {}
                reject(err);
            }
        });
        ws.addEventListener('message', (event) => {
            let msg;
            try { msg = JSON.parse(event.data); } catch (_) { return; }
            if (!pending.has(msg.id)) return;
            const p = pending.get(msg.id);
            pending.delete(msg.id);
            if (msg.error) p.rej(new Error(msg.error.message || 'TrueNAS API error'));
            else p.res(msg.result);
        });
        ws.addEventListener('error', () => {
            clearTimeout(timer);
            if (plainFallbackUrl && retryPlainWs) {
                trueNasRpc(apiKey, plainFallbackUrl, method, params, false).then(resolve, reject);
                return;
            }
            reject(new Error('TrueNAS API connection failed'));
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
        const opts = { method, timeout: 9000, ...(target.protocol === 'https:' ? { agent: new (require('https').Agent)({ rejectUnauthorized: !ALLOW_INSECURE_TLS }) } : {}) };
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
        const opts = { method: opt.method || 'GET', headers: Object.assign({ 'User-Agent': 'dashboard-server/1.0', 'Accept': opt.accept === 'prometheus' ? 'text/plain' : 'application/json' }, opt.headers || {}), timeout: opt.timeout || 12000 };
        if (u.protocol === 'https:' && opt.insecure) opts.rejectUnauthorized = false;
        let body = opt.body; if (body && typeof body !== 'string') { body = JSON.stringify(body); opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json'; }
        const req2 = lib.request(u, opts, (r) => {
            let data = ''; r.on('data', d => { data += d; if (data.length > 4e6) req2.destroy(new Error('too large')); });
            r.on('end', () => { let parsed = data; if (opt.accept !== 'prometheus') { try { parsed = JSON.parse(data); } catch (e) { } } resolve({ status: r.statusCode, body: parsed, raw: data, headers: r.headers || {} }); });
        });
        req2.on('timeout', () => req2.destroy(new Error('timeout')));
        req2.on('error', (err) => resolve({ status: 0, error: err.message }));
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
    adguard: { id: 'adguard', title: 'AdGuard Home', category: 'network', icon: 'adguard-home', defaultUrl: 'http://192.168.1.1:3000', auth: { type: 'basic', userField: 'username', passField: 'password' }, poll: 30, testRequest: 'stats', requests: [{ id: 'stats', path: '/control/stats' }, { id: 'status', path: '/control/status', optional: true }], normalize: (r) => { const s = r.stats || {}; const total = s.num_dns_queries || 0, blocked = s.num_blocked_filtering || 0; return { gauge: { label: 'Blocked', value: total ? Math.round(blocked / total * 100) : 0, max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Queries', value: total, kind: 'stat' }, { label: 'Blocked', value: blocked, kind: 'stat', state: 'warn' }, { label: 'Protection', value: (r.status && r.status.protection_enabled) ? 'On' : 'Off', kind: 'text', state: (r.status && r.status.protection_enabled) ? 'good' : 'bad' }] }; } },
    pihole: { id: 'pihole', title: 'Pi-hole', category: 'network', icon: 'pi-hole', defaultUrl: 'http://192.168.1.1', auth: { type: 'query', name: 'auth', field: 'token' }, poll: 30, testRequest: 'summary', requests: [{ id: 'summary', path: '/admin/api.php?summaryRaw' }], normalize: (r) => { const s = r.summary || {}; return { gauge: { label: 'Blocked', value: Math.round(Number(s.ads_percentage_today) || 0), max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Queries', value: Number(s.dns_queries_today) || 0, kind: 'stat' }, { label: 'Blocked', value: Number(s.ads_blocked_today) || 0, kind: 'stat', state: 'warn' }, { label: 'On lists', value: Number(s.domains_being_blocked) || 0, kind: 'stat' }] }; } },
    proxmox: { id: 'proxmox', title: 'Proxmox VE', category: 'virtualization', icon: 'proxmox', defaultUrl: 'https://192.168.1.10:8006', allowInsecure: true, auth: { type: 'pveToken', userField: 'user', tokenField: 'tokenid', secretField: 'secret' }, poll: 30, testRequest: 'resources', requests: [{ id: 'resources', path: '/api2/json/cluster/resources' }], normalize: (r) => { const d = (r.resources && r.resources.data) || []; const vms = d.filter(x => x.type === 'qemu' || x.type === 'lxc'); const running = vms.filter(x => x.status === 'running').length; const nodes = d.filter(x => x.type === 'node'); const cpu = nodes.reduce((a, n) => a + (n.cpu || 0), 0) / (nodes.length || 1) * 100; const mem = nodes.reduce((a, n) => a + (n.mem || 0), 0), maxmem = nodes.reduce((a, n) => a + (n.maxmem || 0), 0); return { gauge: { label: 'CPU', value: Math.round(cpu), max: 100, unit: '%', state: cpu >= 90 ? 'bad' : cpu >= 75 ? 'warn' : 'good' }, fields: [{ label: 'VMs/LXC', value: running + '/' + vms.length, kind: 'text', state: running === vms.length ? 'good' : 'warn' }, { label: 'Nodes', value: nodes.filter(n => n.status === 'online').length + '/' + nodes.length, kind: 'text' }, { label: 'Memory', value: maxmem ? Math.round(mem / maxmem * 100) + '%' : '—', kind: 'text' }] }; } },
    portainer: { id: 'portainer', title: 'Portainer', category: 'containers', icon: 'portainer', defaultUrl: 'http://192.168.1.10:9000', auth: { type: 'header', name: 'X-API-Key', field: 'key' }, poll: 30, testRequest: 'endpoints', requests: [{ id: 'endpoints', path: '/api/endpoints' }], normalize: (r) => { const eps = Array.isArray(r.endpoints) ? r.endpoints : []; const up = eps.filter(e => e.Status === 1).length; let running = 0, total = 0; eps.forEach(e => { const s = e.Snapshots && e.Snapshots[0]; if (s) { running += s.RunningContainerCount || 0; total += (s.RunningContainerCount || 0) + (s.StoppedContainerCount || 0); } }); return { fields: [{ label: 'Endpoints', value: up + '/' + eps.length, kind: 'text', state: up === eps.length ? 'good' : 'warn' }, { label: 'Containers', value: running + '/' + total, kind: 'text' }, { label: 'Running', value: running, kind: 'stat', state: 'good' }] }; } },
    homeassistant: { id: 'homeassistant', title: 'Home Assistant', category: 'smarthome', icon: 'home-assistant', defaultUrl: 'http://192.168.1.10:8123', auth: { type: 'bearer', field: 'token' }, poll: 30, testRequest: 'config', requests: [{ id: 'config', path: '/api/config' }, { id: 'states', path: '/api/states', optional: true }], normalize: (r) => { const states = Array.isArray(r.states) ? r.states : []; const dom = (s) => String(s.entity_id || '').split('.')[0]; const nm = (s) => (s.attributes && s.attributes.friendly_name) || s.entity_id || ''; const of = (d) => states.filter(s => dom(s) === d); const lights = of('light'); const lightsOn = lights.filter(s => s.state === 'on').length; const switches = of('switch').filter(s => s.state === 'on').length; const climate = of('climate'); const locks = of('lock'); const locked = locks.filter(s => s.state === 'locked').length; const unlocked = locks.filter(s => s.state === 'unlocked'); const covers = of('cover'); const openCovers = covers.filter(s => s.state === 'open'); const personsHome = of('person').filter(s => s.state === 'home').length; const unavailable = states.filter(s => s.state === 'unavailable' || s.state === 'unknown'); const total = states.length; const availPct = total ? Math.round((total - unavailable.length) / total * 100) : 0; const fields = [{ label: 'Lights on', value: lightsOn + '/' + lights.length, kind: 'text', state: lightsOn ? 'good' : 'idle' }, { label: 'Switches on', value: switches, kind: 'stat', state: switches ? 'good' : 'idle' }, { label: 'Climate', value: climate.length, kind: 'stat' }, { label: 'Locks', value: locks.length ? (locked + '/' + locks.length) : '—', kind: 'text', state: unlocked.length ? 'warn' : (locks.length ? 'good' : 'idle') }, { label: 'People home', value: personsHome, kind: 'stat', state: personsHome ? 'good' : 'idle' }, { label: 'Entities', value: total, kind: 'stat' }]; const attn = []; unlocked.slice(0, 4).forEach(s => attn.push({ label: nm(s), sub: 'unlocked', value: 'unlocked', state: 'warn' })); openCovers.slice(0, 4).forEach(s => attn.push({ label: nm(s), sub: 'open', value: 'open', state: 'warn' })); unavailable.slice(0, 6).forEach(s => attn.push({ label: nm(s), sub: dom(s), value: 'unavailable', state: 'bad' })); return { gauge: { label: 'Available', value: availPct, max: 100, unit: '%', state: availPct >= 98 ? 'good' : availPct >= 90 ? 'warn' : 'bad' }, fields, items: attn.slice(0, 8), version: (r.config && r.config.version) || undefined, ok: !!(r.config && r.config.version) || total > 0 }; } },
    ollama: { id: 'ollama', title: 'Ollama', category: 'ai', icon: 'ollama', defaultUrl: 'http://localhost:11434', auth: { type: 'none' }, poll: 30, testRequest: 'tags', requests: [{ id: 'tags', path: '/api/tags' }, { id: 'ps', path: '/api/ps', optional: true }, { id: 'ver', path: '/api/version', optional: true }], normalize: (r) => { const models = (r.tags && Array.isArray(r.tags.models)) ? r.tags.models : []; const loaded = (r.ps && Array.isArray(r.ps.models)) ? r.ps.models : []; const gb = (b) => (Number(b) / 1e9).toFixed(1); const diskBytes = models.reduce((a, m) => a + (Number(m.size) || 0), 0); const vramBytes = loaded.reduce((a, m) => a + (Number(m.size_vram) || 0), 0); const loadedNames = new Set(loaded.map(m => m.name || m.model)); const desc = (m) => { const d = m.details || {}; return [d.parameter_size, d.quantization_level].filter(Boolean).join(' · '); }; const fields = [{ label: 'Models', value: models.length, kind: 'stat' }, { label: 'Loaded', value: loaded.length, kind: 'stat', state: loaded.length ? 'good' : 'idle' }, { label: 'On disk', value: models.length ? gb(diskBytes) + ' GB' : '—', kind: 'text' }]; if (vramBytes) fields.push({ label: 'VRAM in use', value: gb(vramBytes) + ' GB', kind: 'text', state: 'good' }); const src = models.length ? models : loaded; const items = src.slice(0, 6).map(m => { const nm = m.name || m.model || 'model'; const isLoaded = loadedNames.has(nm); return { label: nm, sub: desc(m) || (m.size ? gb(m.size) + ' GB' : ''), value: isLoaded ? 'loaded' : (m.size ? gb(m.size) + ' GB' : ''), state: isLoaded ? 'good' : 'idle' }; }); return { fields, items, version: (r.ver && r.ver.version) || undefined, ok: r.tags !== undefined }; } },
    plex: { id: 'plex', title: 'Plex', category: 'media', icon: 'plex', defaultUrl: 'http://192.168.1.10:32400', auth: { type: 'header', name: 'X-Plex-Token', field: 'token' }, poll: 20, testRequest: 'sessions', requests: [{ id: 'sessions', path: '/status/sessions' }], normalize: (r) => { const mc = r.sessions && r.sessions.MediaContainer; const n = (mc && mc.size) || 0; const items = ((mc && mc.Metadata) || []).slice(0, 5).map(m => ({ label: m.title || m.grandparentTitle || 'stream', sub: (m.User && m.User.title) || '', state: 'good' })); return { fields: [{ label: 'Streams', value: n, kind: 'stat', state: n ? 'good' : 'idle' }], items }; } },
    jellyfin: { id: 'jellyfin', title: 'Jellyfin', category: 'media', icon: 'jellyfin', defaultUrl: 'http://192.168.1.10:8096', auth: { type: 'header', name: 'X-Emby-Token', field: 'key' }, poll: 20, testRequest: 'sessions', requests: [{ id: 'sessions', path: '/Sessions' }, { id: 'counts', path: '/Items/Counts', optional: true }], normalize: (r) => { const ses = Array.isArray(r.sessions) ? r.sessions.filter(s => s.NowPlayingItem) : []; const c = r.counts || {}; return { fields: [{ label: 'Streams', value: ses.length, kind: 'stat', state: ses.length ? 'good' : 'idle' }, { label: 'Movies', value: c.MovieCount || 0, kind: 'stat' }, { label: 'Episodes', value: c.EpisodeCount || 0, kind: 'stat' }], items: ses.slice(0, 5).map(s => ({ label: (s.NowPlayingItem && s.NowPlayingItem.Name) || 'stream', sub: s.UserName || '', state: 'good' })) }; } },
    overseerr: { id: 'overseerr', title: 'Overseerr / Jellyseerr', category: 'media', icon: 'overseerr', defaultUrl: 'http://192.168.1.10:5055', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 60, testRequest: 'count', requests: [{ id: 'count', path: '/api/v1/request/count' }], normalize: (r) => { const c = r.count || {}; return { fields: [{ label: 'Pending', value: c.pending || 0, kind: 'stat', state: (c.pending || 0) > 0 ? 'warn' : 'good' }, { label: 'Approved', value: c.approved || 0, kind: 'stat' }, { label: 'Total', value: c.total || 0, kind: 'stat' }] }; } },
    immich: { id: 'immich', title: 'Immich', category: 'media', icon: 'immich', defaultUrl: 'http://192.168.1.10:2283', auth: { type: 'header', name: 'x-api-key', field: 'key' }, poll: 300, testRequest: 'stats', requests: [{ id: 'stats', path: '/api/server/statistics' }], normalize: (r) => { const s = r.stats || {}; return { fields: [{ label: 'Photos', value: s.photos || 0, kind: 'stat' }, { label: 'Videos', value: s.videos || 0, kind: 'stat' }, { label: 'Usage', value: s.usage || 0, kind: 'bytes' }] }; } },
    tailscale: { id: 'tailscale', title: 'Tailscale', category: 'network', icon: 'tailscale', defaultUrl: 'https://api.tailscale.com', auth: { type: 'bearer', field: 'token' }, poll: 300, testRequest: 'devices', requests: [{ id: 'devices', path: '/api/v2/tailnet/-/devices' }], normalize: (r) => { const d = (r.devices && r.devices.devices) || []; const now = Date.now(); const online = d.filter(x => x.lastSeen && (now - new Date(x.lastSeen).getTime()) < 300000).length; return { fields: [{ label: 'Devices', value: d.length, kind: 'stat' }, { label: 'Online', value: online, kind: 'stat', state: 'good' }] }; } },
    gotify: { id: 'gotify', title: 'Gotify', category: 'notifications', icon: 'gotify', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'header', name: 'X-Gotify-Key', field: 'key' }, poll: 30, testRequest: 'messages', requests: [{ id: 'messages', path: '/message?limit=10' }], normalize: (r) => { const m = (r.messages && r.messages.messages) || []; return { fields: [{ label: 'Messages', value: (r.messages && r.messages.paging && r.messages.paging.size) || m.length, kind: 'stat' }], items: m.slice(0, 5).map(x => ({ label: x.title || 'message', sub: (x.message || '').slice(0, 48), state: (x.priority || 0) >= 6 ? 'bad' : (x.priority || 0) >= 3 ? 'warn' : 'idle' })) }; } },
    healthchecks: { id: 'healthchecks', title: 'Healthchecks', category: 'monitoring', icon: 'healthchecks', defaultUrl: 'https://healthchecks.io', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 60, testRequest: 'checks', requests: [{ id: 'checks', path: '/api/v3/checks/' }], normalize: (r) => { const c = (r.checks && r.checks.checks) || []; const down = c.filter(x => x.status === 'down').length; const grace = c.filter(x => x.status === 'grace').length; return { fields: [{ label: 'Checks', value: c.length, kind: 'stat' }, { label: 'Down', value: down, kind: 'stat', state: down ? 'bad' : 'good' }, { label: 'Grace', value: grace, kind: 'stat', state: grace ? 'warn' : 'good' }] }; } },
    speedtest: { id: 'speedtest', title: 'Speedtest Tracker', category: 'network', icon: 'speedtest-tracker', defaultUrl: 'http://192.168.1.10:8765', auth: { type: 'bearer', field: 'token' }, poll: 600, testRequest: 'latest', requests: [{ id: 'latest', path: '/api/v1/results/latest' }], normalize: (r) => { const d = (r.latest && r.latest.data) || {}; const dl = d.download_bits ? d.download_bits / 1e6 : (d.download ? d.download / 125000 : 0); const ul = d.upload_bits ? d.upload_bits / 1e6 : (d.upload ? d.upload / 125000 : 0); return { fields: [{ label: 'Down', value: Math.round(dl) + ' Mbps', kind: 'text', state: 'good' }, { label: 'Up', value: Math.round(ul) + ' Mbps', kind: 'text' }, { label: 'Ping', value: d.ping != null ? Math.round(d.ping) + ' ms' : '—', kind: 'text' }] }; } },
    glances: { id: 'glances', title: 'Glances', category: 'monitoring', icon: 'glances', defaultUrl: 'http://192.168.1.10:61208', auth: { type: 'none' }, poll: 15, testRequest: 'cpu', requests: [{ id: 'cpu', path: '/api/4/cpu' }, { id: 'mem', path: '/api/4/mem', optional: true }, { id: 'load', path: '/api/4/load', optional: true }], normalize: (r) => { const cpu = (r.cpu && r.cpu.total) || 0; const mem = (r.mem && r.mem.percent) || 0; return { gauge: { label: 'CPU', value: Math.round(cpu), max: 100, unit: '%', state: cpu >= 90 ? 'bad' : cpu >= 75 ? 'warn' : 'good' }, bars: [{ label: 'CPU', value: Math.round(cpu), max: 100, unit: '%' }, { label: 'RAM', value: Math.round(mem), max: 100, unit: '%', state: mem >= 90 ? 'bad' : mem >= 75 ? 'warn' : '' }], fields: [{ label: 'Load', value: (r.load && r.load.min1 != null) ? r.load.min1.toFixed(2) : '—', kind: 'text' }] }; } },
    uptimekuma: { id: 'uptimekuma', title: 'Uptime Kuma', category: 'monitoring', icon: 'uptime-kuma', defaultUrl: 'http://192.168.1.10:3001', auth: { type: 'none' }, poll: 30, testRequest: 'heartbeat', configFields: [{ name: 'slug', label: 'Status-page slug', kind: 'text' }], requests: [{ id: 'heartbeat', path: '/api/status-page/heartbeat/{{cfg.slug}}' }], normalize: (r) => { const hb = (r.heartbeat && r.heartbeat.heartbeatList) || {}; const mons = Object.keys(hb); const down = mons.filter(id => { const l = hb[id]; return l && l.length && l[l.length - 1].status === 0; }).length; return { fields: [{ label: 'Monitors', value: mons.length, kind: 'stat' }, { label: 'Down', value: down, kind: 'stat', state: down ? 'bad' : 'good' }], items: mons.slice(0, 6).map(id => { const l = hb[id]; const last = l && l[l.length - 1]; return { label: 'Monitor ' + id, value: last && last.status === 1 ? 'up' : 'down', state: last && last.status === 1 ? 'good' : 'bad' }; }) }; } },
    prometheus: { id: 'prometheus', title: 'Prometheus', category: 'monitoring', icon: 'prometheus', defaultUrl: 'http://192.168.1.10:9090', auth: { type: 'none' }, poll: 30, testRequest: 'targets', requests: [{ id: 'targets', path: '/api/v1/targets?state=active' }], normalize: (r) => { const t = (r.targets && r.targets.data && r.targets.data.activeTargets) || []; const up = t.filter(x => x.health === 'up').length; return { gauge: { label: 'Targets up', value: t.length ? Math.round(up / t.length * 100) : 0, max: 100, unit: '%', state: up < t.length ? 'warn' : 'good' }, fields: [{ label: 'Targets', value: up + '/' + t.length, kind: 'text', state: up === t.length ? 'good' : 'warn' }] }; } },
    weather: { id: 'weather', title: 'Weather', category: 'feeds', icon: 'openweathermap', defaultUrl: 'https://api.open-meteo.com', auth: { type: 'none' }, poll: 900, configFields: [{ name: 'lat', label: 'Latitude', kind: 'text' }, { name: 'lon', label: 'Longitude', kind: 'text' }], testRequest: 'forecast', requests: [{ id: 'forecast', path: '/v1/forecast?latitude={{cfg.lat}}&longitude={{cfg.lon}}&current=temperature_2m&daily=temperature_2m_max,temperature_2m_min&timezone=auto' }], normalize: (r) => { const c = (r.forecast && r.forecast.current) || {}; const d = (r.forecast && r.forecast.daily) || {}; return { fields: [{ label: 'Now', value: c.temperature_2m != null ? Math.round(c.temperature_2m) + '°' : '—', kind: 'text', state: 'good' }, { label: 'High', value: (d.temperature_2m_max && d.temperature_2m_max[0] != null) ? Math.round(d.temperature_2m_max[0]) + '°' : '—', kind: 'text' }, { label: 'Low', value: (d.temperature_2m_min && d.temperature_2m_min[0] != null) ? Math.round(d.temperature_2m_min[0]) + '°' : '—', kind: 'text' }] }; } },
    truenasscale: { id: 'truenasscale', title: 'TrueNAS SCALE', category: 'storage', icon: 'truenas-scale', defaultUrl: 'https://192.168.1.10', allowInsecure: true, auth: { type: 'bearer', field: 'key' }, poll: 60, testRequest: 'info', requests: [{ id: 'info', path: '/api/v2.0/system/info' }, { id: 'pools', path: '/api/v2.0/pool', optional: true }, { id: 'alerts', path: '/api/v2.0/alert/list', optional: true }], normalize: (r) => { const pools = Array.isArray(r.pools) ? r.pools : []; const alerts = Array.isArray(r.alerts) ? r.alerts.filter(a => !a.dismissed) : []; return { fields: [{ label: 'Pools', value: pools.length, kind: 'stat' }, { label: 'Healthy', value: pools.filter(p => p.healthy !== false).length + '/' + pools.length, kind: 'text', state: pools.every(p => p.healthy !== false) ? 'good' : 'bad' }, { label: 'Alerts', value: alerts.length, kind: 'stat', state: alerts.length ? 'warn' : 'good' }] }; } },
    sonarr: { id: 'sonarr', title: 'Sonarr', category: 'media', icon: 'sonarr', defaultUrl: 'http://192.168.1.10:8989', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 120, testRequest: 'queue', requests: [{ id: 'queue', path: '/api/v3/queue?pageSize=1' }, { id: 'missing', path: '/api/v3/wanted/missing?pageSize=1', optional: true }], actions: [{ id: 'rss', label: 'RSS sync', method: 'POST', path: '/api/v3/command', body: { name: 'RssSync' } }, { id: 'search-missing', label: 'Search missing', method: 'POST', path: '/api/v3/command', body: { name: 'MissingEpisodeSearch' } }], normalize: (r) => ({ fields: [{ label: 'Queue', value: (r.queue && r.queue.totalRecords) || 0, kind: 'stat' }, { label: 'Missing', value: (r.missing && r.missing.totalRecords) || 0, kind: 'stat', state: ((r.missing && r.missing.totalRecords) || 0) > 0 ? 'warn' : 'good' }] }) },
    radarr: { id: 'radarr', title: 'Radarr', category: 'media', icon: 'radarr', defaultUrl: 'http://192.168.1.10:7878', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 120, testRequest: 'queue', requests: [{ id: 'queue', path: '/api/v3/queue?pageSize=1' }, { id: 'missing', path: '/api/v3/wanted/missing?pageSize=1', optional: true }], actions: [{ id: 'rss', label: 'RSS sync', method: 'POST', path: '/api/v3/command', body: { name: 'RssSync' } }, { id: 'search-missing', label: 'Search missing', method: 'POST', path: '/api/v3/command', body: { name: 'MissingMoviesSearch' } }], normalize: (r) => ({ fields: [{ label: 'Queue', value: (r.queue && r.queue.totalRecords) || 0, kind: 'stat' }, { label: 'Missing', value: (r.missing && r.missing.totalRecords) || 0, kind: 'stat', state: ((r.missing && r.missing.totalRecords) || 0) > 0 ? 'warn' : 'good' }] }) },
    lidarr: { id: 'lidarr', title: 'Lidarr', category: 'media', icon: 'lidarr', defaultUrl: 'http://192.168.1.10:8686', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 300, testRequest: 'queue', requests: [{ id: 'queue', path: '/api/v1/queue?pageSize=1' }, { id: 'missing', path: '/api/v1/wanted/missing?pageSize=1', optional: true }], normalize: (r) => ({ fields: [{ label: 'Queue', value: (r.queue && r.queue.totalRecords) || 0, kind: 'stat' }, { label: 'Missing', value: (r.missing && r.missing.totalRecords) || 0, kind: 'stat', state: ((r.missing && r.missing.totalRecords) || 0) > 0 ? 'warn' : 'good' }] }) },
    prowlarr: { id: 'prowlarr', title: 'Prowlarr', category: 'media', icon: 'prowlarr', defaultUrl: 'http://192.168.1.10:9696', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 300, testRequest: 'indexers', requests: [{ id: 'indexers', path: '/api/v1/indexer' }], normalize: (r) => { const ix = Array.isArray(r.indexers) ? r.indexers : []; return { fields: [{ label: 'Indexers', value: ix.length, kind: 'stat' }, { label: 'Enabled', value: ix.filter(x => x.enable).length, kind: 'stat', state: 'good' }] }; } },
    bazarr: { id: 'bazarr', title: 'Bazarr', category: 'media', icon: 'bazarr', defaultUrl: 'http://192.168.1.10:6767', auth: { type: 'header', name: 'X-API-KEY', field: 'key' }, poll: 300, testRequest: 'badges', requests: [{ id: 'badges', path: '/api/badges' }], normalize: (r) => { const b = r.badges || {}; return { fields: [{ label: 'Missing eps', value: b.episodes || 0, kind: 'stat', state: (b.episodes || 0) > 0 ? 'warn' : 'good' }, { label: 'Missing films', value: b.movies || 0, kind: 'stat', state: (b.movies || 0) > 0 ? 'warn' : 'good' }, { label: 'Providers', value: b.providers || 0, kind: 'stat' }] }; } },
    tautulli: { id: 'tautulli', title: 'Tautulli', category: 'media', icon: 'tautulli', defaultUrl: 'http://192.168.1.10:8181', auth: { type: 'query', name: 'apikey', field: 'key' }, poll: 30, testRequest: 'activity', requests: [{ id: 'activity', path: '/api/v2?cmd=get_activity' }], normalize: (r) => { const d = (r.activity && r.activity.response && r.activity.response.data) || {}; return { fields: [{ label: 'Streams', value: d.stream_count || 0, kind: 'stat', state: d.stream_count ? 'good' : 'idle' }, { label: 'Bandwidth', value: d.total_bandwidth ? Math.round(d.total_bandwidth / 1000) + ' Mbps' : '—', kind: 'text' }, { label: 'Transcodes', value: d.stream_count_transcode || 0, kind: 'stat' }] }; } },
    sabnzbd: { id: 'sabnzbd', title: 'SABnzbd', category: 'downloads', icon: 'sabnzbd', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'query', name: 'apikey', field: 'key' }, poll: 15, testRequest: 'queue', requests: [{ id: 'queue', path: '/api?mode=queue&output=json' }], actions: [{ id: 'pause', label: 'Pause', method: 'GET', path: '/api?mode=pause&output=json' }, { id: 'resume', label: 'Resume', method: 'GET', path: '/api?mode=resume&output=json' }], normalize: (r) => { const q = (r.queue && r.queue.queue) || {}; return { fields: [{ label: 'Speed', value: q.kbpersec ? Math.round(Number(q.kbpersec)) + ' KB/s' : 'idle', kind: 'text', state: Number(q.kbpersec) > 0 ? 'good' : 'idle' }, { label: 'Queue', value: q.noofslots || 0, kind: 'stat' }, { label: 'Left', value: q.sizeleft || '—', kind: 'text' }] }; } },
    gatus: { id: 'gatus', title: 'Gatus', category: 'monitoring', icon: 'gatus', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 30, testRequest: 'statuses', requests: [{ id: 'statuses', path: '/api/v1/endpoints/statuses' }], normalize: (r) => { const e = Array.isArray(r.statuses) ? r.statuses : []; const last = x => x.results && x.results[x.results.length - 1]; const down = e.filter(x => { const l = last(x); return l && !l.success; }).length; return { fields: [{ label: 'Endpoints', value: e.length, kind: 'stat' }, { label: 'Down', value: down, kind: 'stat', state: down ? 'bad' : 'good' }], items: e.slice(0, 6).map(x => { const l = last(x); return { label: x.name || x.key, value: l && l.success ? 'up' : 'down', state: l && l.success ? 'good' : 'bad' }; }) }; } },
    scrutiny: { id: 'scrutiny', title: 'Scrutiny', category: 'storage', icon: 'scrutiny', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 300, testRequest: 'summary', requests: [{ id: 'summary', path: '/api/summary' }], normalize: (r) => { const d = (r.summary && r.summary.data && r.summary.data.summary) || {}; const disks = Object.values(d); const failed = disks.filter(x => x.device && x.device.device_status !== 0).length; const temps = disks.map(x => x.temp).filter(t => t != null); return { fields: [{ label: 'Disks', value: disks.length, kind: 'stat' }, { label: 'Failing', value: failed, kind: 'stat', state: failed ? 'bad' : 'good' }, { label: 'Hottest', value: temps.length ? Math.max.apply(null, temps) + '°' : '—', kind: 'text' }] }; } },
    alertmanager: { id: 'alertmanager', title: 'Alertmanager', category: 'monitoring', icon: 'prometheus', defaultUrl: 'http://192.168.1.10:9093', auth: { type: 'none' }, poll: 30, testRequest: 'alerts', requests: [{ id: 'alerts', path: '/api/v2/alerts?active=true' }], normalize: (r) => { const a = Array.isArray(r.alerts) ? r.alerts : []; const crit = a.filter(x => x.labels && x.labels.severity === 'critical').length; return { fields: [{ label: 'Firing', value: a.length, kind: 'stat', state: a.length ? 'bad' : 'good' }, { label: 'Critical', value: crit, kind: 'stat', state: crit ? 'bad' : 'good' }], items: a.slice(0, 5).map(x => ({ label: (x.labels && (x.labels.alertname || x.labels.instance)) || 'alert', sub: (x.annotations && x.annotations.summary) || '', state: (x.labels && x.labels.severity === 'critical') ? 'bad' : 'warn' })) }; } },
    netdata: { id: 'netdata', title: 'Netdata', category: 'monitoring', icon: 'netdata', defaultUrl: 'http://192.168.1.10:19999', auth: { type: 'none' }, poll: 30, testRequest: 'alarms', requests: [{ id: 'alarms', path: '/api/v1/alarms?active=true' }], normalize: (r) => { const arr = Object.values((r.alarms && r.alarms.alarms) || {}); const crit = arr.filter(x => x.status === 'CRITICAL').length, warn = arr.filter(x => x.status === 'WARNING').length; return { fields: [{ label: 'Active', value: arr.length, kind: 'stat', state: arr.length ? 'warn' : 'good' }, { label: 'Critical', value: crit, kind: 'stat', state: crit ? 'bad' : 'good' }, { label: 'Warning', value: warn, kind: 'stat', state: warn ? 'warn' : 'good' }] }; } },
    paperless: { id: 'paperless', title: 'Paperless-ngx', category: 'productivity', icon: 'paperless-ngx', defaultUrl: 'http://192.168.1.10:8000', auth: { type: 'token', field: 'token' }, poll: 300, testRequest: 'stats', requests: [{ id: 'stats', path: '/api/statistics/' }], normalize: (r) => { const s = r.stats || {}; return { fields: [{ label: 'Documents', value: s.documents_total || 0, kind: 'stat' }, { label: 'Inbox', value: s.documents_inbox || 0, kind: 'stat', state: (s.documents_inbox || 0) > 0 ? 'warn' : 'good' }, { label: 'Tags', value: s.tag_count || 0, kind: 'stat' }] }; } },
    gitea: { id: 'gitea', title: 'Gitea / Forgejo', category: 'productivity', icon: 'gitea', defaultUrl: 'http://192.168.1.10:3000', auth: { type: 'token', field: 'token' }, poll: 120, testRequest: 'version', requests: [{ id: 'version', path: '/api/v1/version' }, { id: 'notif', path: '/api/v1/notifications?status-types=unread&limit=50', optional: true }], normalize: (r) => ({ fields: [{ label: 'Version', value: (r.version && r.version.version) || '—', kind: 'text' }, { label: 'Notifications', value: Array.isArray(r.notif) ? r.notif.length : 0, kind: 'stat', state: Array.isArray(r.notif) && r.notif.length ? 'warn' : 'good' }] }) },
    nextcloud: { id: 'nextcloud', title: 'Nextcloud', category: 'productivity', icon: 'nextcloud', defaultUrl: 'http://192.168.1.10', auth: { type: 'basic', userField: 'username', passField: 'password', headers: { 'OCS-APIRequest': 'true' } }, poll: 120, testRequest: 'info', requests: [{ id: 'info', path: '/ocs/v2.php/apps/serverinfo/api/v1/info?format=json' }], normalize: (r) => { const d = (r.info && r.info.ocs && r.info.ocs.data && r.info.ocs.data.nextcloud) || {}; const st = d.storage || {}; const sys = d.system || {}; return { fields: [{ label: 'Users', value: st.num_users || 0, kind: 'stat' }, { label: 'Files', value: st.num_files || 0, kind: 'stat' }, { label: 'Load', value: (sys.cpuload && sys.cpuload[0] != null) ? sys.cpuload[0].toFixed(2) : '—', kind: 'text' }] }; } },
    traefik: { id: 'traefik', title: 'Traefik', category: 'network', icon: 'traefik', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 60, testRequest: 'overview', requests: [{ id: 'overview', path: '/api/overview' }], normalize: (r) => { const h = (r.overview && r.overview.http) || {}; const rt = h.routers || {}, sv = h.services || {}; return { fields: [{ label: 'Routers', value: rt.total || 0, kind: 'stat' }, { label: 'Services', value: sv.total || 0, kind: 'stat' }, { label: 'Errors', value: (rt.errors || 0) + (sv.errors || 0), kind: 'stat', state: ((rt.errors || 0) + (sv.errors || 0)) ? 'bad' : 'good' }] }; } },
    authentik: { id: 'authentik', title: 'Authentik', category: 'security', icon: 'authentik', defaultUrl: 'https://192.168.1.10:9443', allowInsecure: true, auth: { type: 'bearer', field: 'token' }, poll: 120, testRequest: 'users', requests: [{ id: 'users', path: '/api/v3/core/users/?page_size=1' }, { id: 'fails', path: '/api/v3/events/events/?action=login_failed&page_size=1', optional: true }], normalize: (r) => ({ fields: [{ label: 'Users', value: (r.users && r.users.pagination && r.users.pagination.count) || 0, kind: 'stat' }, { label: 'Failed logins', value: (r.fails && r.fails.pagination && r.fails.pagination.count) || 0, kind: 'stat', state: ((r.fails && r.fails.pagination && r.fails.pagination.count) || 0) > 0 ? 'warn' : 'good' }] }) },
    crowdsec: { id: 'crowdsec', title: 'CrowdSec', category: 'security', icon: 'crowdsec', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'header', name: 'X-Api-Key', field: 'key' }, poll: 60, testRequest: 'decisions', requests: [{ id: 'decisions', path: '/v1/decisions' }], normalize: (r) => { const d = Array.isArray(r.decisions) ? r.decisions : []; const bans = d.filter(x => x.type === 'ban').length; return { fields: [{ label: 'Decisions', value: d.length, kind: 'stat' }, { label: 'Bans', value: bans, kind: 'stat', state: bans ? 'warn' : 'good' }], items: d.slice(0, 5).map(x => ({ label: x.value || x.scope, sub: (x.scenario || '').split('/').pop(), value: x.type, state: x.type === 'ban' ? 'bad' : 'warn' })) }; } },
    cloudflare: { id: 'cloudflare', title: 'Cloudflare Tunnels', category: 'network', icon: 'cloudflare', defaultUrl: 'https://api.cloudflare.com', auth: { type: 'bearer', field: 'token' }, poll: 120, configFields: [{ name: 'account', label: 'Account ID', kind: 'text' }], testRequest: 'tunnels', requests: [{ id: 'tunnels', path: '/client/v4/accounts/{{cfg.account}}/cfd_tunnel?is_deleted=false' }], normalize: (r) => { const t = (r.tunnels && r.tunnels.result) || []; const healthy = t.filter(x => x.status === 'healthy').length; return { fields: [{ label: 'Tunnels', value: t.length, kind: 'stat' }, { label: 'Healthy', value: healthy + '/' + t.length, kind: 'text', state: healthy === t.length ? 'good' : 'warn' }], items: t.slice(0, 5).map(x => ({ label: x.name, value: x.status, state: x.status === 'healthy' ? 'good' : x.status === 'degraded' ? 'warn' : 'bad' })) }; } },
    pbs: { id: 'pbs', title: 'Proxmox Backup', category: 'storage', icon: 'proxmox', defaultUrl: 'https://192.168.1.10:8007', allowInsecure: true, auth: { type: 'pveToken', scheme: 'PBSAPIToken', sep: ':', userField: 'user', tokenField: 'tokenid', secretField: 'secret' }, poll: 300, testRequest: 'usage', requests: [{ id: 'usage', path: '/api2/json/status/datastore-usage' }], normalize: (r) => { const d = (r.usage && r.usage.data) || []; const ds = d[0] || {}; const pct = ds.total ? Math.round(ds.used / ds.total * 100) : 0; return { gauge: { label: 'Datastore', value: pct, max: 100, unit: '%', state: pct >= 90 ? 'bad' : pct >= 75 ? 'warn' : 'good' }, fields: [{ label: 'Datastores', value: d.length, kind: 'stat' }, { label: 'Used', value: pct + '%', kind: 'text' }] }; } },
    mealie: { id: 'mealie', title: 'Mealie', category: 'productivity', icon: 'mealie', defaultUrl: 'http://192.168.1.10:9000', auth: { type: 'bearer', field: 'token' }, poll: 600, testRequest: 'stats', requests: [{ id: 'stats', path: '/api/households/statistics' }], normalize: (r) => { const s = r.stats || {}; return { fields: [{ label: 'Recipes', value: s.totalRecipes || 0, kind: 'stat' }, { label: 'Users', value: s.totalUsers || 0, kind: 'stat' }, { label: 'Tags', value: s.totalTags || 0, kind: 'stat' }] }; } },
    audiobookshelf: { id: 'audiobookshelf', title: 'Audiobookshelf', category: 'media', icon: 'audiobookshelf', defaultUrl: 'http://192.168.1.10:13378', auth: { type: 'bearer', field: 'token' }, poll: 600, testRequest: 'libraries', requests: [{ id: 'libraries', path: '/api/libraries' }], normalize: (r) => { const libs = (r.libraries && r.libraries.libraries) || []; return { fields: [{ label: 'Libraries', value: libs.length, kind: 'stat' }] }; } },
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
            { id: 'downloads', path: '/api/v1/downloads?page=1&page_size=8', optional: true }
        ],
        normalize: (r, ctx) => {
            const ok = !!(r.health && String(r.health.status || '').toLowerCase() === 'ok');
            const stats = r.stats || {};
            const pending = r.pending && typeof r.pending.count === 'number' ? r.pending.count : null;
            const sessions = (r.nowplaying && Array.isArray(r.nowplaying.sessions)) ? r.nowplaying.sessions : [];
            const releases = (r.releases && Array.isArray(r.releases.items)) ? r.releases.items : [];
            const dls = (r.downloads && Array.isArray(r.downloads.items)) ? r.downloads.items : [];
            const activeDls = dls.filter(d => !/^(completed|imported|failed|cancelled|canceled)$/i.test(String(d.status || '')));
            const client = r.client || null;                     // slskd download-client status
            const clientOk = client ? (client.configured && (!client.mount || client.mount.ok !== false)) : null;
            const integr = r.integr || null;                     // which DN sources are wired up
            const fields = [
                { label: 'Backend', value: ok ? 'Online' : 'Unreachable', kind: 'text', state: ok ? 'good' : 'bad' },
                typeof stats.total_artists === 'number' ? { label: 'Artists', value: stats.total_artists, kind: 'stat' } : null,
                typeof stats.total_albums === 'number' ? { label: 'Albums', value: stats.total_albums, kind: 'stat' } : null,
                pending != null ? { label: 'Pending requests', value: pending, kind: 'stat', state: pending > 0 ? 'warn' : 'good' } : null,
                sessions.length ? { label: 'Listening now', value: sessions.length, kind: 'stat', state: 'good' } : null,
                activeDls.length ? { label: 'Downloading', value: activeDls.length, kind: 'stat', state: 'good' } : null,
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
                    downloads: activeDls.slice(0, 6).map(d => ({ album: d.album_title, artist: d.artist_name, status: d.status, progress: d.progress_percent, files: d.files_total ? `${d.files_completed}/${d.files_total}` : null, error: d.error_message || null })),
                    stats: { artists: stats.total_artists, albums: stats.total_albums, tracks: stats.total_tracks, size: stats.total_size_bytes, unmatched: stats.unmatched_count },
                    recentlyAdded: Array.isArray(stats.recently_added) ? stats.recently_added.slice(0, 6).map(a => ({ title: a.album_title, artist: a.album_artist_name, mbid: a.release_group_mbid, cover: a.cover_url || null, year: a.year })) : [],
                    client: clientOk, integrations: integr, base: ctx.base
                }
            };
        }
    },
    vaultwarden: { id: 'vaultwarden', title: 'Vaultwarden', category: 'security', icon: 'vaultwarden', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'none' }, poll: 120, testRequest: 'alive', requests: [{ id: 'alive', path: '/alive' }, { id: 'version', path: '/api/version', optional: true }], normalize: (r) => ({ fields: [{ label: 'Status', value: 'Online', kind: 'text', state: 'good' }, { label: 'Version', value: r.version || '—', kind: 'text' }] }) },
    coingecko: { id: 'coingecko', title: 'Crypto (CoinGecko)', category: 'feeds', icon: 'bitcoin', defaultUrl: 'https://api.coingecko.com', auth: { type: 'none' }, poll: 300, configFields: [{ name: 'coins', label: 'Coin IDs (comma)', kind: 'text' }], testRequest: 'price', requests: [{ id: 'price', path: '/api/v3/simple/price?ids={{cfg.coins}}&vs_currencies=usd&include_24hr_change=true' }], normalize: (r) => { const p = r.price || {}; const items = Object.keys(p).map(k => { const o = p[k]; const ch = o.usd_24h_change; return { label: k, value: o.usd != null ? '$' + o.usd : '—', sub: ch != null ? ch.toFixed(1) + '%' : '', state: ch > 0 ? 'good' : ch < 0 ? 'bad' : 'idle' }; }); return { items }; } },
    qbittorrent: { id: 'qbittorrent', title: 'qBittorrent', category: 'media', icon: 'qbittorrent', defaultUrl: 'http://192.168.1.10:8080', auth: { type: 'session', userField: 'username', passField: 'password' }, poll: 15, login: { path: '/api/v2/auth/login', method: 'POST', body: 'username={{enc:cred.username}}&password={{enc:cred.password}}', tokenFrom: 'cookie', cookieName: 'SID', apply: 'cookie' }, testRequest: 'xfer', requests: [{ id: 'xfer', path: '/api/v2/transfer/info' }, { id: 'torrents', path: '/api/v2/torrents/info', optional: true }], actions: [{ id: 'pause-all', label: 'Pause all', method: 'POST', path: '/api/v2/torrents/pause', body: 'hashes=all' }, { id: 'resume-all', label: 'Resume all', method: 'POST', path: '/api/v2/torrents/resume', body: 'hashes=all' }], normalize: (r) => { const x = r.xfer || {}; const ts = Array.isArray(r.torrents) ? r.torrents : []; const active = ts.filter(t => /dl|down|stalledUP|uploading|forcedUP/i.test(t.state || '')).length; return { fields: [{ label: 'Download', value: x.dl_info_speed || 0, kind: 'rate', state: 'good' }, { label: 'Upload', value: x.up_info_speed || 0, kind: 'rate' }, { label: 'Torrents', value: active + '/' + ts.length, kind: 'text' }], items: ts.filter(t => /dl|down|meta/i.test(t.state || '')).slice(0, 5).map(t => ({ label: t.name, sub: Math.round((t.progress || 0) * 100) + '%', state: 'good' })) }; } },
    synology: { id: 'synology', title: 'Synology DSM', category: 'storage', icon: 'synology', defaultUrl: 'http://192.168.1.10:5000', allowInsecure: true, auth: { type: 'session', userField: 'username', passField: 'password' }, poll: 60, login: { path: '/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&session=Core&format=sid&account={{enc:cred.username}}&passwd={{enc:cred.password}}', method: 'GET', tokenFrom: 'json', tokenPath: 'data.sid', apply: 'query', applyName: '_sid' }, testRequest: 'info', requests: [{ id: 'info', path: '/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info' }], normalize: (r) => { const d = (r.info && r.info.data) || {}; const up = Number(d.uptime) || 0, days = Math.floor(up / 86400), hrs = Math.floor((up % 86400) / 3600); const t = d.temperature; return { fields: [{ label: 'Model', value: d.model || '—', kind: 'text' }, { label: 'Temp', value: t != null ? t + '°C' : '—', kind: 'text', state: t >= 65 ? 'bad' : t >= 55 ? 'warn' : 'good' }, { label: 'Uptime', value: up ? (days + 'd ' + hrs + 'h') : '—', kind: 'text' }] }; } },
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
        const baseUrl = (storedEndpoint('Node Exporter') || probe.defaultUrl).replace(/\/+$/, '');
        const r = await liveFetch({ baseUrl, path: probe.path, key: '', probe });
        if (r.ok && r.body && r.body.raw) sseBroadcast('host', { raw: r.body.raw, ts: Date.now() });
    } catch (e) { /* skip this tick */ }
}
async function sseSampleMedia() {
    try {
        const probe = LIVE_PROBES['Tracearr'];
        const baseUrl = (storedEndpoint('Tracearr') || probe.defaultUrl).replace(/\/+$/, '');
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
const _sessions = new Map();   // token -> expiry ms
const SESSION_TTL_MS = 12 * 3600 * 1000;
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
    const tok = crypto.randomBytes(32).toString('hex');
    _sessions.set(tok, Date.now() + SESSION_TTL_MS);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(req, 'cc_session', tok, SESSION_TTL_MS / 1000) });
    res.end(JSON.stringify(Object.assign({ ok: true }, extra || {})));
}
function parseCookies(req) { const out = {}; String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return out; }
function hasSession(req) {
    const tok = parseCookies(req).cc_session || '';
    if (!tok) return false;
    const exp = _sessions.get(tok);
    if (exp && exp > Date.now()) return true;
    _sessions.delete(tok);
    return false;
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
function isSecureRequest(req) { return reqScheme(req) === 'https'; }
function publicOrigin(req) { return PUBLIC_URL || `${reqScheme(req)}://${reqHost(req)}`; }
// Build a Set-Cookie that upgrades to Secure automatically behind TLS.
// SameSite=Strict: the dashboard has no cross-site entry flow, so the cookie is
// never sent on a cross-origin request — closing the residual CSRF surface.
function sessionCookie(req, name, value, maxAgeSec) {
    const secure = isSecureRequest(req) ? '; Secure' : '';
    return `${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`;
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

/* ═══════════════════════════ DEMO MODE ═══════════════════════════
   `DEMO=1` serves a realistic, fully synthetic homelab so the UI is explorable
   with zero configuration — and so documentation screenshots contain no real
   infrastructure. Generic instance names, RFC-5737 documentation IPs, invented
   clients. Values drift slightly over time so charts and the live badge move. */
const DEMO = process.env.DEMO === '1';
const DEMO_T0 = Date.now();
function dwave(period, amp, base, phase) { return base + amp * Math.sin((Date.now() - DEMO_T0) / period + (phase || 0)); }
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
const DEMO_ENABLED = new Set(['ollama', 'homeassistant', 'sonarr', 'radarr', 'sabnzbd', 'qbittorrent', 'plex', 'jellyfin', 'tautulli', 'proxmox', 'adguard', 'prometheus', 'immich']);
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
    const W = {
        ollama: { fields: [{ label: 'Models', value: 5, kind: 'stat' }, { label: 'Loaded', value: 2, kind: 'stat', state: 'good' }, { label: 'On disk', value: '28.4 GB', kind: 'text' }, { label: 'VRAM in use', value: '11.2 GB', kind: 'text', state: 'good' }], items: [{ label: 'llama3.1:8b', sub: '8.0B · Q4_K_M', value: 'loaded', state: 'good' }, { label: 'qwen2.5-coder:14b', sub: '14.8B · Q4_K_M', value: 'loaded', state: 'good' }, { label: 'mistral-small:24b', sub: '24B · Q4_K_M', value: '14.3 GB', state: 'idle' }, { label: 'nomic-embed-text:latest', sub: '137M · F16', value: '0.3 GB', state: 'idle' }, { label: 'llava:13b', sub: '13B · Q4_0', value: '8.0 GB', state: 'idle' }], version: '0.5.4' },
        homeassistant: { gauge: { label: 'Available', value: 99, max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Lights on', value: '4/11', kind: 'text', state: 'good' }, { label: 'Switches on', value: 3, kind: 'stat', state: 'good' }, { label: 'Climate', value: 2, kind: 'stat' }, { label: 'Locks', value: '2/2', kind: 'text', state: 'good' }, { label: 'People home', value: 2, kind: 'stat', state: 'good' }, { label: 'Entities', value: 214, kind: 'stat' }], items: [{ label: 'Garage Door', sub: 'open', value: 'open', state: 'warn' }], version: '2026.6.1' },
        sonarr: { fields: [{ label: 'Queue', value: 2, kind: 'stat' }, { label: 'Missing', value: 5, kind: 'stat', state: 'warn' }] },
        radarr: { fields: [{ label: 'Queue', value: 1, kind: 'stat' }, { label: 'Missing', value: 3, kind: 'stat', state: 'warn' }] },
        sabnzbd: { fields: [{ label: 'Speed', value: Math.round(dwave(6000, 4000, 6000)) + ' KB/s', kind: 'text', state: 'good' }, { label: 'Queue', value: 3, kind: 'stat' }, { label: 'Left', value: '2.4 GB', kind: 'text' }] },
        qbittorrent: { fields: [{ label: 'Download', value: Math.max(0, Math.round(dwave(9000, 3e6, 5e6))), kind: 'rate', state: 'good' }, { label: 'Upload', value: Math.max(0, Math.round(dwave(7000, 8e5, 1.2e6))), kind: 'rate' }, { label: 'Torrents', value: '3/24', kind: 'text' }], items: [{ label: 'ubuntu-24.04.1-desktop-amd64.iso', sub: '68%', state: 'good' }, { label: 'debian-12.7.0-amd64-DVD-1.iso', sub: '31%', state: 'good' }] },
        plex: { fields: [{ label: 'Streams', value: 3, kind: 'stat', state: 'good' }], items: [{ label: 'The Shining', sub: 'alex · direct play', state: 'good' }, { label: 'Dune: Part Two', sub: 'sam · transcode', state: 'good' }, { label: 'Severance — S01E03', sub: 'jodie · direct play', state: 'good' }] },
        jellyfin: { fields: [{ label: 'Streams', value: 1, kind: 'stat', state: 'good' }, { label: 'Devices', value: 6, kind: 'stat' }] },
        tautulli: { fields: [{ label: 'Streams', value: 3, kind: 'stat', state: 'good' }, { label: 'Bandwidth', value: '48 Mbps', kind: 'text' }, { label: 'Transcodes', value: 1, kind: 'stat' }] },
        proxmox: { gauge: { label: 'CPU', value: Math.max(0, Math.round(dwave(11000, 12, 24))), max: 100, unit: '%', state: 'good' }, fields: [{ label: 'VMs/LXC', value: '11/12', kind: 'text', state: 'warn' }, { label: 'Nodes', value: '3/3', kind: 'text' }, { label: 'Memory', value: '61%', kind: 'text' }] },
        adguard: { gauge: { label: 'Blocked', value: 18, max: 100, unit: '%', state: 'good' }, fields: [{ label: 'Queries', value: 84213, kind: 'stat' }, { label: 'Blocked', value: 15380, kind: 'stat', state: 'warn' }, { label: 'Protection', value: 'On', kind: 'text', state: 'good' }] },
        prometheus: { gauge: { label: 'Targets up', value: 96, max: 100, unit: '%', state: 'warn' }, fields: [{ label: 'Targets', value: '24/25', kind: 'text', state: 'warn' }] },
        immich: { fields: [{ label: 'Photos', value: 48210, kind: 'stat' }, { label: 'Videos', value: 3120, kind: 'stat' }, { label: 'Users', value: 4, kind: 'stat' }] }
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

const server = http.createServer(async (req, res) => {
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
            if (!ok) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'invalid password' })); return; }
            // Transparently upgrade a legacy sha256 vault hash to scrypt on success.
            if (!_envAuthTarget && /^[0-9a-f]{64}$/i.test(String(target))) { try { setVaultAuthPassword(pw); } catch (e) {} }
            issueSession(req, res);
            return;
        }
        if (req.url === '/api/logout' && req.method === 'POST') {
            const tok = parseCookies(req).cc_session || '';
            if (tok) _sessions.delete(tok);
            auditLog(req, 'auth.logout', '', 'ok');
            res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `cc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0` });
            res.end(JSON.stringify({ ok: true }));
            return;
        }
        // Endpoints reachable WITHOUT a session even when auth is on:
        //   /api/login (above), /api/stream handshake, /api/meta (liveness).
        const open = req.url === '/api/stream' || req.url === '/api/meta';
        if (req.url.startsWith('/api/') && !open && !hasSession(req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'authentication required', login: '/api/login' }));
            return;
        }
    }
    // ── first-run setup: set (or clear) the optional dashboard password ──
    // Open while no auth exists yet (first run); requires a session once auth is on.
    if (req.url === '/api/setup/password' && req.method === 'POST') {
        if (authEnabled() && !hasSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'authentication required' })); return; }
        if (authPasswordFromEnv()) { res.writeHead(409, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'password is managed by DASHBOARD_PASSWORD in the environment' })); return; }
        const body = await readJsonBody(req).catch(() => ({}));
        const pw = String((body && body.password) || '');
        if (pw && pw.length < 12) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'password must be at least 12 characters' })); return; }
        setVaultAuthPassword(pw || '');
        auditLog(req, 'auth.set-password', '', pw ? 'set' : 'cleared');
        // Rotate: invalidate the caller's prior session token before issuing a fresh one.
        const oldTok = parseCookies(req).cc_session || ''; if (oldTok) _sessions.delete(oldTok);
        if (pw) { issueSession(req, res, { enabled: true }); return; }   // keep the user signed in with a new token
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
    } else if (req.url === '/api/unifi/status') {
        try {
            const out = await queryUnifiStatus();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(out));
        } catch (err) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ configured: true, ok: false, error: err.message || 'UniFi status unavailable', alerts: ['UniFi status unavailable.'] }));
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
        // Try to discover Tracearr API endpoints
        const TRACEARR_BASE = 'http://127.0.0.1:30316';
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
                const proxyReq = require('http').get(url, {
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
        const cat = Object.values(INTEGRATIONS).map(d => ({
            id: d.id, title: d.title, category: d.category, icon: d.icon || d.id, defaultUrl: d.defaultUrl || '', note: d.note || '',
            authFields: igAuthFields(d.auth), configFields: d.configFields || [],
            // Expose write-actions (metadata only — never how they authenticate) so the
            // provider card can render control buttons.
            actions: (d.actions || []).map(a => ({ id: a.id, label: a.label, confirm: !!a.confirm, danger: !!a.danger, params: a.params || [] })),
            enabled: (DEMO && DEMO_ENABLED.has(d.id)) || !!(settings.integrations && settings.integrations[d.id] && settings.integrations[d.id].enabled),
            url: (DEMO && DEMO_ENABLED.has(d.id)) ? (d.defaultUrl || '') : (storedEndpoint(d.id) || '')
        }));
        jsonRes(res, 200, cat);
    } else if (req.url === '/api/widget' && req.method === 'POST') {
        try {
            const payload = await readJsonBody(req);
            const def = INTEGRATIONS[payload && payload.type];
            if (!def) { jsonRes(res, 404, { ok: false, error: 'unknown integration' }); return; }
            const settings = readDashboardSettings();
            const cfg = (settings.integrations && settings.integrations[def.id]) || {};
            const base = ((storedEndpoint(def.id) || cfg.url || def.defaultUrl) || '').replace(/\/+$/, '');
            if (!base) { jsonRes(res, 400, { ok: false, error: 'No URL configured' }); return; }
            const cred = integrationCred(def.id);
            const out = await runIntegration(def, base, cred, cfg, payload.test);
            jsonRes(res, out.ok === false && payload.test ? 200 : (out.ok === false ? 502 : 200), Object.assign({ type: def.id }, out, { updatedAt: Date.now() }));
        } catch (e) { jsonRes(res, 500, { ok: false, error: e.message }); }
    } else if (req.url === '/api/integration/action' && req.method === 'POST') {
        // Run a named write-action on an enabled provider. Same auth/CSRF/session
        // gates as every POST route; the action must be declared in the provider's
        // `actions` array (no arbitrary path is ever accepted from the client).
        try {
            const payload = await readJsonBody(req);
            const def = INTEGRATIONS[payload && payload.type];
            if (!def) { jsonRes(res, 404, { ok: false, error: 'unknown integration' }); return; }
            const settings = readDashboardSettings();
            const cfg = (settings.integrations && settings.integrations[def.id]) || {};
            if (!(cfg && cfg.enabled)) { jsonRes(res, 400, { ok: false, error: 'provider not enabled' }); return; }
            const base = ((storedEndpoint(def.id) || cfg.url || def.defaultUrl) || '').replace(/\/+$/, '');
            if (!base) { jsonRes(res, 400, { ok: false, error: 'No URL configured' }); return; }
            const out = await runIntegrationAction(def, base, integrationCred(def.id), cfg, String(payload.action || ''), payload.params || {});
            auditLog(req, 'integration.action', def.id + ':' + (payload.action || ''), out.ok ? 'ok' : 'failed');
            jsonRes(res, out.ok ? 200 : (out.status || 502), Object.assign({ type: def.id }, out));
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
                const r = await get('/api/v1/downloads?page=1&page_size=20');
                jsonRes(res, 200, { ok: true, items: (r.items || []).map(d => ({ album: d.album_title, artist: d.artist_name, track: d.track_title, status: d.status, progress: d.progress_percent, files: d.files_total ? d.files_completed + '/' + d.files_total : null, error: d.error_message, source: d.source })) });
            } else if (what === 'releases') {
                const r = await get('/api/v1/following/new-releases?limit=24&offset=0');
                jsonRes(res, 200, { ok: true, items: (r.items || []).map(x => ({ title: x.title, artist: x.artist_name, date: x.first_release_date, type: x.primary_type, mbid: x.release_group_mbid, cover: coverRef({ musicbrainz_id: x.release_group_mbid }) })) });
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
        if (target.protocol === 'https:') opts.rejectUnauthorized = !ALLOW_INSECURE_TLS;
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

        let target;
        try {
            if (/^https?:\/\//i.test(rawSrc)) {
                target = new URL(rawSrc);
                if (target.hostname !== '127.0.0.1') throw new Error('blocked external image proxy target');
            } else {
                const rel = rawSrc.startsWith('/') ? rawSrc : `/${rawSrc}`;
                target = new URL(rel, 'http://127.0.0.1:30316');
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
        // Proxy Tracearr API requests
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
            const TRACEARR_URL = `http://127.0.0.1:30316${path}`;
            attempts++;
            
            try {
                const proxyReq = require('http').get(TRACEARR_URL, {
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
            const endpoint = (override || LIVE_PROBES['TrueNAS Web UI'].defaultUrl).replace(/\/+$/, '');
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
        const baseUrl = (override || probe.defaultUrl).replace(/\/+$/, '');
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
        console.log(`🐉 Dashboard running at http://127.0.0.1:${PORT}/`);
    });

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
module.exports = { INTEGRATIONS, hashPassword, verifyPassword, igApplyTpl, securityHeaders, isSecretPlaceholder, SECRET_SENTINEL, escapeJsonForScript, ipZone, assertFetchTarget };
