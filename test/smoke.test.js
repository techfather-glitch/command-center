'use strict';
// Smoke tests for Command Center — zero dependencies, Node's built-in runner.
//   node --test            (from the repo root)
//
// Two goals:
//   1. Every provider adapter's normalize() must survive empty/partial data
//      without throwing, and produce the right shape on a realistic response.
//      (The adapters are the riskiest surface — this is the safety net.)
//   2. The security primitives (password hashing, template substitution,
//      response headers, secret redaction) behave as claimed.

const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
// Point the server at a throwaway data dir so requiring it can never write a
// vault key into the repo. The require.main guard means nothing binds a port.
process.env.DATA_DIR = path.join(os.tmpdir(), 'cc-smoke-' + process.pid);

const { test } = require('node:test');
const assert = require('node:assert/strict');
const cc = require('../server.js');

const { INTEGRATIONS, hashPassword, verifyPassword, igApplyTpl, securityHeaders, isSecretPlaceholder, SECRET_SENTINEL, escapeJsonForScript, ipZone, assertFetchTarget, sessionCookie, SECRET_FIELDS, signSession, hasSession, serviceProbeBase, isLoopbackUrl } = cc;

// ── helpers ──────────────────────────────────────────────────────────────
const field = (out, rx) => (out.fields || []).find(f => new RegExp(rx, 'i').test(f.label));
const fval = (out, rx) => { const f = field(out, rx); return f ? f.value : undefined; };

// ── 1. adapter normalize(): null-safety across the whole registry ─────────
test('every adapter normalize() survives empty data without throwing', () => {
  const offenders = [];
  for (const [id, def] of Object.entries(INTEGRATIONS)) {
    if (typeof def.normalize !== 'function') continue;
    let out;
    try { out = def.normalize({}, { base: 'http://x', cfg: {} }); }
    catch (e) { offenders.push(`${id}: threw ${e.message}`); continue; }
    if (out != null && typeof out !== 'object') offenders.push(`${id}: returned ${typeof out}`);
  }
  assert.deepEqual(offenders, [], 'adapters that mishandle empty data:\n' + offenders.join('\n'));
});

test('every adapter also survives a single-key partial response', () => {
  const offenders = [];
  for (const [id, def] of Object.entries(INTEGRATIONS)) {
    if (typeof def.normalize !== 'function' || !Array.isArray(def.requests)) continue;
    for (const rq of def.requests) {
      const raw = {}; raw[rq.id] = null;   // this request came back null/failed
      try { def.normalize(raw, { base: 'http://x', cfg: {} }); }
      catch (e) { offenders.push(`${id} (${rq.id}=null): ${e.message}`); }
    }
  }
  assert.deepEqual(offenders, [], 'adapters that throw on a null request:\n' + offenders.join('\n'));
});

// ── 2. adapter normalize(): realistic responses produce the right shape ───
const CASES = {
  ollama: {
    raw: {
      tags: { models: [
        { name: 'llama3.1:8b', size: 4.6e9, details: { parameter_size: '8B', quantization_level: 'Q4' } },
        { name: 'embed', size: 3e8, details: {} },
      ] },
      ps: { models: [{ name: 'llama3.1:8b', size_vram: 5.1e9 }] },
      ver: { version: '0.5.4' },
    },
    check: (o) => {
      assert.equal(fval(o, '^Models$'), 2, 'Models count');
      assert.equal(fval(o, 'Loaded'), 1, 'Loaded count');
      assert.equal(o.version, '0.5.4');
      assert.equal(o.ok, true);
      assert.ok(o.items.some(m => m.state === 'good'), 'loaded model highlighted');
    },
  },
  homeassistant: {
    raw: {
      config: { version: '2026.6.1' },
      states: [
        { entity_id: 'light.a', state: 'on', attributes: { friendly_name: 'A' } },
        { entity_id: 'light.b', state: 'off' },
        { entity_id: 'lock.c', state: 'unlocked', attributes: { friendly_name: 'Back Door' } },
        { entity_id: 'sensor.d', state: 'unavailable', attributes: { friendly_name: 'Shed' } },
      ],
    },
    check: (o) => {
      assert.equal(o.gauge.label, 'Available');
      assert.equal(o.gauge.value, 75, '3 of 4 available');
      assert.equal(fval(o, 'Lights on'), '1/2');
      assert.equal(o.version, '2026.6.1');
      assert.ok(o.items.some(i => /unlocked/i.test(i.value)), 'unlocked door flagged');
      assert.ok(o.items.some(i => /unavailable/i.test(i.value)), 'offline device flagged');
    },
  },
  kubernetes: {
    raw: {
      version: { gitVersion: 'v1.30.2' },
      nodes: { items: [{ status: { conditions: [{ type: 'Ready', status: 'True' }] } }] },
      pods: { items: [{ status: { phase: 'Running' } }, { status: { phase: 'Pending' } }] },
    },
    check: (o) => {
      assert.equal(o.gauge.label, 'Nodes Ready');
      assert.equal(o.gauge.value, 100);
      assert.equal(fval(o, '^Nodes$'), 1);
      assert.equal(fval(o, 'Pods Running'), 1);
      assert.equal(o.ok, true);
    },
  },
  incus: {
    raw: {
      instances: { metadata: [
        { status: 'Running', type: 'container' },
        { status: 'Stopped', type: 'virtual-machine' },
      ] },
      server: { metadata: { environment: { server_version: '6.1' }, auth: 'trusted' } },
    },
    check: (o) => {
      assert.equal(fval(o, 'Instances'), 2);
      assert.equal(fval(o, '^Running$'), 1);
      assert.equal(fval(o, 'VMs'), 1);
      assert.equal(fval(o, 'Containers'), 1);
      assert.equal(o.version, '6.1');
      assert.equal(o.ok, true);
    },
  },
  emby: {
    raw: {
      info: { Version: '4.8.11', OperatingSystemDisplayName: 'Linux', HasUpdateAvailable: false },
      sessions: [{ NowPlayingItem: { Name: 'x' }, PlayState: { IsPaused: false } }],
    },
    check: (o) => {
      assert.equal(fval(o, 'Streams'), 1);
      assert.equal(o.version, '4.8.11');
      assert.equal(o.ok, true);
    },
  },
  podman: {
    raw: {
      info: { host: { memTotal: 16e9, memFree: 8e9, cpus: 8 }, store: { containerStore: { number: 5, running: 3, stopped: 2 }, graphDriverName: 'overlay' }, version: { Version: '5.0.0' } },
      containers: [{ State: 'running' }, { State: 'running' }, { State: 'running' }, { State: 'exited' }, { State: 'exited' }],
    },
    check: (o) => {
      assert.equal(o.gauge.label, 'Memory Used');
      assert.equal(o.gauge.value, 50);
      assert.equal(fval(o, 'Containers'), 5);
      assert.equal(o.version, '5.0.0');
    },
  },
  opnsense: {
    raw: {
      status: { status: 'OK' },
      info: { versions: ['24.7.3'] },
      res: { memory: { total: 8e9, used: 2e9 } },
      time: { uptime: '3 days', loadavg: '0.42' },
    },
    check: (o) => {
      assert.equal(o.version, '24.7.3');
      assert.equal(o.ok, true);
      assert.ok(field(o, 'Health'));
      assert.equal(o.gauge.value, 25);
    },
  },
  pfsense: {
    raw: {
      version: { data: { version: '2.7.2' } },
      status: { data: { cpu_usage: 20, mem_usage: 40, disk_usage: 30, uptime: '5 days', cpu_count: 4 } },
    },
    check: (o) => {
      assert.equal(o.version, '2.7.2');
      assert.equal(o.ok, true);
      assert.equal(o.gauge.value, 40);
    },
  },
  unraid: {
    raw: {
      online: { data: { online: true } },
      data: { data: { info: { os: { uptime: '10 days' }, versions: { unraid: '6.12.10' } }, array: { state: 'STARTED', capacity: { kilobytes: { free: '1000', used: '3000', total: '4000' } } } } },
    },
    check: (o) => {
      assert.equal(o.version, '6.12.10');
      assert.equal(o.ok, true);
      assert.equal(o.gauge.value, 75, 'array 3000/4000 KB used');
      assert.equal(fval(o, 'Array'), 'STARTED');
    },
  },
  sonarr: {
    raw: { queue: { totalRecords: 3 }, missing: { totalRecords: 1 } },
    check: (o) => {
      assert.equal(fval(o, 'Queue'), 3);
      assert.equal(fval(o, 'Missing'), 1);
    },
  },
  plex: {
    raw: { sessions: { MediaContainer: { size: 2, Metadata: [{ title: 'X', User: { title: 'u' } }] } } },
    check: (o) => { assert.equal(fval(o, 'Streams'), 2); },
  },
};

for (const [id, c] of Object.entries(CASES)) {
  test(`adapter normalize(): ${id} on a realistic response`, () => {
    const def = INTEGRATIONS[id];
    assert.ok(def, `${id} exists in the registry`);
    const out = def.normalize(c.raw, { base: 'http://x', cfg: {} });
    assert.ok(out && typeof out === 'object');
    c.check(out);
  });
}

// ── 3. declared write-actions are well-formed ─────────────────────────────
test('every declared provider action has an id, label, method and path', () => {
  const bad = [];
  for (const [id, def] of Object.entries(INTEGRATIONS)) {
    for (const a of (def.actions || [])) {
      if (!a.id || !a.label) bad.push(`${id}: action missing id/label`);
      if (!a.path || !/^\//.test(a.path)) bad.push(`${id}:${a.id}: path must be an absolute route`);
      if (a.method && !/^(GET|POST|PUT|DELETE)$/.test(a.method)) bad.push(`${id}:${a.id}: odd method ${a.method}`);
    }
  }
  assert.deepEqual(bad, []);
});

// ── 4. password hashing (scrypt + legacy fallback) ────────────────────────
test('scrypt hash round-trips and rejects the wrong password', () => {
  const h = hashPassword('correct horse battery staple');
  assert.match(h, /^scrypt\$/, 'stored as a scrypt digest, not plaintext/sha');
  assert.equal(verifyPassword('correct horse battery staple', h), true);
  assert.equal(verifyPassword('wrong', h), false);
});

test('legacy sha256 digests still verify (transparent upgrade path)', () => {
  const legacy = crypto.createHash('sha256').update('hunter2hunter2').digest('hex');
  assert.equal(verifyPassword('hunter2hunter2', legacy), true);
  assert.equal(verifyPassword('nope', legacy), false);
});

test('verifyPassword is safe on empty/garbage stored values', () => {
  assert.equal(verifyPassword('x', ''), false);
  assert.equal(verifyPassword('x', 'not-a-hash'), false);
  assert.equal(verifyPassword('x', null), false);
});

// ── 5. template substitution (used to build provider requests) ────────────
test('igApplyTpl substitutes cred/cfg/base and blanks unknown keys', () => {
  assert.equal(igApplyTpl('{{cred.key}}', { cred: { key: 'abc' } }), 'abc');
  assert.equal(igApplyTpl('{{base}}/api', { base: 'http://h:1' }), 'http://h:1/api');
  assert.equal(igApplyTpl('{{cfg.lat}},{{cfg.lon}}', { cfg: { lat: '1', lon: '2' } }), '1,2');
  assert.equal(igApplyTpl('{{cred.missing}}', { cred: {} }), '', 'unknown key -> empty, not literal');
});

test('igApplyTpl leaves single braces alone (GraphQL bodies are safe)', () => {
  assert.equal(igApplyTpl('{ info { os } }', {}), '{ info { os } }');
});

test('igApplyTpl {{enc:...}} percent-encodes for URL/form contexts', () => {
  const ctx = { cred: { username: 'ad min', password: 'p@ss&wo+rd#1' } };
  assert.equal(igApplyTpl('{{enc:cred.password}}', ctx), 'p%40ss%26wo%2Brd%231');
  assert.equal(igApplyTpl('u={{enc:cred.username}}', ctx), 'u=ad%20min');
  // raw form still passes through unencoded (correct for headers/JSON)
  assert.equal(igApplyTpl('{{cred.password}}', ctx), 'p@ss&wo+rd#1');
});

test('session-login credentials are encoded, not raw-interpolated', () => {
  // qBittorrent form body and Synology query string must use the enc: mode so a
  // password with &/+/# cannot corrupt the request (regression guard).
  const qbt = INTEGRATIONS.qbittorrent.login.body;
  assert.match(qbt, /\{\{enc:cred\.password\}\}/);
  assert.doesNotMatch(qbt, /\{\{cred\.password\}\}/, 'qBittorrent must not raw-interpolate the password');
  const syn = INTEGRATIONS.synology.login.path;
  assert.match(syn, /\{\{enc:cred\.password\}\}/);
  assert.doesNotMatch(syn, /passwd=\{\{cred\.password\}\}/, 'Synology must not raw-interpolate the password');
});

// ── 6. security response headers ──────────────────────────────────────────
test('securityHeaders always sets CSP + hardening headers', () => {
  const h = securityHeaders({ headers: {}, socket: {} });
  assert.match(h['Content-Security-Policy'], /default-src 'self'/);
  assert.match(h['Content-Security-Policy'], /frame-ancestors 'none'/);
  assert.match(h['Content-Security-Policy'], /object-src 'none'/);
  assert.equal(h['X-Frame-Options'], 'DENY');
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['Referrer-Policy'], 'same-origin');
});

test('HSTS is present only behind TLS, absent on plain HTTP', () => {
  const plain = securityHeaders({ headers: {}, socket: {} });
  assert.equal(plain['Strict-Transport-Security'], undefined);
  const tls = securityHeaders({ headers: { 'x-forwarded-proto': 'https' }, socket: {} });
  assert.match(tls['Strict-Transport-Security'], /max-age=/);
});

// ── 6a. every provider credential field is vaulted, never left in settings ──
// If a new integration introduces a credential field name that SECRET_FIELDS
// doesn't cover, that secret would be written to the plaintext settings file
// (and ride along in exports) instead of the encrypted vault. Enforce coverage.
test('SECRET_FIELDS covers every credential field name in the registry', () => {
  const missing = new Set();
  for (const def of Object.values(INTEGRATIONS)) {
    const a = def.auth || {};
    for (const k of ['field', 'userField', 'passField', 'tokenField', 'secretField']) {
      if (a[k] && !SECRET_FIELDS.has(a[k])) missing.add(a[k]);
    }
  }
  assert.deepEqual([...missing], [], 'credential fields not vaulted (would leak to plaintext settings): ' + [...missing].join(', '));
  // Dropped Needle stores a session token set outside the auth descriptor.
  assert.ok(SECRET_FIELDS.has('sessionToken'), 'sessionToken must be vaulted');
});

// ── 5b. native probes never target a loopback default ──────────────────────
// Inside a container 127.0.0.1 is the container itself — a loopback default must
// read as "not configured" (''), and the address the user gives a fleet service
// must be the address that gets probed.
test('serviceProbeBase: loopback defaults are "not configured", user addresses win', () => {
  const fs = require('node:fs');
  const sPath = path.join(process.env.DATA_DIR, 'dashboard-settings.json');
  assert.equal(isLoopbackUrl('http://127.0.0.1:30316'), true);
  assert.equal(isLoopbackUrl('http://localhost:9100'), true);
  assert.equal(isLoopbackUrl('http://192.168.50.96:9100'), false);
  // no config at all -> Tracearr's 127.0.0.1 default must NOT be probed
  fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
  fs.writeFileSync(sPath, JSON.stringify({}));
  assert.equal(serviceProbeBase('Tracearr'), '', 'loopback default -> not configured');
  // a fleet service's own host/port becomes the probe address
  fs.writeFileSync(sPath, JSON.stringify({ customServices: [{ name: 'Tracearr', host: '192.168.50.96', port: 30316 }] }));
  assert.equal(serviceProbeBase('Tracearr'), 'http://192.168.50.96:30316');
  // port 443 implies https
  fs.writeFileSync(sPath, JSON.stringify({ customServices: [{ name: 'TrueNAS Web UI', host: '192.168.50.96', port: 443 }] }));
  assert.equal(serviceProbeBase('TrueNAS Web UI'), 'https://192.168.50.96:443');
  // an explicit endpoints override beats everything
  fs.writeFileSync(sPath, JSON.stringify({ endpoints: { Tracearr: { url: 'http://10.0.0.9:30316/' } }, customServices: [{ name: 'Tracearr', host: '192.168.50.96', port: 30316 }] }));
  assert.equal(serviceProbeBase('Tracearr'), 'http://10.0.0.9:30316');
  fs.writeFileSync(sPath, JSON.stringify({}));
});

// ── 6a2. stateless session tokens: validate, survive "restart", reject forgery ──
// Sessions are signed (HMAC) not stored in memory, so they must validate purely
// from the token + key — which is what lets them survive a container restart.
test('signed session token validates, and forged/expired ones are rejected', () => {
  const req = (h) => ({ headers: { cookie: h } });
  const good = signSession(Date.now() + 3600e3);
  assert.equal(hasSession(req('cc_session=' + good)), true, 'a freshly signed token is accepted');
  assert.equal(hasSession(req('cc_session=' + good)), true, 're-validation (a "restart") still accepts it — no in-memory store');
  const [exp, sig] = good.split('.');
  assert.equal(hasSession(req('cc_session=' + exp + '.' + 'x'.repeat(sig.length))), false, 'a forged signature is rejected');
  assert.equal(hasSession(req('cc_session=' + (Date.now() - 1000) + '.' + sig)), false, 'an expired token is rejected');
  assert.equal(hasSession(req('cc_session=garbage')), false, 'a malformed token is rejected');
  assert.equal(hasSession(req('')), false, 'no cookie -> no session');
});

// ── 6b. session cookie: Secure tracks the real transport, not PUBLIC_URL ───
// Regression guard for the login-loop bug: with PUBLIC_URL=https set, a direct
// http://LAN-IP request must still get a NON-Secure cookie, or the browser drops
// it and every sign-in bounces back to the lock screen. Secure follows the
// actual transport (real TLS socket or a trusted proxy's forwarded-proto).
test('sessionCookie is HttpOnly + SameSite=Strict, and Secure only over TLS', () => {
  const http = sessionCookie({ headers: {}, socket: {} }, 'cc_session', 'tok', 3600);
  assert.match(http, /cc_session=tok/);
  assert.match(http, /HttpOnly/);
  assert.match(http, /SameSite=Lax/);   // Lax so an auth reverse-proxy's cross-site redirect keeps the session
  assert.doesNotMatch(http, /Secure/, 'a cookie returned over http:// must NOT be Secure (else it is dropped)');

  const viaProxy = sessionCookie({ headers: { 'x-forwarded-proto': 'https' }, socket: {} }, 'cc_session', 'tok', 3600);
  assert.match(viaProxy, /; Secure/, 'https behind a trusted proxy -> Secure');
  const tlsSock = sessionCookie({ headers: {}, socket: { encrypted: true } }, 'cc_session', 'tok', 3600);
  assert.match(tlsSock, /; Secure/, 'a direct TLS socket -> Secure');
});

// ── 7b. inline-script JSON escaping (stored-XSS guard) ────────────────────
test('escapeJsonForScript neutralizes a </script> breakout and round-trips', () => {
  const payload = { name: '</script><img src=x onerror=alert(document.cookie)>' };
  const safe = escapeJsonForScript(JSON.stringify(payload));
  // the escaped output must NOT contain a literal script-closer or tag open
  assert.doesNotMatch(safe, /<\/script/i, 'must not emit a literal </script');
  assert.doesNotMatch(safe, /<img/i, 'must not emit a literal <img');
  assert.ok(!safe.includes('<') && !safe.includes('>') && !safe.includes('&'), 'no raw < > & survive');
  // and it must still parse back to the exact original object
  assert.deepEqual(JSON.parse(safe), payload);
});

// ── 7c. SSRF egress guard ─────────────────────────────────────────────────
test('ipZone classifies loopback / link-local / metadata / private / public', () => {
  assert.equal(ipZone('127.0.0.1'), 'loopback');
  assert.equal(ipZone('::1'), 'loopback');
  assert.equal(ipZone('169.254.169.254'), 'linklocal');       // the classic cloud metadata IP
  assert.equal(ipZone('::ffff:169.254.169.254'), 'linklocal'); // IPv4-mapped bypass
  assert.equal(ipZone('100.100.100.200'), 'metadata');        // Alibaba
  assert.equal(ipZone('0.0.0.0'), 'unspecified');
  assert.equal(ipZone('10.0.0.5'), 'private');
  assert.equal(ipZone('192.168.1.10'), 'private');
  assert.equal(ipZone('172.16.0.1'), 'private');
  assert.equal(ipZone('8.8.8.8'), 'public');
});

test('assertFetchTarget blocks loopback/metadata for the tile proxy but allows LAN', async () => {
  // custom-tile proxy posture: no loopback, LAN allowed
  const opt = { allowLoopback: false, allowPrivate: true };
  await assert.rejects(assertFetchTarget('http://127.0.0.1:2375/containers/json', opt), /loopback/);
  await assert.rejects(assertFetchTarget('http://169.254.169.254/latest/meta-data/', opt), /linklocal/);
  await assert.rejects(assertFetchTarget('http://[::ffff:169.254.169.254]/', opt), /linklocal/);
  await assert.rejects(assertFetchTarget('http://0.0.0.0/', opt), /unspecified/);
  await assert.rejects(assertFetchTarget('ftp://192.168.1.10/', opt), /http/);
  await assert.doesNotReject(assertFetchTarget('http://192.168.1.10:9090/metrics', opt), 'LAN JSON API is allowed');
  // provider posture: loopback allowed (local Prometheus etc.), metadata still blocked
  await assert.doesNotReject(assertFetchTarget('http://127.0.0.1:9090/', { allowLoopback: true }));
  await assert.rejects(assertFetchTarget('http://169.254.169.254/', { allowLoopback: true }), /linklocal/);
});

// ── 7. secret redaction sentinel ──────────────────────────────────────────
test('the secret sentinel is a placeholder, not a real value', () => {
  assert.equal(SECRET_SENTINEL, '***');
  assert.equal(isSecretPlaceholder(SECRET_SENTINEL), true);
  assert.equal(isSecretPlaceholder('••••••••'), true);
  assert.equal(isSecretPlaceholder('a-real-api-key'), false);
});
