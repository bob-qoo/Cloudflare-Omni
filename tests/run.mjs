/**
 * Tests for the Cloudflare-Omni Worker, with a focus on the KV layer:
 * config read/write/merge, the IP library (CRUD / import / filters) and
 * the preferred-IP auto-pick, plus the admin auth rejections.
 *
 * Run: `npm test`  (or `node tests/run.mjs`)
 *
 * No test framework and no network: the Worker is imported directly,
 * `caches` is an in-memory mock, KV is a MockKV, and all subscriptions
 * under test are direct node links (no upstream fetches).
 */

import { createHash } from 'node:crypto';
import worker from '../src/index.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

class MockKV {
  constructor() {
    this.store = new Map();
  }
  async get(key, type) {
    const v = this.store.get(key);
    if (v === undefined) return null;
    if (type === 'json') return JSON.parse(v);
    return v;
  }
  async put(key, value) {
    this.store.set(key, typeof value === 'string' ? value : JSON.stringify(value));
  }
  async delete(key) {
    this.store.delete(key);
  }
  async list() {
    return { keys: [...this.store.keys()].map((name) => ({ name })) };
  }
}

// In-memory Cache API mock (the Worker only uses caches.default).
globalThis.caches = {
  default: {
    _store: new Map(),
    async match(req) {
      const key = typeof req === 'string' ? req : req.url;
      const res = this._store.get(key);
      return res ? res.clone() : undefined;
    },
    async put(req, res) {
      const key = typeof req === 'string' ? req : req.url;
      this._store.set(key, res.clone());
    },
    async delete(req) {
      const key = typeof req === 'string' ? req : req.url;
      return this._store.delete(key);
    },
  },
};

// Mock fetch for IPLIST lists and ipwho.is (geo detection). Tests register
// a URL prefix -> { status, body, contentType }; any other fetch throws so
// an unexpected upstream call surfaces immediately.
const fetchMocks = new Map();
globalThis.fetch = async (input) => {
  const url = typeof input === 'string' ? input : input.url;
  for (const [prefix, mock] of fetchMocks) {
    if (url.startsWith(prefix)) {
      return new Response(mock.body, {
        status: mock.status || 200,
        headers: { 'content-type': mock.contentType || 'text/plain' },
      });
    }
  }
  throw new Error('unexpected fetch in test: ' + url);
};

function mockFetch(prefix, body, contentType) {
  fetchMocks.set(prefix, { body, contentType: contentType || 'text/plain' });
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (e) {
    failed++;
    failures.push(name);
    console.log(`FAIL  ${name}\n      ${e.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || 'not equal'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function md5(s) {
  return createHash('md5').update(s, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Helpers to call the Worker
// ---------------------------------------------------------------------------

async function call(env, path, opts = {}) {
  const req = new Request(`https://worker.test${path}`, {
    method: opts.method || 'GET',
    headers: opts.headers || {},
    body: opts.body,
  });
  return worker.fetch(req, env, {});
}

async function callJson(env, path, opts = {}) {
  const res = await call(env, path, opts);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // not JSON (e.g. an HTML error page)
  }
  return { res, text, json };
}

function jsonOpts(body) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  };
}

// A vless node on an edgeTunnel host (used for the auto-pick tests).
const EDGE_NODE =
  'vless://550e8400-e29b-41d4-a716-446655440000@edgetunnel.example.com:443' +
  '?encryption=none&security=tls&sni=edgetunnel.example.com&type=ws&path=%2F#EdgeNode';
const PLAIN_NODE =
  'vless://550e8400-e29b-41d4-a716-446655440000@plain.example.org:443' +
  '?encryption=none&security=tls&sni=plain.example.org&type=ws&path=%2F#PlainNode';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

await test('config: GET returns env config with token masked', async () => {
  const env = { TOKEN: 'secret1', SUBNAME: 'MySub', OMNI_KV: new MockKV() };
  const { res, json } = await callJson(env, '/api/config?token=secret1');
  assertEq(res.status, 200, 'status');
  assertEq(json.ok, true, 'ok');
  assertEq(json.config.token, '********', 'token masked');
  assertEq(json.config.subname, 'MySub', 'subname from env');
  assertEq(json.kvBound, true, 'kvBound');
});

await test('config: KV overrides env, token masked, KV token is the master', async () => {
  const kv = new MockKV();
  await kv.put('config', JSON.stringify({ token: 'kvtoken', subname: 'KVName' }));
  const env = { TOKEN: 'envtoken', SUBNAME: 'EnvName', OMNI_KV: kv };
  const { json } = await callJson(env, '/api/config?token=kvtoken');
  assertEq(json.ok, true, 'admin authed with KV token');
  assertEq(json.config.token, '********', 'token masked');
  assertEq(json.config.subname, 'KVName', 'KV subname wins');
  // Subscription auth must also use the KV token, not the env one.
  const okKv = await call(env, '/sub?token=kvtoken&target=raw&nocache=1');
  assertEq(okKv.status, 200, 'sub with KV token');
  const deniedEnv = await call(env, '/sub?token=envtoken&target=raw&nocache=1');
  const deniedText = await deniedEnv.text();
  assert(!deniedText.includes('vless://'), 'env token no longer works for sub');
});

await test('config: POST saves a subset, validates subuptime and unknown fields', async () => {
  const kv = new MockKV();
  const env = { TOKEN: 'secret1', OMNI_KV: kv };
  const bad1 = await callJson(env, '/api/config?token=secret1', jsonOpts({ subuptime: 0 }));
  assertEq(bad1.res.status, 400, 'subuptime 0 rejected');
  const bad2 = await callJson(env, '/api/config?token=secret1', jsonOpts({ subuptime: 200 }));
  assertEq(bad2.res.status, 400, 'subuptime 200 rejected');
  const bad3 = await callJson(env, '/api/config?token=secret1', jsonOpts({ subuptime: 'abc' }));
  assertEq(bad3.res.status, 400, 'subuptime abc rejected');
  const bad4 = await callJson(env, '/api/config?token=secret1', jsonOpts({ nope: 'x' }));
  assertEq(bad4.res.status, 400, 'unknown field rejected');
  const good = await callJson(env, '/api/config?token=secret1', jsonOpts({ subuptime: 12, subname: 'Saved', preferIp: ['1.1.1.1', '2.2.2.2'] }));
  assertEq(good.res.status, 200, 'valid patch accepted');
  assertEq(good.json.config.subuptime, 12, 'subuptime saved');
  assertEq(good.json.config.subname, 'Saved', 'subname saved');
  assertEq(good.json.config.preferIp, '1.1.1.1,2.2.2.2', 'array preferIp joined');
  const stored = JSON.parse(await kv.get('config', 'text'));
  assertEq(stored.subuptime, 12, 'stored subuptime');
});

await test('config: POST token rotates the master token', async () => {
  const kv = new MockKV();
  const env = { TOKEN: 'oldtoken', OMNI_KV: kv };
  const r = await callJson(env, '/api/config?token=oldtoken', jsonOpts({ token: 'newtoken' }));
  assertEq(r.res.status, 200, 'token change accepted');
  assertEq(r.json.config.token, '********', 'token still masked after change');
  const oldDenied = await callJson(env, '/api/config?token=oldtoken');
  assertEq(oldDenied.res.status, 403, 'old token rejected after rotation');
  const newOk = await callJson(env, '/api/config?token=newtoken');
  assertEq(newOk.res.status, 200, 'new token works');
});

// ---------------------------------------------------------------------------
// IP library: CRUD / filters / import
// ---------------------------------------------------------------------------

await test('ips: POST replaces the library, GET returns it', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const list = [
    { ip: '1.1.1.1', region: 'HK', label: 'hk-1', latency: 42, enabled: true },
    { ip: '2.2.2.2', region: 'US', latency: 80 },
    { ip: '2001:db8::1', region: 'JP' },
  ];
  const r = await callJson(env, '/api/ips?token=secret1', jsonOpts(list));
  assertEq(r.res.status, 200, 'POST status');
  assertEq(r.json.total, 3, 'total');
  const g = await callJson(env, '/api/ips?token=secret1');
  assertEq(g.json.total, 3, 'GET total');
  assertEq(g.json.ips[0].ip, '1.1.1.1', 'first ip');
  assertEq(g.json.ips[0].region, 'HK', 'region kept');
  assertEq(g.json.ips[0].latency, 42, 'latency kept');
  assertEq(g.json.ips[1].enabled, true, 'enabled defaults to true');
  assertEq(g.json.ips[2].ip, '2001:db8::1', 'IPv6 accepted');
  assert(typeof g.json.ips[0].updatedAt === 'string', 'updatedAt filled');
});

await test('ips: POST rejects an invalid IP and dedupes', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const bad = await callJson(env, '/api/ips?token=secret1', jsonOpts([{ ip: '999.1.1.1' }]));
  assertEq(bad.res.status, 400, 'bad IPv4 rejected');
  const bad2 = await callJson(env, '/api/ips?token=secret1', jsonOpts([{ ip: 'not-an-ip' }]));
  assertEq(bad2.res.status, 400, 'garbage rejected');
  const dup = await callJson(env, '/api/ips?token=secret1', jsonOpts([
    { ip: '1.1.1.1', region: 'HK' },
    { ip: '1.1.1.1', region: 'US' },
  ]));
  assertEq(dup.res.status, 200, 'dup accepted');
  assertEq(dup.json.total, 1, 'deduped to one');
  assertEq(dup.json.ips[0].region, 'HK', 'first occurrence wins');
});

await test('ips: PUT upserts by ip, DELETE removes, missing delete is 404', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const add = await callJson(env, '/api/ips?token=secret1', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip: '1.1.1.1', region: 'HK', label: 'a' }),
  });
  assertEq(add.res.status, 200, 'PUT add');
  assertEq(add.json.updated, false, 'not an update');
  assertEq(add.json.total, 1, 'total 1');
  const upd = await callJson(env, '/api/ips?token=secret1', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip: '1.1.1.1', label: 'b', latency: 33 }),
  });
  assertEq(upd.res.status, 200, 'PUT update');
  assertEq(upd.json.updated, true, 'is an update');
  assertEq(upd.json.entry.label, 'b', 'label updated');
  assertEq(upd.json.entry.latency, 33, 'latency updated');
  assertEq(upd.json.entry.region, 'HK', 'region preserved on partial update');
  assertEq(upd.json.total, 1, 'still one entry');
  const bad = await callJson(env, '/api/ips?token=secret1', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip: 'bogus' }),
  });
  assertEq(bad.res.status, 400, 'PUT invalid ip rejected');
  const del = await callJson(env, '/api/ips?token=secret1', { method: 'DELETE' });
  assertEq(del.res.status, 400, 'DELETE without ?ip= is 400');
  const del2 = await callJson(env, '/api/ips?ip=1.1.1.1&token=secret1', { method: 'DELETE' });
  assertEq(del2.res.status, 200, 'DELETE ok');
  assertEq(del2.json.total, 0, 'empty after delete');
  const del3 = await callJson(env, '/api/ips?ip=1.1.1.1&token=secret1', { method: 'DELETE' });
  assertEq(del3.res.status, 404, 'DELETE missing ip is 404');
});

await test('ips: GET filters by region and enabled', async () => {
  const kv = new MockKV();
  await kv.put('ips', JSON.stringify([
    { ip: '1.1.1.1', region: 'HK', enabled: true },
    { ip: '2.2.2.2', region: 'HK', enabled: false },
    { ip: '3.3.3.3', region: 'US', enabled: true },
  ]));
  const env = { TOKEN: 'secret1', OMNI_KV: kv };
  const hk = await callJson(env, '/api/ips?token=secret1&region=hk');
  assertEq(hk.json.total, 2, 'region filter is case-insensitive');
  const on = await callJson(env, '/api/ips?token=secret1&enabled=1');
  assertEq(on.json.total, 2, 'enabled=1');
  const off = await callJson(env, '/api/ips?token=secret1&enabled=0');
  assertEq(off.json.total, 1, 'enabled=0');
  assertEq(off.json.ips[0].ip, '2.2.2.2', 'disabled entry');
  const both = await callJson(env, '/api/ips?token=secret1&region=HK&enabled=1');
  assertEq(both.json.total, 1, 'combined filters');
});

await test('ips: import handles all three line formats, dedupes, counts invalid', async () => {
  const kv = new MockKV();
  await kv.put('ips', JSON.stringify([{ ip: '1.1.1.1', region: 'HK', enabled: true }]));
  const env = { TOKEN: 'secret1', OMNI_KV: kv };
  const text = [
    '9.9.9.9',
    '8.8.8.8#US',
    '7.7.7.7#JP#tokyo-1',
    '1.1.1.1#HK#dup-skipped',
    'not-an-ip',
    '# a comment',
    '',
    '2001:db8::2#HK#v6',
  ].join('\n');
  const r = await callJson(env, '/api/ips/import?token=secret1', {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: text,
  });
  assertEq(r.res.status, 200, 'import status');
  assertEq(r.json.added, 4, 'added');
  assertEq(r.json.skipped, 2, 'skipped (1 dup + 1 invalid)');
  assertEq(r.json.invalid, 1, 'invalid counted');
  assertEq(r.json.total, 5, 'total after import');
  const g = await callJson(env, '/api/ips?token=secret1');
  const byIp = Object.fromEntries(g.json.ips.map((e) => [e.ip, e]));
  assertEq(byIp['8.8.8.8'].region, 'US', 'region from import');
  assertEq(byIp['7.7.7.7'].label, 'tokyo-1', 'label from import');
  assertEq(byIp['2001:db8::2'].region, 'HK', 'IPv6 import');
  assertEq(byIp['1.1.1.1'].region, 'HK', 'existing entry untouched');
});

// ---------------------------------------------------------------------------
// Preferred-IP auto-pick from the KV pool
// ---------------------------------------------------------------------------

function poolEnv(kvIps, extra = {}) {
  const kv = new MockKV();
  if (kvIps) kv.put('ips', JSON.stringify(kvIps));
  return {
    TOKEN: 'secret1',
    LINK: EDGE_NODE,
    EDGETUNNEL_HOSTS: 'edgetunnel.example.com',
    OMNI_KV: kv,
    ...extra,
  };
}

async function subRaw(env, query) {
  const res = await call(env, `/sub?token=secret1&target=raw&nocache=1${query || ''}`);
  assertEq(res.status, 200, 'sub status');
  return res.text();
}

await test('prefer: auto-pick chooses lowest-latency enabled IP', async () => {
  const env = poolEnv([
    { ip: '1.1.1.1', region: 'HK', latency: 50, enabled: true },
    { ip: '2.2.2.2', region: 'US', latency: 20, enabled: true },
    { ip: '3.3.3.3', region: 'JP', latency: 10, enabled: false },
  ]);
  const out = await subRaw(env, '');
  assert(out.includes('@2.2.2.2:443'), 'picked lowest-latency enabled IP, got: ' + out.slice(0, 120));
  // The node name is URL-encoded in the raw link, so decode before checking.
  assert(decodeURIComponent(out).includes('(优选)'), 'node marked as preferred');
  assert(out.includes('sni=edgetunnel.example.com'), 'original domain kept as SNI');
});

await test('prefer: ?region= prefers that region', async () => {
  const env = poolEnv([
    { ip: '1.1.1.1', region: 'HK', latency: 50, enabled: true },
    { ip: '2.2.2.2', region: 'US', latency: 20, enabled: true },
  ]);
  const out = await subRaw(env, '&region=HK');
  assert(out.includes('@1.1.1.1:443'), 'region HK picked, got: ' + out.slice(0, 120));
});

await test('prefer: ?region= with no match falls back to any region', async () => {
  const env = poolEnv([
    { ip: '1.1.1.1', region: 'HK', latency: 50, enabled: true },
    { ip: '2.2.2.2', region: 'US', latency: 20, enabled: true },
  ]);
  const out = await subRaw(env, '&region=SG');
  assert(out.includes('@2.2.2.2:443'), 'falls back to lowest latency overall');
});

await test('prefer: ?ip=auto ignores PREFER_IP env var', async () => {
  const env = poolEnv(
    [{ ip: '2.2.2.2', region: 'US', latency: 20, enabled: true }],
    { PREFER_IP: '9.9.9.9' },
  );
  const out = await subRaw(env, '&ip=auto');
  assert(out.includes('@2.2.2.2:443'), '?ip=auto picked from pool, ignoring PREFER_IP');
  const out2 = await subRaw(env, '');
  assert(out2.includes('@9.9.9.9:443'), 'without ?ip=auto, PREFER_IP still wins over the pool');
});

await test('prefer: explicit ?ip= wins over the pool', async () => {
  const env = poolEnv([{ ip: '2.2.2.2', region: 'US', latency: 20, enabled: true }]);
  const out = await subRaw(env, '&ip=8.8.4.4');
  assert(out.includes('@8.8.4.4:443'), 'explicit ip wins');
});

await test('prefer: empty pool means no replacement (old behaviour)', async () => {
  const env = poolEnv(null);
  const out = await subRaw(env, '');
  assert(out.includes('@edgetunnel.example.com:443'), 'server unchanged with empty pool');
  assert(!out.includes('(优选)'), 'no preferred marker');
});

await test('prefer: non-edge nodes are never rewritten', async () => {
  const kv = new MockKV();
  await kv.put('ips', JSON.stringify([{ ip: '2.2.2.2', region: 'US', latency: 20, enabled: true }]));
  const env = {
    TOKEN: 'secret1',
    LINK: PLAIN_NODE,
    EDGETUNNEL_HOSTS: 'edgetunnel.example.com',
    OMNI_KV: kv,
  };
  const out = await subRaw(env, '');
  assert(out.includes('@plain.example.org:443'), 'non-edge server untouched');
  assert(!out.includes('(优选)'), 'no preferred marker on non-edge node');
});

await test('prefer: pool entries without latency sort after ones with latency', async () => {
  const env = poolEnv([
    { ip: '1.1.1.1', region: 'HK', enabled: true },
    { ip: '2.2.2.2', region: 'US', latency: 99, enabled: true },
  ]);
  const out = await subRaw(env, '');
  assert(out.includes('@2.2.2.2:443'), 'latency entry wins over no-latency entry');
});

// ---------------------------------------------------------------------------
// Admin auth rejections
// ---------------------------------------------------------------------------

await test('admin: no TOKEN configured -> 403 TOKEN_NOT_CONFIGURED', async () => {
  const env = { OMNI_KV: new MockKV() };
  const r = await callJson(env, '/api/config');
  assertEq(r.res.status, 403, 'status');
  assertEq(r.json.error, 'TOKEN_NOT_CONFIGURED', 'error code');
  const page = await call(env, '/admin');
  assertEq(page.status, 403, 'admin page status');
  assert((await page.text()).includes('TOKEN'), 'admin 403 page mentions TOKEN');
});

await test('admin: wrong token and guest tokens are rejected for management', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const wrong = await callJson(env, '/api/config?token=nope');
  assertEq(wrong.res.status, 403, 'wrong token');
  assertEq(wrong.json.error, 'FORBIDDEN', 'wrong token error code');
  const guest = await callJson(env, `/api/config?token=${md5('secret1')}`);
  assertEq(guest.res.status, 403, 'fixed guest token rejected for admin');
  const daily = md5('secret1' + new Date().toISOString().slice(0, 10));
  const guest2 = await callJson(env, `/api/config?token=${daily}`);
  assertEq(guest2.res.status, 403, 'daily guest token rejected for admin');
  // ...but the same guest token still works for the subscription itself.
  const sub = await call(env, `/sub?token=${md5('secret1')}&target=raw&nocache=1`);
  assertEq(sub.status, 200, 'guest token still works for subscription');
});

await test('admin: Bearer header auth works', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const r = await callJson(env, '/api/config', {
    headers: { Authorization: 'Bearer secret1' },
  });
  assertEq(r.res.status, 200, 'Bearer accepted');
  const bad = await callJson(env, '/api/config', {
    headers: { Authorization: 'Bearer nope' },
  });
  assertEq(bad.res.status, 403, 'bad Bearer rejected');
});

await test('admin: /admin page renders with master token', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const r = await call(env, '/admin?token=secret1');
  assertEq(r.status, 200, 'admin page status');
  const html = await r.text();
  assert(html.includes('IP 库'), 'page mentions IP library');
  assert(html.includes('/api/config'), 'page calls the config API');
  assert(html.includes('/api/ips'), 'page calls the ips API');
});

await test('admin: no KV -> writes are 503, reads still work', async () => {
  const env = { TOKEN: 'secret1' }; // no OMNI_KV binding
  const postCfg = await callJson(env, '/api/config?token=secret1', jsonOpts({ subname: 'x' }));
  assertEq(postCfg.res.status, 503, 'POST config without KV is 503');
  assertEq(postCfg.json.error, 'KV_NOT_CONFIGURED', 'error code');
  const postIps = await callJson(env, '/api/ips?token=secret1', jsonOpts([{ ip: '1.1.1.1' }]));
  assertEq(postIps.res.status, 503, 'POST ips without KV is 503');
  const getCfg = await callJson(env, '/api/config?token=secret1');
  assertEq(getCfg.res.status, 200, 'GET config without KV still works');
  assertEq(getCfg.json.kvBound, false, 'kvBound false');
  const getIps = await callJson(env, '/api/ips?token=secret1');
  assertEq(getIps.res.status, 200, 'GET ips without KV still works');
  assertEq(getIps.json.total, 0, 'empty list without KV');
  // Subscription still works without KV (env vars only).
  const env2 = { TOKEN: 'secret1', LINK: EDGE_NODE, EDGETUNNEL_HOSTS: 'edgetunnel.example.com' };
  const out = await (await call(env2, '/sub?token=secret1&target=raw&nocache=1')).text();
  assert(out.includes('@edgetunnel.example.com:443'), 'sub works without KV, no replacement');
});

await test('admin: unknown /api route is 404', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const r = await callJson(env, '/api/nope?token=secret1');
  assertEq(r.res.status, 404, 'unknown api 404');
});

// ---------------------------------------------------------------------------
// Path-based tokens (/admin/<token> and /sub/<token>)
// ---------------------------------------------------------------------------

await test('path token: /sub/<token> serves the subscription', async () => {
  const env = poolEnv([{ ip: '2.2.2.2', region: 'US', latency: 20, enabled: true }]);
  const res = await call(env, '/sub/secret1?target=raw&nocache=1');
  assertEq(res.status, 200, 'sub via path token');
  const out = await res.text();
  assert(out.includes('vless://'), 'subscription body returned');
  const guest = await call(env, `/sub/${md5('secret1')}?target=raw&nocache=1`);
  assertEq(guest.status, 200, 'fixed guest token works in the path too');
  const bad = await call(env, '/sub/nope?target=raw&nocache=1');
  assertEq(bad.status, 200, 'wrong path token still returns a response');
  assert(!(await bad.text()).includes('vless://'), 'wrong path token shows landing page, not nodes');
});

await test('path token: /admin/<token> serves the admin page', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const r = await call(env, '/admin/secret1');
  assertEq(r.status, 200, 'admin page via path token');
  const html = await r.text();
  assert(html.includes('IP 库'), 'page mentions IP library');
  assert(html.includes('在线 IP 列表'), 'page mentions online IP lists');
  const bad = await call(env, '/admin/nope');
  assertEq(bad.status, 403, 'wrong path token is 403');
  // ?token= still works (backward compatible).
  const q = await call(env, '/admin?token=secret1');
  assertEq(q.status, 200, '?token= still works for /admin');
});

// ---------------------------------------------------------------------------
// Online IP lists (IPLIST)
// ---------------------------------------------------------------------------

await test('iplist: config GET/POST carries the iplist field', async () => {
  const kv = new MockKV();
  const env = { TOKEN: 'secret1', OMNI_KV: kv };
  const good = await callJson(env, '/api/config?token=secret1', jsonOpts({ iplist: 'https://example.com/ips.txt\nhttps://example.com/ips2.txt' }));
  assertEq(good.res.status, 200, 'iplist patch accepted');
  assertEq(good.json.config.iplist, 'https://example.com/ips.txt\nhttps://example.com/ips2.txt', 'iplist saved');
  const g = await callJson(env, '/api/config?token=secret1');
  assertEq(g.json.config.iplist, 'https://example.com/ips.txt\nhttps://example.com/ips2.txt', 'iplist round-trips');
});

await test('iplist: online list is fetched, parsed and listed by /api/ips/online', async () => {
  mockFetch('https://example.com/list-a.txt', '1.1.1.1#HK#hk-1\n2.2.2.2#US\n# a comment\nbad-line\n');
  const kv = new MockKV();
  await kv.put('config', JSON.stringify({ iplist: 'https://example.com/list-a.txt' }));
  const env = { TOKEN: 'secret1', OMNI_KV: kv };
  const r = await callJson(env, '/api/ips/online', { headers: { Authorization: 'Bearer secret1' } });
  assertEq(r.res.status, 200, 'online list status');
  assertEq(r.json.total, 2, 'two valid entries (bad line skipped)');
  assertEq(r.json.ips[0].ip, '1.1.1.1', 'first online ip');
  assertEq(r.json.ips[0].label, 'hk-1', 'online label parsed');
  assertEq(r.json.ips[0].source, 'https://example.com/list-a.txt', 'source recorded');
});

await test('iplist: auto-pick uses online IPs when the KV library is empty', async () => {
  mockFetch('https://example.com/list-b.txt', '5.5.5.5#US#us-1\n');
  const kv = new MockKV();
  await kv.put('config', JSON.stringify({ iplist: 'https://example.com/list-b.txt' }));
  const env = {
    TOKEN: 'secret1', LINK: EDGE_NODE, EDGETUNNEL_HOSTS: 'edgetunnel.example.com',
    OMNI_KV: kv,
  };
  const out = await subRaw(env, '');
  assert(out.includes('@5.5.5.5:443'), 'online IP picked, got: ' + out.slice(0, 120));
});

await test('iplist: KV entries win over online entries for the same IP', async () => {
  mockFetch('https://example.com/list-c.txt', '6.6.6.6#US\n7.7.7.7#US\n');
  const kv = new MockKV();
  await kv.put('ips', JSON.stringify([{ ip: '6.6.6.6', region: 'US', latency: 5, enabled: true }]));
  await kv.put('config', JSON.stringify({ iplist: 'https://example.com/list-c.txt' }));
  const env = {
    TOKEN: 'secret1', LINK: EDGE_NODE, EDGETUNNEL_HOSTS: 'edgetunnel.example.com',
    OMNI_KV: kv,
  };
  const out = await subRaw(env, '');
  // KV 6.6.6.6 has latency 5, online 7.7.7.7 has none: KV wins either way,
  // and the online duplicate of 6.6.6.6 must not shadow the KV entry.
  assert(out.includes('@6.6.6.6:443'), 'KV entry wins, got: ' + out.slice(0, 120));
  const r = await callJson(env, '/api/ips/online', { headers: { Authorization: 'Bearer secret1' } });
  assertEq(r.json.total, 1, 'online list excludes the IP already in KV');
  assertEq(r.json.ips[0].ip, '7.7.7.7', 'only the new online IP is listed');
});

await test('iplist: a failing list URL is skipped, not fatal', async () => {
  mockFetch('https://example.com/list-d.txt', 'not found', 'text/plain');
  fetchMocks.set('https://example.com/list-d.txt', { body: 'x', status: 404, contentType: 'text/plain' });
  const kv = new MockKV();
  await kv.put('config', JSON.stringify({ iplist: 'https://example.com/list-d.txt' }));
  const env = {
    TOKEN: 'secret1', LINK: EDGE_NODE, EDGETUNNEL_HOSTS: 'edgetunnel.example.com',
    OMNI_KV: kv,
  };
  const out = await subRaw(env, '');
  assert(out.includes('@edgetunnel.example.com:443'), 'no replacement when the list fails');
});

// ---------------------------------------------------------------------------
// IP region auto-detection (/api/ips/detect)
// ---------------------------------------------------------------------------

function mockGeo(ip, countryCode, city, flagEmoji) {
  mockFetch(`https://ipwho.is/${ip}`, JSON.stringify({
    success: true, ip, country_code: countryCode, country: countryCode === 'US' ? 'United States' : 'Japan',
    city, flag: { emoji: flagEmoji },
  }), 'application/json');
}

await test('detect: one IP returns a formatted label', async () => {
  mockGeo('104.21.0.1', 'US', 'Los Angeles', '🇺🇸');
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const r = await callJson(env, '/api/ips/detect', {
    method: 'POST',
    headers: { Authorization: 'Bearer secret1', 'content-type': 'application/json' },
    body: JSON.stringify({ ip: '104.21.0.1' }),
  });
  assertEq(r.res.status, 200, 'detect status');
  assertEq(r.json.total, 1, 'one detected');
  assertEq(r.json.detected[0].label, '🇺🇸-US-LAX-01', 'label format flag-country-city-serial');
  assertEq(r.json.detected[0].region, 'US', 'region is the country code');
  assertEq(r.json.failed.length, 0, 'nothing failed');
});

await test('detect: serial numbers increment within the same city', async () => {
  mockGeo('104.21.0.2', 'US', 'Los Angeles', '🇺🇸');
  mockGeo('104.21.0.3', 'US', 'Los Angeles', '🇺🇸');
  mockGeo('104.21.0.4', 'JP', 'Tokyo', '🇯🇵');
  const kv = new MockKV();
  await kv.put('ips', JSON.stringify([{ ip: '9.9.9.9', region: 'US', label: '🇺🇸-US-LAX-01', enabled: true }]));
  const env = { TOKEN: 'secret1', OMNI_KV: kv };
  const r = await callJson(env, '/api/ips/detect', {
    method: 'POST',
    headers: { Authorization: 'Bearer secret1', 'content-type': 'application/json' },
    body: JSON.stringify({ ips: ['104.21.0.2', '104.21.0.3', '104.21.0.4'] }),
  });
  assertEq(r.res.status, 200, 'detect status');
  assertEq(r.json.total, 3, 'three detected');
  assertEq(r.json.detected[0].label, '🇺🇸-US-LAX-02', 'second LA IP is -02 (one already in KV)');
  assertEq(r.json.detected[1].label, '🇺🇸-US-LAX-03', 'third LA IP is -03');
  assertEq(r.json.detected[2].label, '🇯🇵-JP-NRT-01', 'Tokyo starts at -01');
});

await test('detect: invalid IP and failed lookup are reported, not fatal', async () => {
  const env = { TOKEN: 'secret1', OMNI_KV: new MockKV() };
  const r = await callJson(env, '/api/ips/detect', {
    method: 'POST',
    headers: { Authorization: 'Bearer secret1', 'content-type': 'application/json' },
    body: JSON.stringify({ ips: ['not-an-ip', '203.0.113.99'] }),
  });
  assertEq(r.res.status, 200, 'detect status');
  assertEq(r.json.total, 0, 'nothing detected');
  assertEq(r.json.failed.length, 2, 'both reported as failed');
  const bad = await callJson(env, '/api/ips/detect', {
    method: 'POST',
    headers: { Authorization: 'Bearer secret1', 'content-type': 'application/json' },
    body: JSON.stringify({}),
  });
  assertEq(bad.res.status, 400, 'empty body is 400');
});

// ---------------------------------------------------------------------------
// Node naming with a detected label
// ---------------------------------------------------------------------------

await test('label: auto-picked labelled IP renames the node to its label', async () => {
  const env = poolEnv([
    { ip: '2.2.2.2', region: 'US', label: '🇺🇸-US-LAX-01', latency: 20, enabled: true },
  ]);
  const out = await subRaw(env, '');
  assert(out.includes('@2.2.2.2:443'), 'labelled IP picked');
  const decoded = decodeURIComponent(out);
  assert(decoded.includes('🇺🇸-US-LAX-01'), 'node renamed to the label, got: ' + decoded.slice(-80));
  assert(!decoded.includes('(优选)'), 'no (优选) suffix when a label is used');
});

await test('label: explicit ?ip= reuses the pool label when the IP is known', async () => {
  const env = poolEnv([
    { ip: '2.2.2.2', region: 'US', label: '🇺🇸-US-LAX-01', latency: 20, enabled: true },
  ]);
  const out = await subRaw(env, '&ip=2.2.2.2');
  assert(out.includes('@2.2.2.2:443'), 'explicit ip applied');
  assert(decodeURIComponent(out).includes('🇺🇸-US-LAX-01'), 'node renamed to the known label');
});

await test('label: unlabelled IP keeps the (优选) suffix', async () => {
  const env = poolEnv([
    { ip: '2.2.2.2', region: 'US', latency: 20, enabled: true },
  ]);
  const out = await subRaw(env, '');
  assert(decodeURIComponent(out).includes('(优选)'), 'unlabelled IP keeps the suffix');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failed tests:');
  for (const n of failures) console.log(`  - ${n}`);
  process.exit(1);
}
