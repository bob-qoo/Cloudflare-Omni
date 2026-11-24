/**
 * Cloudflare-Omni — subscription aggregator & converter on Cloudflare Workers.
 *
 * Aggregates node links and subscription URLs from env vars into one unified
 * subscription, with native output for base64 / raw / Clash / sing-box and
 * forwarding to an external converter backend (e.g. psub) for other targets.
 * For edgeTunnel nodes (Cloudflare-hosted), it can rewrite the connect
 * address to a preferred IP / domain while keeping the original TLS SNI
 * and Host header intact.
 *
 * An optional KV namespace (binding OMNI_KV) persists configuration and an
 * IP library (preferred-IP candidate pool) that can be managed from the
 * built-in admin page at /admin; without the binding the Worker still works
 * with env vars + query params only.
 *
 * No npm dependencies. Pure Worker runtime APIs only
 * (fetch, Cache, KV, crypto.subtle, TextEncoder/TextDecoder, atob/btoa).
 */

export default { fetch: handleFetch };

// ---------------------------------------------------------------------------
// Config & constants
// ---------------------------------------------------------------------------

const DEFAULT_SUBNAME = 'Cloudflare-Omni';
const DEFAULT_UPTIME_HOURS = 6;
const FETCH_TIMEOUT_MS = 8000; // per subscription fetch
const SUB_TOTAL_BYTES = 107374182400; // 100 GiB, shown in subscription-userinfo
const SUB_EXPIRE_TS = 4102444800; // 2100-01-01 00:00:00 UTC
const URLTEST_URL = 'http://www.gstatic.com/generate_204';
const SELECT_GROUP = '🚀 节点选择';
const URLTEST_GROUP = '⚡ 自动选择';

// Protocols we recognise as node links (anything else starting with
// http(s):// is treated as a subscription URL, see classifyLine).
const NODE_SCHEMES = new Set([
  'vless', 'vmess', 'trojan', 'ss', 'shadowsocks',
  'hysteria', 'hysteria2', 'hy2', 'tuic', 'snell',
  'anytls', 'wireguard', 'wg', 'socks', 'socks5', 'http', 'https',
]);

// Built-in edgeTunnel host suffixes (in addition to EDGETUNNEL_HOSTS).
const BUILTIN_EDGE_SUFFIXES = ['.trycloudflare.com', '.workers.dev'];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Split a multi-line env value into trimmed, non-empty lines. */
function splitLines(text) {
  if (!text) return [];
  return String(text)
    .split(/[\r\n]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Split a comma-separated env value into trimmed, non-empty items. */
function splitCsv(text) {
  if (!text) return [];
  return String(text)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * MD5 hex digest (lowercase).
 * Prefers WebCrypto (Cloudflare Workers supports MD5 in subtle.digest);
 * falls back to a pure-JS implementation when the runtime does not
 * (e.g. Node's WebCrypto rejects the MD5 algorithm name).
 */
async function md5Hex(text) {
  try {
    const data = new TextEncoder().encode(text);
    const buf = await crypto.subtle.digest('MD5', data);
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return md5PureJS(text);
  }
}

/** Pure-JS MD5 (RFC 1321), UTF-8 input, lowercase hex output. */
function md5PureJS(str) {
  const safeAdd = (x, y) => {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  };
  const rotl = (n, c) => (n << c) | (n >>> (32 - c));
  const cmn = (q, a, b, x, s, t) => safeAdd(rotl(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  const ff = (a, b, c, d, x, s, t) => cmn((b & c) | (~b & d), a, b, x, s, t);
  const gg = (a, b, c, d, x, s, t) => cmn((b & d) | (c & ~d), a, b, x, s, t);
  const hh = (a, b, c, d, x, s, t) => cmn(b ^ c ^ d, a, b, x, s, t);
  const ii = (a, b, c, d, x, s, t) => cmn(c ^ (b | ~d), a, b, x, s, t);

  const bytes = new TextEncoder().encode(str);
  const bitLen = bytes.length * 8;
  const totalWords = (((bitLen + 64) >>> 9) << 4) + 16;
  const x = new Array(totalWords).fill(0);
  for (let i = 0; i < bytes.length; i++) x[i >> 2] |= bytes[i] << ((i % 4) * 8);
  x[bitLen >> 5] |= 0x80 << (bitLen % 32);
  x[(((bitLen + 64) >>> 9) << 4) + 14] = bitLen;

  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < x.length; i += 16) {
    const oa = a, ob = b, oc = c, od = d;
    a = ff(a, b, c, d, x[i], 7, -680876936); d = ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = ff(c, d, a, b, x[i + 2], 17, 606105819); b = ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = ff(a, b, c, d, x[i + 4], 7, -176418897); d = ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = ff(c, d, a, b, x[i + 6], 17, -1473231341); b = ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = ff(a, b, c, d, x[i + 8], 7, 1770035416); d = ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = ff(c, d, a, b, x[i + 10], 17, -42063); b = ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = ff(a, b, c, d, x[i + 12], 7, 1804603682); d = ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = ff(c, d, a, b, x[i + 14], 17, -1502002290); b = ff(b, c, d, a, x[i + 15], 22, 1236535329);
    a = gg(a, b, c, d, x[i + 1], 5, -165796510); d = gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = gg(c, d, a, b, x[i + 11], 14, 643717713); b = gg(b, c, d, a, x[i], 20, -373897302);
    a = gg(a, b, c, d, x[i + 5], 5, -701558691); d = gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = gg(c, d, a, b, x[i + 15], 14, -660478335); b = gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = gg(a, b, c, d, x[i + 9], 5, 568446438); d = gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = gg(c, d, a, b, x[i + 3], 14, -187363961); b = gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = gg(a, b, c, d, x[i + 13], 5, -1444681467); d = gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = gg(c, d, a, b, x[i + 7], 14, 1735328473); b = gg(b, c, d, a, x[i + 12], 20, -1926607734);
    a = hh(a, b, c, d, x[i + 5], 4, -378558); d = hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = hh(c, d, a, b, x[i + 11], 16, 1839030562); b = hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = hh(a, b, c, d, x[i + 1], 4, -1530992060); d = hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = hh(c, d, a, b, x[i + 7], 16, -155497632); b = hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = hh(a, b, c, d, x[i + 13], 4, 681279174); d = hh(d, a, b, c, x[i], 11, -358537222);
    c = hh(c, d, a, b, x[i + 3], 16, -722521979); b = hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = hh(a, b, c, d, x[i + 9], 4, -640364487); d = hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = hh(c, d, a, b, x[i + 15], 16, 530742520); b = hh(b, c, d, a, x[i + 2], 23, -995338651);
    a = ii(a, b, c, d, x[i], 6, -198630844); d = ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = ii(c, d, a, b, x[i + 14], 15, -1416354905); b = ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = ii(a, b, c, d, x[i + 12], 6, 1700485571); d = ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = ii(c, d, a, b, x[i + 10], 15, -1051523); b = ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = ii(a, b, c, d, x[i + 8], 6, 1873313359); d = ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = ii(c, d, a, b, x[i + 6], 15, -1560198380); b = ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = ii(a, b, c, d, x[i + 4], 6, -145523070); d = ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = ii(c, d, a, b, x[i + 2], 15, 718787259); b = ii(b, c, d, a, x[i + 9], 21, -343485551);
    a = safeAdd(a, oa); b = safeAdd(b, ob); c = safeAdd(c, oc); d = safeAdd(d, od);
  }
  let hex = '';
  for (const w of [a, b, c, d]) {
    for (let i = 0; i < 4; i++) {
      hex += ((w >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
    }
  }
  return hex;
}

/** UTF-8 safe base64 encode (btoa only handles Latin-1). */
function b64encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/** UTF-8 safe base64 decode. Returns null on invalid input. */
function b64decode(str) {
  if (!str) return null;
  try {
    const clean = String(str).replace(/\s/g, '');
    if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
    // Tolerate URL-safe alphabet and missing padding.
    const norm = clean.replace(/-/g, '+').replace(/_/g, '/');
    const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Heuristic: does this text look like base64 that decodes to node links? */
function looksLikeBase64Sub(text) {
  const clean = String(text).trim().replace(/\s/g, '');
  if (clean.length < 8 || !/^[A-Za-z0-9+/=]+$/.test(clean)) return false;
  const decoded = b64decode(clean);
  return !!decoded && decoded.includes('://');
}

/** HTML-escape a string for the landing/dashboard pages. */
function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Parse a URL query string into a plain object without turning '+' into
 * a space (proxy links percent-encode their values, so a raw '+' is a
 * literal plus). Duplicate keys: last one wins.
 */
function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const pair of qs.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = eq >= 0 ? pair.slice(0, eq) : pair;
    const v = eq >= 0 ? pair.slice(eq + 1) : '';
    try {
      out[decodeURIComponent(k)] = decodeURIComponent(v);
    } catch {
      out[k] = v; // keep raw on malformed percent-encoding
    }
  }
  return out;
}

/** Serialize a plain object back to a query string (skips empty values). */
function stringifyQuery(params) {
  const parts = [];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return parts.join('&');
}

/**
 * Split a proxy link into its structural parts without relying on the
 * URL parser (non-standard schemes and base64 userinfo can confuse it).
 * Returns { scheme, userinfo, host, port, path, query, fragment }.
 */
function splitLink(link) {
  let rest = String(link).trim();
  let fragment = '';
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) {
    fragment = rest.slice(hashIdx + 1);
    rest = rest.slice(0, hashIdx);
  }
  let scheme = '';
  const schemeIdx = rest.indexOf('://');
  if (schemeIdx >= 0) {
    scheme = rest.slice(0, schemeIdx).toLowerCase();
    rest = rest.slice(schemeIdx + 3);
  }
  let query = '';
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) {
    query = rest.slice(qIdx + 1);
    rest = rest.slice(0, qIdx);
  }
  // rest is now [userinfo@]host[:port][/path...]
  let path = '';
  const slashIdx = rest.indexOf('/');
  if (slashIdx >= 0) {
    path = rest.slice(slashIdx);
    rest = rest.slice(0, slashIdx);
  }
  let userinfo = '';
  const atIdx = rest.lastIndexOf('@');
  let hostport = rest;
  if (atIdx >= 0) {
    userinfo = rest.slice(0, atIdx);
    hostport = rest.slice(atIdx + 1);
  }
  let host = hostport;
  let port = '';
  // IPv6 literal: [::1]:port
  const v6 = hostport.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) {
    host = v6[1];
    port = v6[2] || '';
  } else {
    const colonIdx = hostport.lastIndexOf(':');
    if (colonIdx >= 0 && /^\d+$/.test(hostport.slice(colonIdx + 1))) {
      host = hostport.slice(0, colonIdx);
      port = hostport.slice(colonIdx + 1);
    }
  }
  return { scheme, userinfo, host, port, path, query, fragment };
}

/** Decode a link fragment into a human readable node name. */
function decodeName(fragment) {
  if (!fragment) return '';
  try {
    return decodeURIComponent(fragment);
  } catch {
    return fragment;
  }
}

/** Render a YAML scalar: bare when safe, double-quoted (JSON style) otherwise. */
function yamlScalar(v) {
  if (v === null || v === undefined) return '""';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  const s = String(v);
  if (s === '') return '""';
  // Bare scalars: plain ASCII without YAML-special characters.
  if (/^[A-Za-z0-9][A-Za-z0-9._\-/:]*$/.test(s) && !/[:#]/.test(s.slice(1))) {
    return s;
  }
  return JSON.stringify(s); // valid double-quoted YAML scalar
}

/** Indent every line of a block by `n` spaces (for nested YAML). */
function indentBlock(text, n) {
  const pad = ' '.repeat(n);
  return text
    .split('\n')
    .map((line) => (line ? pad + line : line))
    .join('\n');
}

// ---------------------------------------------------------------------------
// Node model & parsing
// ---------------------------------------------------------------------------
// A normalized node keeps the original query params (URL-based protocols)
// or the decoded JSON object (vmess) as the source of truth for rebuilding
// the link, plus a parsed "view" of the fields every renderer needs.
// Nodes that are never modified are emitted via their original `raw` link,
// so parsing/rebuilding is lossless for the common case.

function newNode(protocol) {
  return {
    protocol,          // normalized protocol id
    name: '',
    server: '',
    port: 0,
    uuid: '',          // vless / vmess / trojan id
    password: '',      // trojan / ss / hy2 / tuic / anytls password, snell psk
    cipher: '',        // ss method, snell cipher
    tls: false,
    sni: '',
    host: '',          // ws / xhttp Host header
    path: '',
    type: 'tcp',       // network: tcp | ws | grpc | xhttp | h2 | httpupgrade
    alpn: '',
    fingerprint: '',
    flow: '',
    security: '',      // vless encryption / trojan security marker
    params: {},        // extra query params, preserved for link rebuild
    userinfo: '',      // raw userinfo part (reused when rebuilding)
    urlPath: '',       // path segment after host:port (usually empty)
    vmess: null,       // decoded vmess JSON object (vmess only)
    raw: '',
    modified: false,
    preferApplied: false,
  };
}

/** Fill the view fields (tls/sni/host/...) from node.params. */
function viewFromParams(node) {
  const p = node.params;
  node.tls = p.security === 'tls' || p.tls === 'tls' || node.protocol === 'trojan';
  node.sni = p.sni || p.peer || '';
  node.host = p.host || '';
  node.path = p.path || '';
  node.type = p.type || 'tcp';
  node.alpn = p.alpn || '';
  node.fingerprint = p.fp || p.fingerprint || '';
  node.flow = p.flow || '';
  node.security = p.security || p.encryption || '';
}

/** Write one view field back into params (and keep the view in sync). */
function setNodeField(node, field, value) {
  node[field] = value;
  if (node.vmess) {
    // vmess JSON keys differ from the view names.
    const map = {
      server: 'add', uuid: 'id', cipher: 'scy', type: 'net',
      fingerprint: 'fp',
    };
    if (field === 'tls') {
      node.vmess.tls = value ? 'tls' : '';
    } else if (map[field]) {
      node.vmess[map[field]] = value;
    } else if (['port', 'host', 'path', 'sni', 'alpn'].includes(field)) {
      node.vmess[field] = value;
    }
    return;
  }
  // 'tls' has no entry in keyMap below: handle it before the lookup,
  // otherwise this branch would be unreachable.
  if (field === 'tls') {
    if (value) node.params.security = 'tls';
    else if (node.params.security === 'tls') delete node.params.security;
    return;
  }
  const keyMap = {
    sni: 'sni', host: 'host', path: 'path', type: 'type',
    alpn: 'alpn', fingerprint: 'fp', flow: 'flow', security: 'security',
  };
  const key = keyMap[field];
  if (!key) return;
  if (value === '' || value === undefined || value === null) delete node.params[key];
  else node.params[key] = String(value);
}

/** URL-decode a userinfo credential, tolerating malformed input. */
function decCred(s) {
  if (!s) return '';
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Parse one proxy link into a normalized node.
 * Returns the node, or null when the link cannot be parsed.
 */
function parseNode(link) {
  if (!link || typeof link !== 'string') return null;
  const text = link.trim();
  if (!text.includes('://')) return null;
  const parts = splitLink(text);
  const scheme = parts.scheme;
  if (!NODE_SCHEMES.has(scheme)) return null;

  const params = parseQuery(parts.query);
  const name = decodeName(parts.fragment);
  const port = parts.port ? parseInt(parts.port, 10) : 0;

  // --- vmess: base64 JSON in the userinfo/host part ----------------------
  if (scheme === 'vmess') {
    // vmess://<base64-json>  (the whole authority is the payload)
    const payload = parts.userinfo ? `${parts.userinfo}@${parts.host}` : parts.host;
    const jsonText = b64decode(payload.replace(/\s/g, ''));
    if (!jsonText) return null;
    let obj;
    try {
      obj = JSON.parse(jsonText);
    } catch {
      return null;
    }
    if (!obj || typeof obj !== 'object' || !obj.add) return null;
    const node = newNode('vmess');
    node.raw = text;
    node.vmess = obj;
    node.name = obj.ps || name || '';
    node.server = String(obj.add || '');
    node.port = parseInt(obj.port, 10) || 0;
    node.uuid = String(obj.id || '');
    node.cipher = String(obj.scy || 'auto');
    node.type = String(obj.net || 'tcp');
    node.host = String(obj.host || '');
    node.path = String(obj.path || '');
    node.tls = obj.tls === 'tls';
    node.sni = String(obj.sni || '');
    node.alpn = String(obj.alpn || '');
    node.fingerprint = String(obj.fp || '');
    node.params = { aid: obj.aid, type: obj.type };
    return node;
  }

  // --- shadowsocks: two common encodings ----------------------------------
  if (scheme === 'ss' || scheme === 'shadowsocks') {
    const node = newNode('ss');
    node.raw = text;
    node.params = params;
    node.urlPath = parts.path;
    let method = '';
    let password = '';
    let server = '';
    let portNum = 0;
    // Form B: ss://<b64(method:password)>@server:port
    // Form A: ss://<b64(method:password@server:port)> (host holds the payload)
    const tryInner = (decoded) => {
      if (!decoded || !decoded.includes('@')) return false;
      const at = decoded.lastIndexOf('@');
      const creds = decoded.slice(0, at);
      const hp = decoded.slice(at + 1);
      const colon = creds.indexOf(':');
      if (colon < 0) return false;
      const hpParts = splitLink(`x://${hp}`);
      method = creds.slice(0, colon);
      password = creds.slice(colon + 1);
      server = hpParts.host;
      portNum = hpParts.port ? parseInt(hpParts.port, 10) : 0;
      return true;
    };
    if (parts.userinfo) {
      // Form B (or plaintext method:password@server:port)
      const decoded = b64decode(parts.userinfo);
      if (decoded && decoded.includes(':') && !decoded.includes('@')) {
        const colon = decoded.indexOf(':');
        method = decoded.slice(0, colon);
        password = decoded.slice(colon + 1);
      } else if (parts.userinfo.includes(':')) {
        const colon = parts.userinfo.indexOf(':');
        method = decCred(parts.userinfo.slice(0, colon));
        password = decCred(parts.userinfo.slice(colon + 1));
      } else {
        return null;
      }
      server = parts.host;
      portNum = port;
    } else {
      // Form A: the whole authority is the base64 payload.
      const decoded = b64decode(parts.host + parts.path.replace(/^\//, ''));
      if (!tryInner(decoded)) return null;
    }
    if (!method || !server || !portNum) return null;
    node.name = name;
    node.server = server;
    node.port = portNum;
    node.cipher = method;
    node.password = password;
    node.userinfo = b64encode(`${method}:${password}`).replace(/=+$/, '');
    viewFromParams(node);
    return node;
  }

  // --- snell: base64(method:psk@server:port) or plaintext psk@server:port --
  if (scheme === 'snell') {
    const node = newNode('snell');
    node.raw = text;
    node.params = params;
    let method = '';
    let psk = '';
    let server = '';
    let portNum = 0;
    if (parts.userinfo) {
      psk = decCred(parts.userinfo);
      server = parts.host;
      portNum = port;
      method = params.method || '';
    } else {
      const decoded = b64decode(parts.host);
      if (!decoded || !decoded.includes('@')) return null;
      const at = decoded.lastIndexOf('@');
      const creds = decoded.slice(0, at);
      const hp = decoded.slice(at + 1);
      const colon = creds.indexOf(':');
      if (colon < 0) return null;
      method = creds.slice(0, colon);
      psk = creds.slice(colon + 1);
      const hpParts = splitLink(`x://${hp}`);
      server = hpParts.host;
      portNum = hpParts.port ? parseInt(hpParts.port, 10) : 0;
    }
    if (!server || !portNum) return null;
    node.name = name;
    node.server = server;
    node.port = portNum;
    node.cipher = method;
    node.password = psk;
    viewFromParams(node);
    return node;
  }

  // --- generic URL-based protocols ----------------------------------------
  const node = newNode(
    scheme === 'hy2' ? 'hysteria2'
      : scheme === 'wg' ? 'wireguard'
      : scheme === 'socks' ? 'socks5'
      : scheme,
  );
  node.raw = text;
  node.params = params;
  node.userinfo = parts.userinfo;
  node.urlPath = parts.path;
  node.name = name;
  node.server = parts.host;
  node.port = port;
  if (!node.server || !node.port) return null;

  switch (node.protocol) {
    case 'vless': {
      node.uuid = decCred(parts.userinfo);
      if (!node.uuid) return null;
      break;
    }
    case 'trojan': {
      node.password = decCred(parts.userinfo);
      if (!node.password) return null;
      node.tls = true;
      break;
    }
    case 'hysteria2': {
      node.password = decCred(parts.userinfo);
      break;
    }
    case 'hysteria': {
      // hysteria://[user:pass@]server:port?auth=...&protocol=...
      if (parts.userinfo) {
        node.password = decCred(parts.userinfo);
      } else if (params.auth) {
        node.password = params.auth;
      } else if (params.authStr || params.auth_str) {
        node.password = params.authStr || params.auth_str;
      }
      break;
    }
    case 'tuic': {
      // tuic://uuid:password@server:port
      const cred = decCred(parts.userinfo);
      const colon = cred.indexOf(':');
      if (colon >= 0) {
        node.uuid = cred.slice(0, colon);
        node.password = cred.slice(colon + 1);
      } else {
        node.uuid = cred;
      }
      if (!node.uuid) return null;
      break;
    }
    case 'anytls': {
      node.password = decCred(parts.userinfo);
      break;
    }
    case 'wireguard': {
      // wireguard://privateKey@server:port?publicKey=..&address=..&...
      node.password = decCred(parts.userinfo); // private key
      break;
    }
    case 'socks5': {
      const cred = decCred(parts.userinfo);
      const colon = cred.indexOf(':');
      if (colon >= 0) {
        node.uuid = cred.slice(0, colon);
        node.password = cred.slice(colon + 1);
      }
      break;
    }
    case 'http': {
      const cred = decCred(parts.userinfo);
      const colon = cred.indexOf(':');
      if (colon >= 0) {
        node.uuid = cred.slice(0, colon);
        node.password = cred.slice(colon + 1);
      }
      break;
    }
    default:
      return null;
  }
  viewFromParams(node);
  return node;
}

// ---------------------------------------------------------------------------
// Link rebuild (only used when a node was modified, e.g. prefer replacement
// or rename; unmodified nodes are emitted via their original `raw` link)
// ---------------------------------------------------------------------------

function buildLink(node) {
  if (!node.modified && node.raw) return node.raw;
  const server = node.server.includes(':') && !node.server.startsWith('[')
    ? `[${node.server}]`
    : node.server;
  const nameFrag = node.name ? `#${encodeURIComponent(node.name)}` : '';
  const portPart = node.port ? `:${node.port}` : '';

  switch (node.protocol) {
    case 'vmess': {
      const obj = { ...node.vmess };
      obj.ps = node.name;
      obj.add = node.server;
      obj.port = String(node.port);
      return `vmess://${b64encode(JSON.stringify(obj))}`;
    }
    case 'vless': {
      const qs = stringifyQuery(node.params);
      return `vless://${encodeURIComponent(node.uuid)}@${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'trojan': {
      const qs = stringifyQuery(node.params);
      return `trojan://${encodeURIComponent(node.password)}@${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'ss': {
      const qs = stringifyQuery(node.params);
      const userinfo = b64encode(`${node.cipher}:${node.password}`).replace(/=+$/, '');
      return `ss://${userinfo}@${server}${portPart}/${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'hysteria2': {
      const qs = stringifyQuery(node.params);
      return `hysteria2://${encodeURIComponent(node.password)}@${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'hysteria': {
      const qs = stringifyQuery(node.params);
      const ui = node.userinfo ? `${node.userinfo}@` : '';
      return `hysteria://${ui}${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'tuic': {
      const qs = stringifyQuery(node.params);
      const ui = node.password
        ? `${encodeURIComponent(node.uuid)}:${encodeURIComponent(node.password)}`
        : encodeURIComponent(node.uuid);
      return `tuic://${ui}@${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'snell': {
      const qs = stringifyQuery(node.params);
      const inner = `${node.cipher}:${node.password}@${node.server}${portPart}`;
      const userinfo = b64encode(inner).replace(/=+$/, '');
      return `snell://${userinfo}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'anytls': {
      const qs = stringifyQuery(node.params);
      return `anytls://${encodeURIComponent(node.password)}@${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'wireguard': {
      const qs = stringifyQuery(node.params);
      return `wireguard://${encodeURIComponent(node.password)}@${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'socks5': {
      const qs = stringifyQuery(node.params);
      const ui = node.uuid
        ? `${encodeURIComponent(node.uuid)}${node.password ? ':' + encodeURIComponent(node.password) : ''}@`
        : '';
      return `socks5://${ui}${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    case 'http': {
      const qs = stringifyQuery(node.params);
      const ui = node.uuid
        ? `${encodeURIComponent(node.uuid)}${node.password ? ':' + encodeURIComponent(node.password) : ''}@`
        : '';
      return `http://${ui}${server}${portPart}${node.urlPath}${qs ? '?' + qs : ''}${nameFrag}`;
    }
    default:
      return node.raw || '';
  }
}

// ---------------------------------------------------------------------------
// Clash YAML input parsing (minimal indentation-based parser for the
// `proxies:` list only — enough for real-world subscription files)
// ---------------------------------------------------------------------------

function indentOf(line) {
  let n = 0;
  while (line[n] === ' ') n++;
  return n;
}

function isBlankOrComment(line) {
  const t = line.trim();
  return t === '' || t.startsWith('#');
}

/** Remove a trailing ` # comment` that is not inside quotes. */
function stripYamlComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) {
      if (line[i - 1] !== '\\') inDouble = !inDouble;
    } else if (c === '#' && !inSingle && !inDouble && i > 0 && /\s/.test(line[i - 1])) {
      return line.slice(0, i).trimEnd();
    }
  }
  return line;
}

function parseFlowList(str) {
  const inner = str.trim().slice(1, -1).trim();
  if (!inner) return [];
  const items = [];
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    if (c === ',' && !inSingle && !inDouble) {
      items.push(parseScalar(cur.trim()));
      cur = '';
    } else {
      cur += c;
    }
  }
  if (cur.trim() !== '') items.push(parseScalar(cur.trim()));
  return items;
}

function parseFlowMap(str) {
  const inner = str.trim().slice(1, -1).trim();
  const obj = {};
  if (!inner) return obj;
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  let depth = 0;
  const parts = [];
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    if (!inSingle && !inDouble) {
      if (c === '[' || c === '{') depth++;
      if (c === ']' || c === '}') depth--;
      if (c === ',' && depth === 0) {
        parts.push(cur);
        cur = '';
        continue;
      }
    }
    cur += c;
  }
  if (cur.trim() !== '') parts.push(cur);
  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim().replace(/^['"]|['"]$/g, '');
    obj[k] = parseScalar(part.slice(idx + 1).trim());
  }
  return obj;
}

function parseScalar(str) {
  const s = String(str).trim();
  if (s === '') return '';
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return parseFloat(s);
  if (s.startsWith('[') && s.endsWith(']')) return parseFlowList(s);
  if (s.startsWith('{') && s.endsWith('}')) return parseFlowMap(s);
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    try {
      return JSON.parse(s);
    } catch {
      return s.slice(1, -1);
    }
  }
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  return s;
}

/**
 * Recursive block parser. `lines` are pre-cleaned (tabs expanded, dash-map
 * items split). Returns [value, nextIndex]. `minIndent` is the smallest
 * indent this block may start at.
 */
function parseYamlBlock(lines, i, minIndent) {
  // Skip blanks/comments.
  while (i < lines.length && isBlankOrComment(lines[i])) i++;
  if (i >= lines.length) return [null, i];
  const firstIndent = indentOf(lines[i]);
  if (firstIndent < minIndent) return [null, i];
  const first = lines[i];

  if (/^\s*-\s*($|[^\s])/.test(first)) {
    // ---- LIST ----
    const listIndent = firstIndent;
    const arr = [];
    while (i < lines.length) {
      while (i < lines.length && isBlankOrComment(lines[i])) i++;
      if (i >= lines.length) break;
      const line = lines[i];
      if (indentOf(line) !== listIndent || !/^\s*-/.test(line)) break;
      const afterDash = line.slice(listIndent + 1);
      const content = afterDash.replace(/^ /, '');
      if (content.trim() === '') {
        // Bare '-': nested block follows.
        const [v, ni] = parseYamlBlock(lines, i + 1, listIndent + 1);
        arr.push(v);
        i = ni;
      } else if (/^(?:"[^"]*"|'[^']*'|[^:\s][^:]*)\s*:/.test(content)) {
        // Map item whose first key is on the dash line: rewrite it as a
        // nested map at indent+2 and parse it together with the siblings.
        // `rewritten[0]` is the synthetic line standing in for lines[i],
        // so rewritten index ni corresponds to original index i + ni.
        const rewritten = [
          ' '.repeat(listIndent + 2) + content,
          ...lines.slice(i + 1),
        ];
        const [v, ni] = parseYamlBlock(rewritten, 0, listIndent + 2);
        arr.push(v);
        i = i + ni;
      } else {
        arr.push(parseScalar(stripYamlComment(content)));
        i++;
      }
    }
    return [arr, i];
  }

  // ---- MAP ----
  const mapIndent = firstIndent;
  const obj = {};
  while (i < lines.length) {
    while (i < lines.length && isBlankOrComment(lines[i])) i++;
    if (i >= lines.length) break;
    const line = lines[i];
    if (indentOf(line) !== mapIndent) break;
    if (/^\s*-/.test(line)) break;
    const m = line.match(/^\s*([^:]+):\s*(.*)$/);
    if (!m) break;
    const key = m[1].trim().replace(/^['"]|['"]$/g, '');
    const rest = stripYamlComment(m[2]).trim();
    if (rest === '' || rest === '|' || rest === '>') {
      const [v, ni] = parseYamlBlock(lines, i + 1, mapIndent + 1);
      obj[key] = v;
      i = ni;
    } else {
      obj[key] = parseScalar(rest);
      i++;
    }
  }
  return [obj, i];
}

/** Extract the `proxies:` list from a Clash YAML document. */
function extractClashProxies(text) {
  const rawLines = String(text)
    .replace(/\t/g, '  ')
    .split(/\r?\n/);
  let start = -1;
  for (let i = 0; i < rawLines.length; i++) {
    if (/^proxies:\s*(#.*)?$/.test(rawLines[i])) {
      start = i + 1;
      break;
    }
  }
  if (start < 0) return [];
  // Collect until the next top-level key (indent 0).
  const block = [];
  for (let i = start; i < rawLines.length; i++) {
    const line = rawLines[i];
    if (line.trim() !== '' && !line.startsWith('#') && indentOf(line) === 0) break;
    block.push(line);
  }
  const [value] = parseYamlBlock(block, 0, 0);
  return Array.isArray(value) ? value : [];
}

/** Convert one Clash proxy dict into a normalized node (or null). */
function clashProxyToNode(p) {
  if (!p || typeof p !== 'object') return null;
  const type = String(p.type || '').toLowerCase();
  const protocolMap = {
    vless: 'vless', vmess: 'vmess', trojan: 'trojan',
    ss: 'ss', shadowsocks: 'ss', hysteria: 'hysteria',
    hysteria2: 'hysteria2', tuic: 'tuic', snell: 'snell',
    anytls: 'anytls', wireguard: 'wireguard',
    socks5: 'socks5', socks: 'socks5', http: 'http',
  };
  const protocol = protocolMap[type];
  if (!protocol || !p.server || !p.port) return null;

  const node = newNode(protocol);
  node.raw = '';
  node.modified = true; // rebuild links from the normalized form
  node.name = String(p.name || '');
  node.server = String(p.server);
  node.port = parseInt(p.port, 10) || 0;
  node.uuid = String(p.uuid || '');
  node.password = String(p.password || p.psk || '');
  node.cipher = String(p.cipher || '');
  node.tls = p.tls === true;
  node.sni = String(p.servername || p.sni || '');
  node.type = String(p.network || 'tcp');
  node.alpn = Array.isArray(p.alpn) ? p.alpn.join(',') : String(p.alpn || '');
  node.fingerprint = String(p['client-fingerprint'] || p.fingerprint || '');
  node.flow = String(p.flow || '');

  // Transport details (ws / grpc / xhttp / h2).
  const wsOpts = p['ws-opts'] || {};
  const grpcOpts = p['grpc-opts'] || {};
  const xhttpOpts = p['xhttp-opts'] || {};
  const headers = wsOpts.headers || xhttpOpts.headers || {};
  node.host = String(headers.Host || headers.host || p.host || '');
  node.path = String(
    wsOpts.path || xhttpOpts.path || grpcOpts['grpc-service-name'] || p.path || '',
  );
  if (node.type === 'ws' && wsOpts['early-data-header-name']) {
    node.params['eh'] = wsOpts['early-data-header-name'];
  }

  const params = {};
  if (node.tls) params.security = 'tls';
  if (node.type) params.type = node.type;
  if (node.host) params.host = node.host;
  if (node.path) params.path = node.path;
  if (node.sni) params.sni = node.sni;
  if (node.alpn) params.alpn = node.alpn;
  if (node.fingerprint) params.fp = node.fingerprint;
  if (node.flow) params.flow = node.flow;
  const reality = p['reality-opts'] || {};
  if (reality['public-key']) params.pbk = reality['public-key'];
  if (reality['short-id']) params.sid = reality['short-id'];
  if (p['skip-cert-verify']) params.allowInsecure = '1';
  if (p['packet-encoding']) params.packetEncoding = p['packet-encoding'];
  if (p['udp-over-tcp']) params.udpOverTcp = 'true';
  if (p['ip-version']) params.ipVersion = p['ip-version'];
  if (p['underlying-proxy']) params.dialerProxy = p['underlying-proxy'];

  switch (protocol) {
    case 'vmess': {
      node.cipher = String(p.cipher || 'auto');
      node.vmess = {
        v: '2', ps: node.name, add: node.server, port: String(node.port),
        id: node.uuid, aid: String(p.alterId || 0), scy: node.cipher,
        net: node.type, type: String(p['http-opts']?.method || ''),
        host: node.host, path: node.path,
        tls: node.tls ? 'tls' : '', sni: node.sni,
        alpn: node.alpn, fp: node.fingerprint,
      };
      node.params = { aid: node.vmess.aid };
      break;
    }
    case 'ss': {
      if (p.plugin) params.plugin = pluginToString(p.plugin, p['plugin-opts']);
      node.params = params;
      break;
    }
    case 'hysteria': {
      node.userinfo = node.password;
      if (p.auth_str) params.auth = p.auth_str;
      if (p.protocol) params.protocol = p.protocol;
      if (p.up) params.up = String(p.up);
      if (p.down) params.down = String(p.down);
      node.params = params;
      break;
    }
    case 'hysteria2': {
      if (p.up) params.up = String(p.up);
      if (p.down) params.down = String(p.down);
      if (p.obfs) params.obfs = p.obfs;
      if (p['obfs-password']) params.obfsPassword = p['obfs-password'];
      node.params = params;
      break;
    }
    case 'tuic': {
      if (p['congestion-controller']) params.congestion_control = p['congestion-controller'];
      if (p['udp-relay-mode']) params.udp_relay_mode = p['udp-relay-mode'];
      if (p['reduce-rtt']) params.reduce_rtt = '1';
      if (p['heartbeat-interval']) params.heartbeat_interval = String(p['heartbeat-interval']);
      node.params = params;
      break;
    }
    case 'snell': {
      if (p.version) params.version = String(p.version);
      if (p.mode) params.mode = p.mode;
      node.cipher = String(p.cipher || '');
      node.params = params;
      break;
    }
    case 'anytls': {
      node.params = params;
      break;
    }
    case 'wireguard': {
      node.password = String(p['private-key'] || '');
      params.publicKey = String(p['public-key'] || '');
      if (p['pre-shared-key']) params.presharedKey = p['pre-shared-key'];
      if (p.ip) params.address = p.ip;
      if (p.ipv6) params.address = [params.address, p.ipv6].filter(Boolean).join(',');
      if (p['allowed-ips']) params.allowedIPs = p['allowed-ips'].join(',');
      if (p['persistent-keepalive']) params.keepalive = String(p['persistent-keepalive']);
      if (p.mtu) params.mtu = String(p.mtu);
      if (p.reserved) params.reserved = p.reserved.join(',');
      node.params = params;
      break;
    }
    case 'socks5':
    case 'http': {
      node.params = params;
      break;
    }
    default: {
      node.params = params;
    }
  }
  return node;
}

function pluginToString(plugin, opts) {
  if (!plugin) return '';
  if (!opts || typeof opts !== 'object') return String(plugin);
  const kv = Object.entries(opts).map(([k, v]) => `${k}=${v}`).join(';');
  return kv ? `${plugin};${kv}` : String(plugin);
}

/** Parse a Clash YAML subscription into normalized nodes. */
function parseClashText(text) {
  const nodes = [];
  for (const proxy of extractClashProxies(text)) {
    const node = clashProxyToNode(proxy);
    if (node) nodes.push(node);
  }
  return nodes;
}

// ---------------------------------------------------------------------------
// sing-box JSON input parsing
// ---------------------------------------------------------------------------

/** Convert one sing-box outbound into a normalized node (or null). */
function singboxOutboundToNode(o) {
  if (!o || typeof o !== 'object') return null;
  const skip = new Set(['selector', 'urltest', 'direct', 'block', 'dns']);
  if (skip.has(o.type)) return null;
  const typeMap = {
    vless: 'vless', vmess: 'vmess', trojan: 'trojan',
    shadowsocks: 'ss', hysteria: 'hysteria', hysteria2: 'hysteria2',
    tuic: 'tuic', snell: 'snell', anytls: 'anytls',
    wireguard: 'wireguard', socks: 'socks5', http: 'http',
  };
  const protocol = typeMap[o.type];
  if (!protocol || !o.server || !o.server_port) return null;

  const node = newNode(protocol);
  node.raw = '';
  node.modified = true;
  node.name = String(o.tag || '');
  node.server = String(o.server);
  node.port = parseInt(o.server_port, 10) || 0;
  node.uuid = String(o.uuid || '');
  node.password = String(o.password || o.psk || '');
  node.cipher = String(o.method || '');
  const tls = o.tls || {};
  node.tls = tls.enabled === true;
  node.sni = String(tls.server_name || '');
  node.type = String(o.network || 'tcp');
  node.alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : String(tls.alpn || '');
  node.fingerprint = String(tls.utls?.fingerprint || '');
  node.flow = String(o.flow || '');

  const transport = o.transport || {};
  node.type = String(transport.type || node.type);
  if (transport.type === 'ws' || transport.type === 'httpupgrade' || transport.type === 'xhttp') {
    node.host = String(transport.headers?.Host || transport.headers?.host || '');
    node.path = String(transport.path || '');
  } else if (transport.type === 'grpc') {
    node.path = String(transport.service_name || '');
  }

  const params = {};
  if (node.tls) params.security = 'tls';
  if (node.type) params.type = node.type;
  if (node.host) params.host = node.host;
  if (node.path) params.path = node.path;
  if (node.sni) params.sni = node.sni;
  if (node.alpn) params.alpn = node.alpn;
  if (node.fingerprint) params.fp = node.fingerprint;
  if (node.flow) params.flow = node.flow;
  if (tls.insecure) params.allowInsecure = '1';
  if (tls.reality?.public_key) params.pbk = tls.reality.public_key;
  if (tls.reality?.short_id) params.sid = tls.reality.short_id;
  if (o.packet_encoding) params.packetEncoding = o.packet_encoding;
  if (o.udp_over_tcp) params.udpOverTcp = 'true';

  switch (protocol) {
    case 'vmess': {
      node.cipher = String(o.security || 'auto');
      node.vmess = {
        v: '2', ps: node.name, add: node.server, port: String(node.port),
        id: node.uuid, aid: String(o.alter_id || 0), scy: node.cipher,
        net: node.type, type: '', host: node.host, path: node.path,
        tls: node.tls ? 'tls' : '', sni: node.sni,
        alpn: node.alpn, fp: node.fingerprint,
      };
      node.params = { aid: node.vmess.aid };
      break;
    }
    case 'ss': {
      if (o.plugin) params.plugin = pluginToString(o.plugin, o.plugin_opts);
      node.params = params;
      break;
    }
    case 'hysteria': {
      node.userinfo = node.password;
      if (o.auth_str) params.auth = o.auth_str;
      if (o.up_mbps) params.up = String(o.up_mbps);
      if (o.down_mbps) params.down = String(o.down_mbps);
      node.params = params;
      break;
    }
    case 'hysteria2': {
      if (o.up_mbps) params.up = String(o.up_mbps);
      if (o.down_mbps) params.down = String(o.down_mbps);
      if (o.obfs?.type) params.obfs = o.obfs.type;
      if (o.obfs?.password) params.obfsPassword = o.obfs.password;
      node.params = params;
      break;
    }
    case 'tuic': {
      if (o.congestion_control) params.congestion_control = o.congestion_control;
      if (o.udp_relay_mode) params.udp_relay_mode = o.udp_relay_mode;
      if (o.zero_rtt_handshake) params.reduce_rtt = '1';
      if (o.heartbeat) params.heartbeat_interval = o.heartbeat;
      node.params = params;
      break;
    }
    case 'snell': {
      if (o.version) params.version = String(o.version);
      if (o.mode) params.mode = o.mode;
      node.params = params;
      break;
    }
    case 'wireguard': {
      node.password = String(o.private_key || '');
      params.publicKey = String(o.peer_public_key || '');
      if (o.pre_shared_key) params.presharedKey = o.pre_shared_key;
      if (o.local_address) params.address = o.local_address.join(',');
      if (o.mtu) params.mtu = String(o.mtu);
      if (o.persistent_keepalive) params.keepalive = String(o.persistent_keepalive);
      if (o.reserved) params.reserved = o.reserved.join(',');
      node.params = params;
      break;
    }
    default: {
      node.params = params;
    }
  }
  return node;
}

/** Parse a sing-box JSON subscription into normalized nodes. */
function parseSingboxText(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  const outbounds = doc?.outbounds;
  if (!Array.isArray(outbounds)) return [];
  const nodes = [];
  for (const o of outbounds) {
    const node = singboxOutboundToNode(o);
    if (node) nodes.push(node);
  }
  return nodes;
}

// ---------------------------------------------------------------------------
// Line classification & subscription fetching
// ---------------------------------------------------------------------------

/**
 * Classify one line from LINK / LINKSUB:
 *  - 'node': a proxy link (vless://, vmess://, ... or an http(s) proxy link)
 *  - 'sub' : an http(s) subscription URL to fetch
 *  - 'ignore': anything else
 * An http(s) URL is a proxy node only when it carries userinfo or a
 * fragment (a name) — otherwise it is a subscription URL.
 */
function classifyLine(line) {
  const t = String(line).trim();
  if (!t || t.startsWith('#')) return 'ignore';
  const schemeIdx = t.indexOf('://');
  if (schemeIdx < 0) return 'ignore';
  const scheme = t.slice(0, schemeIdx).toLowerCase();
  if (scheme === 'http' || scheme === 'https') {
    const parts = splitLink(t);
    if (parts.userinfo || parts.fragment) return 'node';
    return 'sub';
  }
  return NODE_SCHEMES.has(scheme) ? 'node' : 'ignore';
}

/** Parse a plaintext (or base64-decoded) link list into nodes. */
function parseLinkList(text) {
  const nodes = [];
  let failed = 0;
  for (const line of splitLines(text)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || !t.includes('://')) continue;
    const node = parseNode(t);
    if (node) nodes.push(node);
    else failed++;
  }
  return { nodes, failed };
}

/** Detect the format of a fetched subscription body and parse it. */
function parseSubContent(text) {
  const trimmed = String(text).trim();
  if (!trimmed) return { nodes: [], failed: 0 };

  // sing-box JSON: starts with '{' and has an outbounds array.
  if (trimmed.startsWith('{')) {
    try {
      const doc = JSON.parse(trimmed);
      if (Array.isArray(doc?.outbounds)) {
        const nodes = parseSingboxText(trimmed);
        return { nodes, failed: doc.outbounds.length - nodes.length };
      }
    } catch {
      // fall through to the other formats
    }
  }

  // Clash YAML: has a top-level `proxies:` key.
  if (/^proxies:/m.test(trimmed)) {
    const proxies = extractClashProxies(trimmed);
    const nodes = parseClashText(trimmed);
    return { nodes, failed: Math.max(0, proxies.length - nodes.length) };
  }

  // Base64-encoded link list.
  if (looksLikeBase64Sub(trimmed)) {
    const decoded = b64decode(trimmed.replace(/\s/g, ''));
    if (decoded) return parseLinkList(decoded);
  }

  // Plaintext link list.
  return parseLinkList(trimmed);
}

/** Fetch one subscription URL with a timeout. Returns text or null. */
async function fetchOneSub(url, userAgent) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': userAgent || 'Cloudflare-Omni/1.0',
        Accept: 'text/plain, */*',
      },
      redirect: 'follow',
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null; // timeout / network error: skip, never abort the whole run
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Aggregate every node from LINK (direct node links) and LINKSUB
 * (subscription URLs, fetched in parallel). Returns { nodes, stats }.
 */
async function aggregateNodes(env, request) {
  const stats = { direct: 0, subsOk: 0, subsFailed: 0, parseFailed: 0 };
  const nodes = [];

  const linkLines = splitLines(env.LINK || '');
  const subLines = splitLines(env.LINKSUB || '');
  const allLines = [...linkLines, ...subLines];

  const nodeLines = [];
  const subUrls = [];
  for (const line of allLines) {
    const kind = classifyLine(line);
    if (kind === 'node') nodeLines.push(line);
    else if (kind === 'sub') subUrls.push(line);
  }

  // Direct node links.
  for (const line of nodeLines) {
    const node = parseNode(line);
    if (node) nodes.push(node);
    else stats.parseFailed++;
  }
  stats.direct = nodes.length;

  // Subscription URLs, fetched in parallel (8s timeout each, failures skip).
  const uniqueSubs = [...new Set(subUrls)];
  if (uniqueSubs.length > 0) {
    const ua = request.headers.get('User-Agent') || '';
    const results = await Promise.allSettled(
      uniqueSubs.map((u) => fetchOneSub(u, ua)),
    );
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.status !== 'fulfilled' || !r.value) {
        stats.subsFailed++;
        continue;
      }
      const { nodes: subNodes, failed } = parseSubContent(r.value);
      stats.subsOk++;
      stats.parseFailed += failed;
      nodes.push(...subNodes);
    }
  }

  return { nodes, stats };
}

// ---------------------------------------------------------------------------
// Dedupe & edgeTunnel preferred-IP / preferred-domain replacement
// ---------------------------------------------------------------------------

/** Dedupe by protocol + server + port + credential; rename same names. */
function dedupeNodes(nodes) {
  const seen = new Set();
  const nameCount = new Map();
  const out = [];
  for (const node of nodes) {
    const cred = node.uuid || node.password || '';
    const key = `${node.protocol}|${node.server.toLowerCase()}|${node.port}|${cred}`;
    if (seen.has(key)) continue;
    seen.add(key);

    // Same display name used twice: append a numeric suffix.
    if (!node.name) node.name = `${node.protocol}-${node.server}`;
    const base = node.name;
    const count = (nameCount.get(base) || 0) + 1;
    nameCount.set(base, count);
    if (count > 1) {
      node.name = `${base} (${count})`;
      node.modified = true;
    }
    out.push(node);
  }
  return out;
}

/** Is this node hosted on an edgeTunnel (Cloudflare) endpoint? */
function isEdgeTunnel(node, edgeHosts) {
  const server = String(node.server || '').toLowerCase();
  if (!server) return false;
  for (const suffix of BUILTIN_EDGE_SUFFIXES) {
    if (server.endsWith(suffix)) return true;
  }
  for (const h of edgeHosts) {
    const host = h.toLowerCase();
    if (server === host || server.endsWith(`.${host}`)) return true;
  }
  return false;
}

/**
 * Preferred IP / domain replacement, edgeTunnel nodes only.
 * - `ip` wins as the connect address when both ip and domain are given.
 * - The original domain is kept as the TLS SNI (set when missing) and as
 *   the Host header for ws / xhttp / httpupgrade / grpc transports.
 * - When the picked IP entry carries a `label` (e.g. an auto-detected
 *   🇺🇸-US-LAX-01), the node is renamed to that label; otherwise the node
 *   keeps its name with a "(优选)" suffix.
 */
function applyPrefer(nodes, preferIp, preferDomain, edgeHosts, preferLabel) {
  const ip = (preferIp || '').trim();
  const domain = (preferDomain || '').trim();
  if (!ip && !domain) return nodes;
  const target = ip || domain;
  const label = (preferLabel || '').trim();
  const tlsProtocols = new Set([
    'vless', 'vmess', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls',
  ]);
  const hostTransports = new Set(['ws', 'xhttp', 'httpupgrade', 'grpc']);

  for (const node of nodes) {
    if (!isEdgeTunnel(node, edgeHosts)) continue;
    const originalDomain = node.server;
    if (!originalDomain || originalDomain === target) continue;
    node.server = target;
    node.modified = true;
    node.preferApplied = true;
    // Keep the original domain as TLS SNI (set it when the node has none).
    if (tlsProtocols.has(node.protocol) && !node.sni) {
      setNodeField(node, 'sni', originalDomain);
    }
    // Keep the original domain as the Host header for HTTP-based transports.
    if (hostTransports.has(node.type) && !node.host) {
      setNodeField(node, 'host', originalDomain);
    }
    if (label) {
      node.name = label;
    } else if (!node.name.endsWith('(优选)')) {
      node.name = `${node.name}(优选)`;
    }
  }
  return nodes;
}

// ---------------------------------------------------------------------------
// Output rendering
// ---------------------------------------------------------------------------

/** Resolve the output format: ?target= wins, then shorthand flags, then UA. */
function resolveTarget(url, userAgent) {
  const t = (url.searchParams.get('target') || '').trim().toLowerCase();
  if (t) return t;
  const p = url.searchParams;
  if (p.has('clash')) return 'clash';
  if (p.has('singbox') || p.has('sb')) return 'singbox';
  if (p.has('surge')) return 'surge';
  if (p.has('quanx') || p.has('quantumultx')) return 'quanx';
  if (p.has('loon')) return 'loon';
  if (p.has('b64') || p.has('base64')) return 'base64';
  if (p.has('raw')) return 'raw';
  const ua = (userAgent || '').toLowerCase();
  if (ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash')) return 'clash';
  if (ua.includes('sing-box') || ua.includes('singbox')) return 'singbox';
  if (ua.includes('surge')) return 'surge';
  if (ua.includes('quantumult')) return 'quanx';
  if (ua.includes('loon')) return 'loon';
  if (ua.includes('shadowrocket')) return 'shadowrocket';
  return 'base64';
}

/** All node links, one per line. */
function toRaw(nodes) {
  return nodes.map((n) => buildLink(n)).filter(Boolean).join('\n');
}

/** Base64-encoded node list (the default subscription format). */
function toBase64(nodes) {
  return b64encode(toRaw(nodes));
}

/** Common subscription response headers. */
function subHeaders(env, userAgent, extra = {}) {
  const uptime = parseInt(env.SUBUPTIME, 10);
  const hours = Number.isFinite(uptime) && uptime > 0 ? uptime : DEFAULT_UPTIME_HOURS;
  const headers = {
    'Profile-Update-Interval': String(hours),
    'Subscription-Userinfo':
      `upload=0; download=0; total=${SUB_TOTAL_BYTES}; expire=${SUB_EXPIRE_TS}`,
    ...extra,
  };
  // Offer a download filename to real clients, not to browsers.
  if (!String(userAgent || '').toLowerCase().includes('mozilla')) {
    const name = encodeURIComponent(env.SUBNAME || DEFAULT_SUBNAME);
    headers['Content-Disposition'] = `attachment; filename*=utf-8''${name}`;
  }
  return headers;
}

/** Transport options block shared by the Clash proxy emitters. */
function clashTransport(node) {
  const lines = [];
  const host = node.host;
  const path = node.path;
  if (node.type === 'ws' || node.type === 'httpupgrade') {
    lines.push('    ws-opts:');
    if (path) lines.push(`      path: ${yamlScalar(path)}`);
    if (host) {
      lines.push('      headers:');
      lines.push(`        Host: ${yamlScalar(host)}`);
    }
  } else if (node.type === 'grpc') {
    lines.push('    grpc-opts:');
    if (path) lines.push(`      grpc-service-name: ${yamlScalar(path)}`);
  } else if (node.type === 'xhttp') {
    lines.push('    xhttp-opts:');
    if (path) lines.push(`      path: ${yamlScalar(path)}`);
    if (host) {
      lines.push('      headers:');
      lines.push(`        Host: ${yamlScalar(host)}`);
    }
  } else if (node.type === 'h2') {
    lines.push('    h2-opts:');
    if (host) lines.push(`      host: [${yamlScalar(host)}]`);
    if (path) lines.push(`      path: ${yamlScalar(path)}`);
  }
  return lines.join('\n');
}

/** One Clash proxy entry (YAML block) for a normalized node. */
function clashProxy(node) {
  const L = [];
  L.push(`  - name: ${yamlScalar(node.name)}`);
  L.push(`    type: ${node.protocol}`);
  L.push(`    server: ${yamlScalar(node.server)}`);
  L.push(`    port: ${node.port}`);
  const allowInsecure = node.params.allowInsecure === '1';
  const alpnList = node.alpn ? node.alpn.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const tlsBlock = () => {
    if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
    if (alpnList.length) L.push(`    alpn: [${alpnList.map(yamlScalar).join(', ')}]`);
    if (node.fingerprint) L.push(`    client-fingerprint: ${yamlScalar(node.fingerprint)}`);
    if (allowInsecure) L.push('    skip-cert-verify: true');
  };

  switch (node.protocol) {
    case 'vless': {
      L.push(`    uuid: ${yamlScalar(node.uuid)}`);
      if (node.flow) L.push(`    flow: ${yamlScalar(node.flow)}`);
      L.push(`    network: ${yamlScalar(node.type)}`);
      // REALITY runs over TLS: a node with reality-opts must have tls: true,
      // otherwise mihomo rejects it with "REALITY requires TLS".
      const useTls = node.tls || !!node.params.pbk;
      L.push(`    tls: ${useTls ? 'true' : 'false'}`);
      if (useTls) {
        if (node.sni) L.push(`    servername: ${yamlScalar(node.sni)}`);
        tlsBlock();
      }
      if (node.params.pbk) {
        L.push('    reality-opts:');
        L.push(`      public-key: ${yamlScalar(node.params.pbk)}`);
        if (node.params.sid) L.push(`      short-id: ${yamlScalar(node.params.sid)}`);
      }
      if (node.params.packetEncoding) L.push(`    packet-encoding: ${yamlScalar(node.params.packetEncoding)}`);
      L.push('    udp: true');
      const t = clashTransport(node);
      if (t) L.push(t);
      break;
    }
    case 'vmess': {
      L.push(`    uuid: ${yamlScalar(node.uuid)}`);
      const aid = node.vmess?.aid ?? node.params.aid ?? 0;
      L.push(`    alterId: ${aid}`);
      L.push(`    cipher: ${yamlScalar(node.cipher || 'auto')}`);
      L.push(`    network: ${yamlScalar(node.type)}`);
      L.push(`    tls: ${node.tls ? 'true' : 'false'}`);
      if (node.tls) {
        if (node.sni) L.push(`    servername: ${yamlScalar(node.sni)}`);
        tlsBlock();
      }
      L.push('    udp: true');
      const t = clashTransport(node);
      if (t) L.push(t);
      break;
    }
    case 'trojan': {
      L.push(`    password: ${yamlScalar(node.password)}`);
      L.push(`    network: ${yamlScalar(node.type)}`);
      if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
      if (alpnList.length) L.push(`    alpn: [${alpnList.map(yamlScalar).join(', ')}]`);
      if (node.fingerprint) L.push(`    client-fingerprint: ${yamlScalar(node.fingerprint)}`);
      if (allowInsecure) L.push('    skip-cert-verify: true');
      L.push('    udp: true');
      const t = clashTransport(node);
      if (t) L.push(t);
      break;
    }
    case 'ss': {
      L.push(`    cipher: ${yamlScalar(node.cipher)}`);
      L.push(`    password: ${yamlScalar(node.password)}`);
      L.push('    udp: true');
      if (node.params.plugin) {
        const [plugin, ...rest] = node.params.plugin.split(';');
        L.push(`    plugin: ${yamlScalar(plugin)}`);
        if (rest.length) {
          L.push('    plugin-opts:');
          for (const kv of rest) {
            const eq = kv.indexOf('=');
            if (eq > 0) L.push(`      ${kv.slice(0, eq)}: ${yamlScalar(kv.slice(eq + 1))}`);
          }
        }
      }
      break;
    }
    case 'hysteria2': {
      L.push(`    password: ${yamlScalar(node.password)}`);
      if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
      if (alpnList.length) L.push(`    alpn: [${alpnList.map(yamlScalar).join(', ')}]`);
      if (node.params.up) L.push(`    up: ${yamlScalar(node.params.up)}`);
      if (node.params.down) L.push(`    down: ${yamlScalar(node.params.down)}`);
      if (node.params.obfs) L.push(`    obfs: ${yamlScalar(node.params.obfs)}`);
      if (node.params.obfsPassword) L.push(`    obfs-password: ${yamlScalar(node.params.obfsPassword)}`);
      if (allowInsecure) L.push('    skip-cert-verify: true');
      break;
    }
    case 'hysteria': {
      L.push(`    auth_str: ${yamlScalar(node.password)}`);
      if (node.params.protocol) L.push(`    protocol: ${yamlScalar(node.params.protocol)}`);
      if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
      if (alpnList.length) L.push(`    alpn: [${alpnList.map(yamlScalar).join(', ')}]`);
      if (node.params.up) L.push(`    up: ${yamlScalar(node.params.up)}`);
      if (node.params.down) L.push(`    down: ${yamlScalar(node.params.down)}`);
      if (allowInsecure) L.push('    skip-cert-verify: true');
      break;
    }
    case 'tuic': {
      L.push(`    uuid: ${yamlScalar(node.uuid)}`);
      L.push(`    password: ${yamlScalar(node.password)}`);
      if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
      if (alpnList.length) L.push(`    alpn: [${alpnList.map(yamlScalar).join(', ')}]`);
      if (node.params.congestion_control) L.push(`    congestion-controller: ${yamlScalar(node.params.congestion_control)}`);
      if (node.params.udp_relay_mode) L.push(`    udp-relay-mode: ${yamlScalar(node.params.udp_relay_mode)}`);
      if (node.params.reduce_rtt) L.push('    reduce-rtt: true');
      if (node.params.heartbeat_interval) L.push(`    heartbeat-interval: ${yamlScalar(node.params.heartbeat_interval)}`);
      if (allowInsecure) L.push('    skip-cert-verify: true');
      break;
    }
    case 'snell': {
      L.push(`    psk: ${yamlScalar(node.password)}`);
      const version = parseInt(node.params.version, 10) || 4;
      L.push(`    version: ${version}`);
      if (version === 6 && node.params.mode) L.push(`    mode: ${yamlScalar(node.params.mode)}`);
      L.push('    udp: true');
      L.push('    reuse: true');
      break;
    }
    case 'anytls': {
      L.push(`    password: ${yamlScalar(node.password)}`);
      if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
      if (alpnList.length) L.push(`    alpn: [${alpnList.map(yamlScalar).join(', ')}]`);
      if (allowInsecure) L.push('    skip-cert-verify: true');
      break;
    }
    case 'wireguard': {
      const addrs = (node.params.address || '').split(',').map((s) => s.trim()).filter(Boolean);
      const v4 = addrs.find((a) => !a.includes(':'));
      const v6 = addrs.find((a) => a.includes(':'));
      if (v4) L.push(`    ip: ${yamlScalar(v4)}`);
      if (v6) L.push(`    ipv6: ${yamlScalar(v6)}`);
      if (node.params.publicKey) L.push(`    public-key: ${yamlScalar(node.params.publicKey)}`);
      L.push(`    private-key: ${yamlScalar(node.password)}`);
      if (node.params.presharedKey) L.push(`    pre-shared-key: ${yamlScalar(node.params.presharedKey)}`);
      if (node.params.allowedIPs) {
        const ips = node.params.allowedIPs.split(',').map((s) => s.trim()).filter(Boolean);
        L.push(`    allowed-ips: [${ips.map(yamlScalar).join(', ')}]`);
      }
      if (node.params.keepalive) L.push(`    persistent-keepalive: ${node.params.keepalive}`);
      if (node.params.mtu) L.push(`    mtu: ${node.params.mtu}`);
      L.push('    udp: true');
      break;
    }
    case 'socks5': {
      if (node.uuid) L.push(`    username: ${yamlScalar(node.uuid)}`);
      if (node.password) L.push(`    password: ${yamlScalar(node.password)}`);
      if (node.tls) L.push('    tls: true');
      if (allowInsecure) L.push('    skip-cert-verify: true');
      L.push('    udp: true');
      break;
    }
    case 'http': {
      if (node.uuid) L.push(`    username: ${yamlScalar(node.uuid)}`);
      if (node.password) L.push(`    password: ${yamlScalar(node.password)}`);
      if (node.tls) L.push('    tls: true');
      if (node.sni) L.push(`    sni: ${yamlScalar(node.sni)}`);
      if (allowInsecure) L.push('    skip-cert-verify: true');
      break;
    }
    default: {
      // Unknown protocol: emit the common fields only.
      break;
    }
  }
  return L.join('\n');
}

/** Native Clash / Mihomo YAML: proxies + select + url-test + basic rules. */
function toClash(nodes) {
  const names = nodes.map((n) => n.name);
  const lines = [];
  lines.push('# Generated by Cloudflare-Omni');
  lines.push('mixed-port: 7890');
  lines.push('allow-lan: false');
  lines.push('mode: rule');
  lines.push('log-level: info');
  lines.push('ipv6: true');
  lines.push('dns:');
  lines.push('  enable: true');
  lines.push('  nameserver:');
  lines.push('    - 223.5.5.5');
  lines.push('    - 8.8.8.8');
  lines.push('proxies:');
  for (const node of nodes) lines.push(clashProxy(node));
  lines.push('proxy-groups:');
  lines.push(`  - name: ${yamlScalar(SELECT_GROUP)}`);
  lines.push('    type: select');
  lines.push('    proxies:');
  for (const n of names) lines.push(`      - ${yamlScalar(n)}`);
  lines.push(`      - ${yamlScalar(URLTEST_GROUP)}`);
  lines.push(`  - name: ${yamlScalar(URLTEST_GROUP)}`);
  lines.push('    type: url-test');
  lines.push(`    url: ${URLTEST_URL}`);
  lines.push('    interval: 300');
  lines.push('    tolerance: 50');
  lines.push('    proxies:');
  for (const n of names) lines.push(`      - ${yamlScalar(n)}`);
  lines.push('rules:');
  lines.push('  - GEOSITE,category-ads-all,REJECT');
  lines.push('  - GEOSITE,cn,DIRECT');
  lines.push('  - GEOIP,CN,DIRECT');
  lines.push('  - GEOIP,private,DIRECT');
  lines.push(`  - MATCH,${SELECT_GROUP}`);
  return lines.join('\n') + '\n';
}

// --- sing-box outbounds ----------------------------------------------------

/** sing-box transport object for a normalized node (or undefined). */
function singboxTransport(node) {
  const headers = node.host ? { Host: node.host } : undefined;
  switch (node.type) {
    case 'ws':
      return { type: 'ws', path: node.path || '/', headers };
    case 'grpc':
      return { type: 'grpc', service_name: node.path || '' };
    case 'xhttp':
      return { type: 'xhttp', path: node.path || '/', headers };
    case 'httpupgrade':
      return { type: 'httpupgrade', path: node.path || '/', headers };
    case 'h2':
      return { type: 'http', path: node.path || '/', headers };
    default:
      return undefined;
  }
}

/** sing-box TLS object for a normalized node (or undefined). */
function singboxTls(node) {
  // REALITY runs over TLS: a node with a reality public key needs the tls
  // block even when node.tls is false, otherwise the reality info is lost.
  if (!node.tls && !node.params.pbk) return undefined;
  const tls = { enabled: true };
  if (node.sni) tls.server_name = node.sni;
  if (node.params.allowInsecure === '1') tls.insecure = true;
  if (node.alpn) tls.alpn = node.alpn.split(',').map((s) => s.trim()).filter(Boolean);
  if (node.fingerprint) tls.utls = { enabled: true, fingerprint: node.fingerprint };
  if (node.params.pbk) {
    tls.reality = {
      enabled: true,
      public_key: node.params.pbk,
      short_id: node.params.sid || '',
    };
  }
  return tls;
}

/** One sing-box outbound object for a normalized node (or null). */
function singboxOutbound(node) {
  const base = { tag: node.name, server: node.server, server_port: node.port };
  const transport = singboxTransport(node);
  const tls = singboxTls(node);
  const withNet = (obj) => {
    if (node.type && node.type !== 'tcp') obj.network = node.type;
    return obj;
  };
  switch (node.protocol) {
    case 'vless': {
      const o = { type: 'vless', ...base, uuid: node.uuid };
      if (node.flow) o.flow = node.flow;
      if (node.params.packetEncoding) o.packet_encoding = node.params.packetEncoding;
      if (transport) o.transport = transport;
      if (tls) o.tls = tls;
      return withNet(o);
    }
    case 'vmess': {
      const o = {
        type: 'vmess', ...base, uuid: node.uuid,
        alter_id: parseInt(node.vmess?.aid ?? node.params.aid ?? 0, 10) || 0,
        security: node.cipher || 'auto',
      };
      if (transport) o.transport = transport;
      if (tls) o.tls = tls;
      return withNet(o);
    }
    case 'trojan': {
      const o = { type: 'trojan', ...base, password: node.password };
      if (transport) o.transport = transport;
      if (tls) o.tls = tls;
      return withNet(o);
    }
    case 'ss': {
      const o = {
        type: 'shadowsocks', ...base,
        method: node.cipher, password: node.password,
      };
      if (node.params.udpOverTcp === 'true') o.udp_over_tcp = true;
      if (node.params.plugin) {
        const [plugin, ...rest] = node.params.plugin.split(';');
        o.plugin = plugin;
        if (rest.length) o.plugin_opts = rest.join(';');
      }
      return o;
    }
    case 'hysteria2': {
      const o = { type: 'hysteria2', ...base, password: node.password };
      if (tls) o.tls = tls;
      if (node.params.obfs) o.obfs = { type: node.params.obfs, password: node.params.obfsPassword || '' };
      if (node.params.up) o.up_mbps = parseInt(node.params.up, 10) || undefined;
      if (node.params.down) o.down_mbps = parseInt(node.params.down, 10) || undefined;
      return o;
    }
    case 'hysteria': {
      const o = { type: 'hysteria', ...base, version: 1, auth_str: node.password };
      if (tls) o.tls = tls;
      if (node.params.up) o.up_mbps = parseInt(node.params.up, 10) || undefined;
      if (node.params.down) o.down_mbps = parseInt(node.params.down, 10) || undefined;
      return o;
    }
    case 'tuic': {
      const o = { type: 'tuic', ...base, uuid: node.uuid, password: node.password };
      if (tls) o.tls = tls;
      if (node.params.congestion_control) o.congestion_control = node.params.congestion_control;
      if (node.params.udp_relay_mode) o.udp_relay_mode = node.params.udp_relay_mode;
      if (node.params.reduce_rtt) o.zero_rtt_handshake = true;
      if (node.params.heartbeat_interval) o.heartbeat = node.params.heartbeat_interval;
      return o;
    }
    case 'snell': {
      const o = {
        type: 'snell', ...base, psk: node.password,
        version: parseInt(node.params.version, 10) || 4,
      };
      if (o.version === 6 && node.params.mode) o.mode = node.params.mode;
      return o;
    }
    case 'anytls': {
      const o = { type: 'anytls', ...base, password: node.password };
      if (tls) o.tls = tls;
      return o;
    }
    case 'wireguard': {
      const o = {
        type: 'wireguard', ...base,
        local_address: (node.params.address || '').split(',').map((s) => s.trim()).filter(Boolean),
        private_key: node.password,
        peer_public_key: node.params.publicKey || '',
      };
      if (node.params.presharedKey) o.pre_shared_key = node.params.presharedKey;
      if (node.params.mtu) o.mtu = parseInt(node.params.mtu, 10) || undefined;
      if (node.params.keepalive) o.persistent_keepalive = parseInt(node.params.keepalive, 10) || undefined;
      if (node.params.reserved) o.reserved = node.params.reserved.split(',').map((s) => parseInt(s.trim(), 10));
      return o;
    }
    case 'socks5': {
      const o = { type: 'socks', ...base, version: '5' };
      if (node.uuid) o.username = node.uuid;
      if (node.password) o.password = node.password;
      return o;
    }
    case 'http': {
      const o = { type: 'http', ...base };
      if (node.uuid) o.username = node.uuid;
      if (node.password) o.password = node.password;
      if (tls) o.tls = tls;
      return o;
    }
    default:
      return null;
  }
}

/** Native sing-box JSON: node outbounds + selector + urltest + direct + block. */
function toSingbox(nodes) {
  const outbounds = [];
  for (const node of nodes) {
    const o = singboxOutbound(node);
    if (o) outbounds.push(o);
  }
  const names = outbounds.map((o) => o.tag);
  outbounds.push({
    type: 'selector', tag: SELECT_GROUP,
    outbounds: [...names, URLTEST_GROUP],
    default: names[0] || 'direct',
  });
  outbounds.push({
    type: 'urltest', tag: URLTEST_GROUP,
    outbounds: names, url: URLTEST_URL, interval: '5m', tolerance: 50,
  });
  outbounds.push({ type: 'direct', tag: 'direct' });
  outbounds.push({ type: 'block', tag: 'block' });

  const doc = {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { tag: 'dns-remote', address: 'tls://8.8.8.8' },
        { tag: 'dns-direct', address: '223.5.5.5', detour: 'direct' },
      ],
      rules: [
        { outbound: 'any', server: 'dns-direct', domain_suffix: ['.cn'] },
      ],
      final: 'dns-remote',
    },
    // No local listeners: this is a pure outbound subscription.
    inbounds: [],
    outbounds,
    route: {
      rules: [
        { action: 'route', outbound: 'block', geosite: 'category-ads-all' },
        { action: 'route', outbound: 'direct', geosite: 'cn' },
        { action: 'route', outbound: 'direct', geoip: ['cn', 'private'] },
      ],
      final: SELECT_GROUP,
    },
  };
  return JSON.stringify(doc, null, 2);
}

// --- external converter backend (e.g. self-hosted psub) --------------------

/** Normalize a SUBAPI value to a base URL (default scheme https). */
function normalizeSubApi(subapi) {
  let api = String(subapi || '').trim().replace(/\/+$/, '');
  if (!api) return '';
  if (!/^https?:\/\//i.test(api)) api = `https://${api}`;
  return api;
}

/**
 * Forward the aggregated subscription to an external converter backend.
 * Returns { body, contentType } or null when the backend is unusable.
 */
async function forwardToConverter(target, selfUrl, env, userAgent) {
  const api = normalizeSubApi(env.SUBAPI);
  if (!api) return null;
  const targetMap = {
    surge: 'surge', quanx: 'quanx', quantumultx: 'quanx',
    loon: 'loon', shadowrocket: 'shadowrocket',
    clash: 'clash', singbox: 'singbox', mixed: 'mixed',
  };
  const t = targetMap[target] || target;
  const q = new URLSearchParams({
    target: t,
    url: selfUrl,
    insert: 'false',
    emoji: 'false',
    list: 'false',
    tfo: 'false',
    scv: 'true',
    fdn: 'false',
    sort: 'false',
    new_name: 'true',
  });
  if (t === 'surge') q.set('ver', '4');
  if (t === 'quanx') q.set('udp', 'true');
  const convUrl = `${api}/sub?${q.toString()}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(convUrl, {
      signal: controller.signal,
      headers: { 'User-Agent': userAgent || 'Cloudflare-Omni/1.0' },
    });
    if (!res.ok) return null;
    const body = await res.text();
    if (!body || !body.trim()) return null;
    return {
      body,
      contentType: res.headers.get('content-type') || 'text/plain; charset=utf-8',
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/**
 * Build the set of accepted tokens for this request:
 *  - the master TOKEN itself
 *  - a fixed guest token: MD5(TOKEN)
 *  - a daily guest token: MD5(TOKEN + UTC date "YYYY-MM-DD"), rotates daily
 * Returns { all:Set, master, fixed, daily }.
 */
async function buildTokens(master) {
  const fixed = await md5Hex(master);
  const date = new Date().toISOString().slice(0, 10); // UTC date
  const daily = await md5Hex(master + date);
  return { all: new Set([master, fixed, daily]), master, fixed, daily };
}

/**
 * Token carried in the URL path: /admin/<token> or /sub/<token>, or the
 * token as the first path segment (/<token>). Returns the decoded token
 * or ''. A token is any run of characters that are not URL-special
 * (letters, digits, '-', '_', '.', '~'); anything else must be
 * percent-encoded by the caller and is decoded here.
 */
function pathToken(url, prefix) {
  const parts = url.pathname.split('/').filter(Boolean);
  if (prefix && parts.length >= 2 && parts[0] === prefix) {
    try {
      return decodeURIComponent(parts[1]);
    } catch {
      return parts[1] || '';
    }
  }
  return '';
}

/** Accept ?token=... or a token as the first path segment (/<token>). */
function isAuthorized(url, tokens) {
  const q = url.searchParams.get('token');
  if (q && tokens.all.has(q)) return true;
  const seg = url.pathname.split('/').filter(Boolean)[0];
  if (seg && tokens.all.has(decodeURIComponent(seg))) return true;
  const subSeg = pathToken(url, 'sub');
  if (subSeg && tokens.all.has(subSeg)) return true;
  const adminSeg = pathToken(url, 'admin');
  if (adminSeg && tokens.all.has(adminSeg)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// KV storage (OMNI_KV): persistent config + IP library
// ---------------------------------------------------------------------------
// The binding is optional: when env.OMNI_KV is absent, every KV read
// returns an empty value and every KV write is skipped (logged, never
// fatal), so the Worker keeps working with env vars + query params only.
//   KV key "config": JSON object, keys are the lowercase config fields.
//   KV key "ips":    JSON array of {ip, region, label, latency, enabled,
//                     updatedAt}.

const KV_CONFIG_KEY = 'config';
const KV_IPS_KEY = 'ips';
const TOKEN_MASK = '********';

/** KV key <-> env var name map for the config object. */
const CONFIG_FIELDS = [
  { kv: 'token', env: 'TOKEN' },
  { kv: 'link', env: 'LINK' },
  { kv: 'linksub', env: 'LINKSUB' },
  { kv: 'subapi', env: 'SUBAPI' },
  { kv: 'subname', env: 'SUBNAME' },
  { kv: 'subuptime', env: 'SUBUPTIME' },
  { kv: 'preferIp', env: 'PREFER_IP' },
  { kv: 'preferDomain', env: 'PREFER_DOMAIN' },
  { kv: 'edgetunnelHosts', env: 'EDGETUNNEL_HOSTS' },
  { kv: 'iplist', env: 'IPLIST' },
];

/** Safe KV read: null when unbound, missing, or on error (never throws). */
async function kvGet(env, key) {
  const kv = env?.OMNI_KV;
  if (!kv) return null;
  try {
    return await kv.get(key, 'text');
  } catch (e) {
    console.error(`[omni] KV get ${key} failed:`, e);
    return null;
  }
}

/** Safe KV write: false when unbound or on error (never throws). */
async function kvPut(env, key, value) {
  const kv = env?.OMNI_KV;
  if (!kv) return false;
  try {
    await kv.put(key, value);
    return true;
  } catch (e) {
    console.error(`[omni] KV put ${key} failed:`, e);
    return false;
  }
}

/** Load the KV config object ({} when unbound / missing / invalid). */
async function loadKvConfig(env) {
  const raw = await kvGet(env, KV_CONFIG_KEY);
  if (!raw) return {};
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
  } catch {
    console.error('[omni] KV config is not valid JSON, ignoring it');
    return {};
  }
}

/** Load the KV IP library array ([] when unbound / missing / invalid). */
async function loadKvIps(env) {
  const raw = await kvGet(env, KV_IPS_KEY);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    console.error('[omni] KV ips is not valid JSON, ignoring it');
    return [];
  }
}

/** Persist the KV config object. False when KV is unbound / fails. */
async function saveKvConfig(env, obj) {
  return kvPut(env, KV_CONFIG_KEY, JSON.stringify(obj));
}

/** Persist the KV IP library array. False when KV is unbound / fails. */
async function saveKvIps(env, list) {
  return kvPut(env, KV_IPS_KEY, JSON.stringify(list));
}

/**
 * Normalize one config value to a string (KV may store numbers / arrays).
 * Arrays join with '\n' for link/linksub and ',' for everything else.
 */
function normalizeConfigValue(kvKey, kvVal, envVal) {
  let v = kvVal;
  if (v === undefined || v === null || v === '') v = envVal;
  if (v === undefined || v === null) v = '';
  if (Array.isArray(v)) {
    v = (kvKey === 'link' || kvKey === 'linksub' || kvKey === 'iplist') ? v.join('\n') : v.join(',');
  }
  return String(v);
}

/**
 * Effective config: KV config wins over env vars, env wins over defaults.
 * Returns a plain object keyed by the env-var names (TOKEN, LINK, ...),
 * so the existing pipeline can use it wherever it used `env`.
 */
async function resolveEffectiveConfig(env) {
  const kvCfg = await loadKvConfig(env);
  const cfg = {};
  for (const { kv, env: envKey } of CONFIG_FIELDS) {
    cfg[envKey] = normalizeConfigValue(kv, kvCfg[kv], env[envKey]);
  }
  return cfg;
}

/** Mask a token for API responses (never echo the real value). */
function maskToken(token) {
  return token ? TOKEN_MASK : '';
}

/** Effective config in KV field names, token masked (for GET /api/config). */
function effectiveConfigForApi(cfg) {
  const out = {};
  for (const { kv, env: envKey } of CONFIG_FIELDS) {
    out[kv] = cfg[envKey] ?? '';
  }
  out.token = maskToken(out.token);
  out.subname = out.subname || DEFAULT_SUBNAME;
  const n = parseInt(out.subuptime, 10);
  out.subuptime = Number.isFinite(n) ? n : DEFAULT_UPTIME_HOURS;
  return out;
}

// --- IP library ------------------------------------------------------------

function isValidIpv4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  return m.slice(1).every((oct) => Number(oct) >= 0 && Number(oct) <= 255);
}

function isValidIpv6(ip) {
  if (!ip || typeof ip !== 'string' || ip.includes(' ')) return false;
  let s = ip;
  // IPv4-mapped tail (::ffff:1.2.3.4): validate the v4 part, then treat it
  // as two groups for the group-count check.
  if (s.includes('.')) {
    const lastColon = s.lastIndexOf(':');
    if (lastColon < 0) return false;
    if (!isValidIpv4(s.slice(lastColon + 1))) return false;
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  if (s.includes('::')) {
    if (s.indexOf('::') !== s.lastIndexOf('::')) return false;
    const [left, right] = s.split('::');
    const lg = left ? left.split(':') : [];
    const rg = right ? right.split(':') : [];
    if (lg.length + rg.length > 7) return false;
    return [...lg, ...rg].every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
  }
  const groups = s.split(':');
  if (groups.length !== 8) return false;
  return groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
}

function isValidIp(ip) {
  return isValidIpv4(ip) || isValidIpv6(ip);
}

/**
 * Normalize one IP entry. `base` is the existing entry when updating
 * (fields not present in `raw` are preserved). Returns null when invalid.
 */
function normalizeIpEntry(raw, base) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const merged = { ...(base || {}), ...raw };
  const ip = String(merged.ip || '').trim();
  if (!isValidIp(ip)) return null;
  const entry = {
    ip,
    region: String(merged.region || '').trim(),
    label: String(merged.label || '').trim(),
    latency: null,
    enabled: true,
    updatedAt: new Date().toISOString(),
  };
  if (merged.latency !== undefined && merged.latency !== null && merged.latency !== '') {
    const n = Number(merged.latency);
    if (Number.isFinite(n) && n >= 0) entry.latency = n;
  }
  if (typeof merged.enabled === 'boolean') entry.enabled = merged.enabled;
  else if (merged.enabled === 0 || merged.enabled === '0' || merged.enabled === 'false') entry.enabled = false;
  else if (merged.enabled === 1 || merged.enabled === '1' || merged.enabled === 'true') entry.enabled = true;
  if (merged.updatedAt && !isNaN(Date.parse(merged.updatedAt))) {
    entry.updatedAt = new Date(merged.updatedAt).toISOString();
  }
  return entry;
}

/** Dedupe an IP list by address (case-insensitive), first occurrence wins. */
function dedupeIpList(list) {
  const seen = new Set();
  const out = [];
  for (const e of list) {
    if (!e || !e.ip) continue;
    const key = String(e.ip).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

/**
 * Pick the best IP entry from the pool: only enabled entries; prefer the
 * given region (falls back to any region when it has no entries); lowest
 * latency first, entries without latency last (stable order). Returns the
 * entry object, or null when the pool is empty.
 */
function pickPreferredIpEntry(pool, region) {
  if (!Array.isArray(pool) || pool.length === 0) return null;
  const enabled = pool.filter((e) => e && e.ip && e.enabled !== false);
  if (enabled.length === 0) return null;
  const want = String(region || '').trim().toLowerCase();
  let candidates = enabled;
  if (want) {
    const inRegion = enabled.filter((e) => String(e.region || '').toLowerCase() === want);
    if (inRegion.length > 0) candidates = inRegion;
  }
  const sorted = [...candidates].sort((a, b) => {
    const la = typeof a.latency === 'number' ? a.latency : Infinity;
    const lb = typeof b.latency === 'number' ? b.latency : Infinity;
    return la - lb;
  });
  return sorted[0] || null;
}

/**
 * Pick the best IP from the pool: only enabled entries; prefer the given
 * region (falls back to any region when it has no entries); lowest latency
 * first, entries without latency last (stable order). Returns '' when empty.
 */
function pickPreferredIp(pool, region) {
  const entry = pickPreferredIpEntry(pool, region);
  return entry ? entry.ip || '' : '';
}

// --- Online IP lists (IPLIST) ----------------------------------------------

/** Cache TTL for a fetched online IP list, in seconds (1 hour). */
const IPLIST_CACHE_TTL = 3600;

/**
 * Fetch one online IP list URL and parse it. Each line is `ip`,
 * `ip#region` or `ip#region#label` (same as the bulk-import format).
 * Results are cached in the Cache API for IPLIST_CACHE_TTL so a
 * subscription request does not refetch the list every time. Returns an
 * array of entries (each with a `source` field = the list URL), or [] on
 * any failure. Never throws.
 */
async function fetchOnlineIpList(listUrl) {
  const url = String(listUrl || '').trim();
  if (!url) return [];
  const cacheKey = new Request(`https://omni.local/iplist?url=${encodeURIComponent(url)}`, { method: 'GET' });
  try {
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      const text = await cached.text();
      return parseIpImportText(text)
        .map((e) => normalizeIpEntry(e, null))
        .filter(Boolean)
        .map((e) => ({ ...e, source: url }));
    }
  } catch {
    // Cache unavailable: fall through to a live fetch.
  }
  let text = '';
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, { signal: ctrl.signal, headers: { 'user-agent': 'Cloudflare-Omni' } });
      if (!res.ok) return [];
      text = await res.text();
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return [];
  }
  try {
    const res = new Response(text, { headers: { 'cache-control': `public, max-age=${IPLIST_CACHE_TTL}` } });
    await caches.default.put(cacheKey, res.clone());
  } catch {
    // Caching is best-effort; the parsed list is still usable.
  }
  return parseIpImportText(text)
    .map((e) => normalizeIpEntry(e, null))
    .filter(Boolean)
    .map((e) => ({ ...e, source: url }));
}

/**
 * Load every online IP list named by cfg.IPLIST (one URL per line) and
 * merge the entries. KV entries win over online entries for the same IP.
 * Returns the merged, deduped pool. Never throws.
 */
async function loadOnlineIps(cfg, kvPool) {
  const urls = splitLines(cfg.IPLIST || '');
  if (urls.length === 0) return [];
  const lists = await Promise.all(urls.map((u) => fetchOnlineIpList(u)));
  const online = lists.flat();
  const kvIps = new Set((kvPool || []).map((e) => String(e.ip || '').toLowerCase()));
  return dedupeIpList(online.filter((e) => e && e.ip && !kvIps.has(String(e.ip).toLowerCase())));
}

/**
 * The full preferred-IP candidate pool: KV library entries first, then
 * online-list entries (KV wins on duplicate IPs). Never throws.
 */
async function loadPreferredIpPool(env, cfg) {
  const kvPool = await loadKvIps(env);
  let online = [];
  try {
    online = await loadOnlineIps(cfg, kvPool);
  } catch {
    online = [];
  }
  return dedupeIpList([...kvPool, ...online]);
}

// --- IP geolocation (auto region detection) --------------------------------

/**
 * Free geolocation providers, tried in order until one answers. Each
 * entry normalises its provider's JSON to
 * { countryCode, country, city, flag }. Cloudflare's egress IPs are
 * blocked by some free geo services, so a single provider is not
 * reliable enough on its own.
 */
const GEO_PROVIDERS = [
  {
    name: 'ipwho.is',
    url: (ip) => `https://ipwho.is/${encodeURIComponent(ip)}`,
    parse: (d) => {
      if (!d || d.success === false) return null;
      const countryCode = String(d.country_code || '').trim().toUpperCase();
      const city = String(d.city || '').trim();
      if (!countryCode || !city) return null;
      const flag = (d.flag && d.flag.emoji) ? String(d.flag.emoji) : flagEmoji(countryCode);
      return { countryCode, country: String(d.country || '').trim(), city, flag };
    },
  },
  {
    name: 'ipapi.co',
    url: (ip) => `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
    parse: (d) => {
      if (!d || d.error) return null;
      const countryCode = String(d.country_code || '').trim().toUpperCase();
      const city = String(d.city || '').trim();
      if (!countryCode || !city) return null;
      return { countryCode, country: String(d.country_name || '').trim(), city, flag: flagEmoji(countryCode) };
    },
  },
  {
    name: 'ipinfo.io',
    url: (ip) => `https://ipinfo.io/${encodeURIComponent(ip)}/json`,
    parse: (d) => {
      if (!d || d.bogon) return null;
      const countryCode = String(d.country || '').trim().toUpperCase();
      const city = String(d.city || '').trim();
      if (!countryCode || !city) return null;
      return { countryCode, country: '', city, flag: flagEmoji(countryCode) };
    },
  },
];

/**
 * Look up one IP's location, trying each free provider in turn. Returns
 * { countryCode, country, city, flag } or null when every provider fails.
 * Never throws.
 */
async function geoLookupIp(ip) {
  if (!isValidIp(ip)) return null;
  for (const provider of GEO_PROVIDERS) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      let data = null;
      try {
        const res = await fetch(provider.url(ip), {
          signal: ctrl.signal,
          headers: { 'user-agent': 'Cloudflare-Omni' },
        });
        if (!res.ok) continue;
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }
      const geo = provider.parse(data);
      if (geo) return geo;
    } catch {
      // Try the next provider.
    }
  }
  return null;
}

/** Flag emoji for a 2-letter country code (regional indicator symbols). */
function flagEmoji(countryCode) {
  const code = String(countryCode || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return '';
  return [...code].map((ch) => String.fromCodePoint(0x1f1e6 + (ch.charCodeAt(0) - 65))).join('');
}

/** Common city name -> short code (IATA-style) for compact labels. */
const CITY_CODE_MAP = {
  'los angeles': 'LAX', 'san francisco': 'SFO', 'san jose': 'SJC',
  'seattle': 'SEA', 'chicago': 'ORD', 'new york': 'JFK',
  'new york city': 'JFK', 'ashburn': 'IAD', 'miami': 'MIA',
  'dallas': 'DFW', 'atlanta': 'ATL', 'denver': 'DEN',
  'boston': 'BOS', 'houston': 'IAH', 'phoenix': 'PHX',
  'portland': 'PDX', 'london': 'LHR', 'frankfurt': 'FRA',
  'paris': 'CDG', 'amsterdam': 'AMS', 'singapore': 'SIN',
  'tokyo': 'NRT', 'hong kong': 'HKG', 'seoul': 'ICN',
  'sydney': 'SYD', 'toronto': 'YYZ', 'vancouver': 'YVR',
  'osaka': 'KIX', 'taipei': 'TPE', 'mumbai': 'BOM',
  'sao paulo': 'GRU', 'johannesburg': 'JNB', 'dubai': 'DXB',
};

/**
 * Short city code for a label: a known IATA-style code when the city is
 * recognised, otherwise the city name uppercased, spaces removed, capped
 * at 10 characters.
 */
function cityCode(city) {
  const name = String(city || '').trim();
  const mapped = CITY_CODE_MAP[name.toLowerCase()];
  if (mapped) return mapped;
  const clean = name.toUpperCase().replace(/[^A-Z0-9]/g, '');
  return clean.slice(0, 10) || 'UNK';
}

/**
 * Format an IP label as [flag]-[country]-[city]-[serial], e.g.
 * 🇺🇸-US-LAX-01. `serial` is the 1-based index within the same
 * country+city group and is rendered as two digits.
 */
function formatIpLabel(geo, serial) {
  const n = Math.max(1, Number(serial) || 1);
  return `${geo.flag}-${geo.countryCode}-${cityCode(geo.city)}-${String(n).padStart(2, '0')}`;
}

/**
 * Detect the location of each IP and build its label. `existing` is the
 * current IP library (used to number serials after the entries already
 * using the same country+city). Returns an array of
 * { ip, countryCode, country, city, flag, region, label } in input order;
 * entries that fail detection are omitted. Never throws.
 */
async function detectIpLabels(ips, existing) {
  const counts = new Map();
  for (const e of existing || []) {
    const label = String(e.label || '');
    const m = /^([^\s-]+)-([A-Z]{2})-([A-Z0-9]+)-(\d{2})$/.exec(label);
    if (m) {
      const key = `${m[2]}|${m[3]}`;
      counts.set(key, Math.max(counts.get(key) || 0, parseInt(m[4], 10)));
    }
  }
  const out = [];
  for (const rawIp of ips || []) {
    const ip = String(rawIp || '').trim();
    if (!isValidIp(ip)) continue;
    const geo = await geoLookupIp(ip);
    if (!geo) continue;
    const key = `${geo.countryCode}|${cityCode(geo.city)}`;
    const serial = (counts.get(key) || 0) + 1;
    counts.set(key, serial);
    out.push({
      ip,
      countryCode: geo.countryCode,
      country: geo.country,
      city: geo.city,
      flag: geo.flag,
      region: geo.countryCode,
      label: formatIpLabel(geo, serial),
    });
  }
  return out;
}


/**
 * Parse bulk-import text: one IP per line, `ip`, `ip#region` or
 * `ip#region#label`. Lines starting with '#' are comments.
 */
function parseIpImportText(text) {
  const entries = [];
  for (const line of splitLines(text)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const parts = t.split('#');
    entries.push({
      ip: (parts[0] || '').trim(),
      region: (parts[1] || '').trim(),
      label: parts.slice(2).join('#').trim(),
    });
  }
  return entries;
}

// --- Config patch validation -----------------------------------------------

const CONFIG_FIELD_TYPES = {
  token: 'string', link: 'string', linksub: 'string', subapi: 'string',
  subname: 'string', subuptime: 'int', preferIp: 'string',
  preferDomain: 'string', edgetunnelHosts: 'string', iplist: 'string',
};

function validateConfigPatch(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: '请求体必须是 JSON 对象。' };
  }
  const patch = {};
  for (const [k, v] of Object.entries(body)) {
    const type = CONFIG_FIELD_TYPES[k];
    if (!type) {
      return { ok: false, error: `未知配置字段: ${k}。允许的字段: ${Object.keys(CONFIG_FIELD_TYPES).join(', ')}。` };
    }
    if (type === 'int') {
      const n = typeof v === 'number' ? v : (typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN);
      if (!Number.isInteger(n) || n < 1 || n > 168) {
        return { ok: false, error: 'subuptime 必须是 1-168 的整数。' };
      }
      patch[k] = n;
    } else if (typeof v === 'string') {
      patch[k] = v;
    } else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
      patch[k] = (k === 'link' || k === 'linksub') ? v.join('\n') : v.join(',');
    } else {
      return { ok: false, error: `字段 ${k} 必须是字符串或字符串数组。` };
    }
  }
  return { ok: true, patch };
}

// --- Admin auth & handlers -------------------------------------------------

function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

/**
 * Master token from the request: /admin/<token> path segment, ?token=
 * query param, or Bearer header. The path form is preferred for the
 * admin page so the token never appears in a query string.
 */
function adminTokenFromRequest(request) {
  const url = new URL(request.url);
  const seg = pathToken(url, 'admin');
  if (seg) return seg;
  const q = url.searchParams.get('token');
  if (q) return q;
  const auth = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  return m ? m[1] : '';
}

/** 503 when the KV binding is missing (write endpoints need KV). */
function requireKvResponse(env) {
  if (env?.OMNI_KV) return null;
  return jsonResponse(
    { ok: false, error: 'KV_NOT_CONFIGURED', message: '未绑定 KV（OMNI_KV）。请先在 wrangler.toml 里配置 kv_namespaces 并部署，或在 Dashboard 绑定 KV 命名空间。' },
    503,
  );
}

function adminForbiddenHtml(message) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Cloudflare-Omni 管理</title>
<style>${PAGE_CSS}</style>
</head>
<body>
<h1>Cloudflare-Omni 管理</h1>
<p role="status">${escapeHtml(message)}</p>
<form id="tokenForm" action="/admin" method="get">
<label for="t">主口令 TOKEN</label>
<input id="t" name="token" type="password" placeholder="主口令 TOKEN" autocomplete="current-password" required>
<button class="primary" type="submit">打开管理页</button>
</form>
<p class="hint">也可以直接访问 <code>/admin/你的主口令</code>。管理接口仅接受主口令，访客 token 不可用。</p>
<script>
document.getElementById('tokenForm').addEventListener('submit', function (ev) {
  ev.preventDefault();
  var t = document.getElementById('t').value.trim();
  if (t) location.href = '/admin/' + encodeURIComponent(t);
});
</script>
</body>
</html>`;
}

function adminPageHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Cloudflare-Omni 管理</title>
<style>${PAGE_CSS}</style>
</head>
<body>
<h1>Cloudflare-Omni 管理</h1>
<div id="msg" role="status" aria-live="polite"></div>

<h2>访问口令</h2>
<label for="token">主口令 TOKEN</label>
<input id="token" type="password" placeholder="主口令（仅用于调用管理接口，不会保存到页面外）" autocomplete="current-password">
<button id="loadBtn" type="button">加载配置与 IP 库</button>
<span class="hint">地址栏是 /admin/你的主口令 时自动填入。</span>

<h2>配置</h2>
<p class="hint" id="cfgHint">保存后写入 KV，优先级：请求参数 &gt; KV 配置 &gt; 环境变量。留空表示沿用环境变量。token 字段显示为掩码，留空表示不修改。</p>
<form id="cfgForm" aria-describedby="cfgHint">
<fieldset>
<legend>订阅与转换</legend>
<label for="c_token">主口令 token</label>
<input id="c_token" type="password" placeholder="********（留空不修改）" autocomplete="off">
<label for="c_link">节点与订阅链接 link（每行一个）</label>
<textarea id="c_link" rows="4"></textarea>
<label for="c_linksub">额外订阅链接 linksub（每行一个）</label>
<textarea id="c_linksub" rows="2"></textarea>
<div class="row">
<div><label for="c_subapi">转换后端 subapi</label><input id="c_subapi" type="text"></div>
<div><label for="c_subname">订阅名 subname</label><input id="c_subname" type="text"></div>
<div><label for="c_subuptime">缓存小时 subuptime（1-168）</label><input id="c_subuptime" type="number" min="1" max="168"></div>
</div>
</fieldset>
<fieldset>
<legend>优选</legend>
<div class="row">
<div><label for="c_preferIp">优选 IP preferIp</label><input id="c_preferIp" type="text" placeholder="1.2.3.4，多个用逗号分隔"></div>
<div><label for="c_preferDomain">优选域名 preferDomain</label><input id="c_preferDomain" type="text"></div>
</div>
<label for="c_edgetunnelHosts">edgeTunnel 域名 edgetunnelHosts（逗号分隔）</label>
<input id="c_edgetunnelHosts" type="text">
<label for="c_iplist">在线优选 IP 列表 iplist（每行一个 .txt 地址）</label>
<textarea id="c_iplist" rows="2" placeholder="https://raw.githubusercontent.com/xxx/ips.txt"></textarea>
<p class="hint" id="iplistHint">每个地址返回一个 .txt，每行一个 IP，格式 ip 或 ip#region 或 ip#region#label。列表每小时拉取一次缓存，自动并入优选候选池（KV 库优先）。</p>
</fieldset>
<button class="primary" type="submit">保存配置</button>
</form>

<h2 id="ipHeading">IP 库（edgeTunnel 优选候选池）</h2>
<p class="hint">未给 ?ip= 且未配 PREFER_IP 时，edgeTunnel 节点自动从这里挑选：优先 ?region= 指定的地区、仅 enabled、延迟最小者优先。带标签的 IP 被选中后，节点名会换成标签（如 🇺🇸-US-LAX-01）。</p>
<div tabindex="0" role="region" aria-labelledby="ipHeading" class="table-wrapper">
<table id="ipTable">
<caption id="ipTableCaption">KV 中的优选 IP</caption>
<thead><tr><th scope="col">IP</th><th scope="col">地区</th><th scope="col">备注</th><th scope="col">延迟(ms)</th><th scope="col">启用</th><th scope="col">操作</th></tr></thead>
<tbody id="ipBody"></tbody>
</table>
</div>
<button id="detectAllBtn" type="button">一键识别全部未标注 IP</button>
<h3>新增 / 编辑</h3>
<form id="ipForm">
<div class="row">
<div><label for="f_ip">IP</label><input id="f_ip" type="text" required placeholder="1.2.3.4 或 IPv6" autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false"></div>
<div><label for="f_region">地区 region</label><input id="f_region" type="text" placeholder="HK / US / JP" autocomplete="off"></div>
<div><label for="f_label">备注 label</label><input id="f_label" type="text" placeholder="🇺🇸-US-LAX-01"></div>
<div><label for="f_latency">延迟 latency(ms)</label><input id="f_latency" type="number" min="0"></div>
<div><label for="f_enabled">启用 enabled</label><input id="f_enabled" type="checkbox" checked></div>
</div>
<button class="primary" type="submit">保存该条</button>
<button type="button" id="ipDetectBtn">识别该 IP 归属地</button>
<button type="button" id="ipClear">清空表单</button>
</form>
<h3>批量导入</h3>
<label for="importText">导入文本</label>
<textarea id="importText" rows="6" placeholder="每行一个 IP，格式：ip 或 ip#region 或 ip#region#label"></textarea><br>
<button id="importBtn" type="button">导入</button>
<button id="exportBtn" type="button">导出 JSON</button>

<h2 id="onlineHeading">在线 IP 列表（IPLIST）</h2>
<p class="hint">配置的在线列表拉取结果（只读，不存 KV）。来源地址与识别出的标签一并显示。</p>
<button id="onlineLoadBtn" type="button">刷新在线列表</button>
<div tabindex="0" role="region" aria-labelledby="onlineHeading" class="table-wrapper">
<table id="onlineTable">
<caption id="onlineTableCaption">在线列表中的优选 IP</caption>
<thead><tr><th scope="col">IP</th><th scope="col">地区</th><th scope="col">备注</th><th scope="col">来源</th></tr></thead>
<tbody id="onlineBody"></tbody>
</table>
</div>

<script>
var tokenInput = document.getElementById('token');
var msgBox = document.getElementById('msg');
(function () {
  var m = location.pathname.match(/^\\/admin\\/([^/]+)/);
  if (m) { tokenInput.value = decodeURIComponent(m[1]); return; }
  var qs = new URLSearchParams(location.search);
  if (qs.get('token')) tokenInput.value = qs.get('token');
})();

function showMsg(text, ok) {
  msgBox.textContent = text;
  msgBox.className = ok ? 'ok' : 'err';
}
function token() { return tokenInput.value.trim(); }
function api(path, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  opts.headers['Authorization'] = 'Bearer ' + token();
  return fetch(path, opts);
}
function loadAll() {
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  api('/api/config').then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('加载配置失败：' + (d.message || d.error), false); return; }
    var c = d.config || {};
    document.getElementById('c_token').value = '';
    document.getElementById('c_link').value = c.link || '';
    document.getElementById('c_linksub').value = c.linksub || '';
    document.getElementById('c_subapi').value = c.subapi || '';
    document.getElementById('c_subname').value = c.subname || '';
    document.getElementById('c_subuptime').value = (c.subuptime === undefined || c.subuptime === null) ? '' : c.subuptime;
    document.getElementById('c_preferIp').value = c.preferIp || '';
    document.getElementById('c_preferDomain').value = c.preferDomain || '';
    document.getElementById('c_edgetunnelHosts').value = c.edgetunnelHosts || '';
    document.getElementById('c_iplist').value = c.iplist || '';
    showMsg('配置已加载。', true);
  }).catch(function (e) { showMsg('加载配置失败：' + e.message, false); });
  loadIps();
  loadOnlineIps();
}
function loadIps() {
  api('/api/ips').then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('加载 IP 库失败：' + (d.message || d.error), false); return; }
    renderIps(d.ips || []);
  }).catch(function (e) { showMsg('加载 IP 库失败：' + e.message, false); });
}
function loadOnlineIps() {
  api('/api/ips/online').then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { renderOnline([]); return; }
    renderOnline(d.ips || []);
  }).catch(function () { renderOnline([]); });
}
function renderOnline(list) {
  var body = document.getElementById('onlineBody');
  body.innerHTML = '';
  list.forEach(function (e) {
    var tr = document.createElement('tr');
    var tdIp = document.createElement('td'); tdIp.textContent = e.ip; tdIp.setAttribute('data-label', 'IP'); tr.appendChild(tdIp);
    var tdR = document.createElement('td'); tdR.textContent = e.region || ''; tdR.setAttribute('data-label', '地区'); tr.appendChild(tdR);
    var tdL = document.createElement('td'); tdL.textContent = e.label || ''; tdL.setAttribute('data-label', '备注'); tr.appendChild(tdL);
    var tdS = document.createElement('td'); tdS.textContent = e.source || ''; tdS.setAttribute('data-label', '来源'); tr.appendChild(tdS);
    body.appendChild(tr);
  });
  if (list.length === 0) {
    var tr0 = document.createElement('tr');
    var td0 = document.createElement('td'); td0.colSpan = 4; td0.textContent = '没有配置在线列表，或列表为空。'; tr0.appendChild(td0);
    body.appendChild(tr0);
  }
}
function renderIps(list) {
  var body = document.getElementById('ipBody');
  body.innerHTML = '';
  list.forEach(function (e) {
    var tr = document.createElement('tr');
    var tdIp = document.createElement('td'); tdIp.textContent = e.ip; tdIp.setAttribute('data-label', 'IP'); tr.appendChild(tdIp);
    var tdR = document.createElement('td'); tdR.textContent = e.region || ''; tdR.setAttribute('data-label', '地区'); tr.appendChild(tdR);
    var tdL = document.createElement('td'); tdL.textContent = e.label || ''; tdL.setAttribute('data-label', '备注'); tr.appendChild(tdL);
    var tdLat = document.createElement('td'); tdLat.textContent = (e.latency === null || e.latency === undefined) ? '' : e.latency; tdLat.setAttribute('data-label', '延迟(ms)'); tr.appendChild(tdLat);
    var tdE = document.createElement('td'); tdE.textContent = e.enabled === false ? '否' : '是'; tdE.setAttribute('data-label', '启用'); tr.appendChild(tdE);
    var tdA = document.createElement('td'); tdA.setAttribute('data-label', '操作');
    var bEdit = document.createElement('button'); bEdit.type = 'button'; bEdit.textContent = '编辑';
    bEdit.onclick = function () {
      document.getElementById('f_ip').value = e.ip;
      document.getElementById('f_region').value = e.region || '';
      document.getElementById('f_label').value = e.label || '';
      document.getElementById('f_latency').value = (e.latency === null || e.latency === undefined) ? '' : e.latency;
      document.getElementById('f_enabled').checked = e.enabled !== false;
      window.scrollTo(0, document.getElementById('ipForm').offsetTop);
    };
    var bDetect = document.createElement('button'); bDetect.type = 'button'; bDetect.textContent = '识别';
    bDetect.onclick = function () { detectOne(e.ip); };
    var bDel = document.createElement('button'); bDel.type = 'button'; bDel.textContent = '删除';
    bDel.onclick = function () {
      if (!confirm('删除 ' + e.ip + '？')) return;
      api('/api/ips?ip=' + encodeURIComponent(e.ip), { method: 'DELETE' }).then(function (r) { return r.json(); }).then(function (d) {
        if (!d.ok) { showMsg('删除失败：' + (d.message || d.error), false); return; }
        showMsg('已删除 ' + e.ip + '。', true); loadIps();
      }).catch(function (err) { showMsg('删除失败：' + err.message, false); });
    };
    tdA.appendChild(bEdit); tdA.appendChild(bDetect); tdA.appendChild(bDel); tr.appendChild(tdA);
    body.appendChild(tr);
  });
  if (list.length === 0) {
    var tr0 = document.createElement('tr');
    var td0 = document.createElement('td'); td0.colSpan = 6; td0.textContent = 'IP 库为空。'; tr0.appendChild(td0);
    body.appendChild(tr0);
  }
}
function detectOne(ip) {
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  api('/api/ips/detect', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip: ip }) }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok || !d.detected || d.detected.length === 0) { showMsg('识别失败：' + (d.message || d.error || '查不到归属地'), false); return; }
    var det = d.detected[0];
    applyDetection(det);
    showMsg('已识别 ' + ip + ' 为 ' + det.label + '。', true);
  }).catch(function (e) { showMsg('识别失败：' + e.message, false); });
}
function applyDetection(det) {
  return api('/api/ips', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip: det.ip, region: det.region, label: det.label }) }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('保存标签失败：' + (d.message || d.error), false); return; }
    loadIps();
  }).catch(function (e) { showMsg('保存标签失败：' + e.message, false); });
}
document.getElementById('detectAllBtn').onclick = function () {
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  api('/api/ips').then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('加载 IP 库失败：' + (d.message || d.error), false); return; }
    var ips = (d.ips || []).filter(function (e) { return !e.label; }).map(function (e) { return e.ip; });
    if (ips.length === 0) { showMsg('没有未标注的 IP。', true); return; }
    return api('/api/ips/detect', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ips: ips }) }).then(function (r) { return r.json(); }).then(function (dd) {
      if (!dd.ok) { showMsg('识别失败：' + (dd.message || dd.error), false); return; }
      var jobs = (dd.detected || []).map(function (det) { return applyDetection(det); });
      return Promise.all(jobs).then(function () {
        showMsg('识别完成：' + (dd.detected || []).length + ' 条已标注' + ((dd.failed || []).length ? '，' + dd.failed.length + ' 条失败' : '') + '。', true);
      });
    });
  }).catch(function (e) { showMsg('识别失败：' + e.message, false); });
};
document.getElementById('loadBtn').onclick = loadAll;
document.getElementById('onlineLoadBtn').onclick = function () {
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  loadOnlineIps();
  showMsg('在线列表已刷新。', true);
};
document.getElementById('cfgForm').onsubmit = function (ev) {
  ev.preventDefault();
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  var body = {};
  var t = document.getElementById('c_token').value;
  if (t) body.token = t;
  body.link = document.getElementById('c_link').value;
  body.linksub = document.getElementById('c_linksub').value;
  body.subapi = document.getElementById('c_subapi').value;
  body.subname = document.getElementById('c_subname').value;
  var up = document.getElementById('c_subuptime').value;
  if (up !== '') body.subuptime = parseInt(up, 10);
  body.preferIp = document.getElementById('c_preferIp').value;
  body.preferDomain = document.getElementById('c_preferDomain').value;
  body.edgetunnelHosts = document.getElementById('c_edgetunnelHosts').value;
  body.iplist = document.getElementById('c_iplist').value;
  api('/api/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('保存失败：' + (d.message || d.error), false); return; }
    showMsg('配置已保存。', true);
  }).catch(function (e) { showMsg('保存失败：' + e.message, false); });
};
document.getElementById('ipForm').onsubmit = function (ev) {
  ev.preventDefault();
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  var lat = document.getElementById('f_latency').value;
  var body = {
    ip: document.getElementById('f_ip').value.trim(),
    region: document.getElementById('f_region').value.trim(),
    label: document.getElementById('f_label').value.trim(),
    latency: lat === '' ? null : parseInt(lat, 10),
    enabled: document.getElementById('f_enabled').checked,
  };
  api('/api/ips', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('保存失败：' + (d.message || d.error), false); return; }
    showMsg('已保存 ' + body.ip + '。', true); loadIps();
  }).catch(function (e) { showMsg('保存失败：' + e.message, false); });
};
document.getElementById('ipDetectBtn').onclick = function () {
  var ip = document.getElementById('f_ip').value.trim();
  if (!ip) { showMsg('请先填写 IP。', false); return; }
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  api('/api/ips/detect', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip: ip }) }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok || !d.detected || d.detected.length === 0) { showMsg('识别失败：' + (d.message || d.error || '查不到归属地'), false); return; }
    var det = d.detected[0];
    document.getElementById('f_region').value = det.region || '';
    document.getElementById('f_label').value = det.label || '';
    showMsg('已识别 ' + ip + ' 为 ' + det.label + '，已填入表单，点“保存该条”写入 IP 库。', true);
  }).catch(function (e) { showMsg('识别失败：' + e.message, false); });
};
document.getElementById('ipClear').onclick = function () {
  document.getElementById('f_ip').value = '';
  document.getElementById('f_region').value = '';
  document.getElementById('f_label').value = '';
  document.getElementById('f_latency').value = '';
  document.getElementById('f_enabled').checked = true;
};
document.getElementById('importBtn').onclick = function () {
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  var text = document.getElementById('importText').value;
  api('/api/ips/import', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: text }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('导入失败：' + (d.message || d.error), false); return; }
    showMsg('导入完成：新增 ' + d.added + ' 条，跳过 ' + d.skipped + ' 条。', true); loadIps();
  }).catch(function (e) { showMsg('导入失败：' + e.message, false); });
};
document.getElementById('exportBtn').onclick = function () {
  if (!token()) { showMsg('请先输入主口令 TOKEN。', false); return; }
  api('/api/ips').then(function (r) { return r.json(); }).then(function (d) {
    if (!d.ok) { showMsg('导出失败：' + (d.message || d.error), false); return; }
    var blob = new Blob([JSON.stringify(d.ips || [], null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'omni-ips.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }).catch(function (e) { showMsg('导出失败：' + e.message, false); });
};
if (tokenInput.value) loadAll();
</script>
</body>
</html>`;
}

/**
 * Admin dispatcher: /admin page + /api/* endpoints.
 * All of them require the master token (env TOKEN or KV config token).
 * Guest tokens (fixed / daily) are NOT accepted here. When no master
 * token is configured at all, management is unavailable (403).
 */
async function handleAdmin(request, env, cfg) {
  const url = new URL(request.url);
  const isApi = url.pathname.startsWith('/api/');
  const master = (cfg.TOKEN || '').trim();
  const deny = (status, error, message) => {
    if (isApi) return jsonResponse({ ok: false, error, message }, status);
    return new Response(adminForbiddenHtml(message), {
      status,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  };
  if (!master) {
    return deny(403, 'TOKEN_NOT_CONFIGURED', '请先设置 TOKEN（环境变量 TOKEN，或在 KV 配置里设置 token），再使用管理功能。');
  }
  const provided = adminTokenFromRequest(request);
  if (!provided || provided !== master) {
    return deny(403, 'FORBIDDEN', '管理接口需要主口令 TOKEN（?token= 或 Authorization: Bearer）。访客 token 不可用。');
  }

  if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
    return new Response(adminPageHtml(), {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }
  if (url.pathname === '/api/config' && request.method === 'GET') {
    return jsonResponse({ ok: true, config: effectiveConfigForApi(cfg), kvBound: !!env?.OMNI_KV });
  }
  if (url.pathname === '/api/config' && request.method === 'POST') {
    return await handleApiConfigPost(request, env);
  }
  if (url.pathname === '/api/ips' && request.method === 'GET') {
    return await handleApiIpsGet(request, env);
  }
  if (url.pathname === '/api/ips' && request.method === 'POST') {
    return await handleApiIpsPost(request, env);
  }
  if (url.pathname === '/api/ips' && request.method === 'PUT') {
    return await handleApiIpsPut(request, env);
  }
  if (url.pathname === '/api/ips' && request.method === 'DELETE') {
    return await handleApiIpsDelete(request, env);
  }
  if (url.pathname === '/api/ips/import' && request.method === 'POST') {
    return await handleApiIpsImport(request, env);
  }
  if (url.pathname === '/api/ips/detect' && request.method === 'POST') {
    return await handleApiIpsDetect(request, env);
  }
  if (url.pathname === '/api/ips/online' && request.method === 'GET') {
    return await handleApiIpsOnline(request, env, cfg);
  }
  return jsonResponse({ ok: false, error: 'NOT_FOUND', message: '未知的管理接口。' }, 404);
}

async function readJsonBody(request) {
  try {
    const text = await request.text();
    if (!text || !text.trim()) return { ok: false, error: '请求体为空。' };
    return { ok: true, body: JSON.parse(text) };
  } catch {
    return { ok: false, error: '请求体不是合法 JSON。' };
  }
}

async function handleApiConfigPost(request, env) {
  const noKv = requireKvResponse(env);
  if (noKv) return noKv;
  const parsed = await readJsonBody(request);
  if (!parsed.ok) return jsonResponse({ ok: false, error: 'BAD_JSON', message: parsed.error }, 400);
  const v = validateConfigPatch(parsed.body);
  if (!v.ok) return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: v.error }, 400);
  const current = await loadKvConfig(env);
  const next = { ...current, ...v.patch };
  const saved = await saveKvConfig(env, next);
  if (!saved) return jsonResponse({ ok: false, error: 'KV_WRITE_FAILED', message: '写入 KV 失败，请稍后重试。' }, 500);
  const cfg = await resolveEffectiveConfig(env);
  return jsonResponse({ ok: true, config: effectiveConfigForApi(cfg), kvBound: true });
}

async function handleApiIpsGet(request, env) {
  const pool = await loadKvIps(env);
  const url = new URL(request.url);
  const region = (url.searchParams.get('region') || '').trim().toLowerCase();
  const enabledParam = url.searchParams.get('enabled');
  let list = pool;
  if (region) list = list.filter((e) => String(e.region || '').toLowerCase() === region);
  if (enabledParam === '1') list = list.filter((e) => e.enabled !== false);
  if (enabledParam === '0') list = list.filter((e) => e.enabled === false);
  return jsonResponse({ ok: true, ips: list, total: list.length, kvBound: !!env?.OMNI_KV });
}

async function handleApiIpsPost(request, env) {
  const noKv = requireKvResponse(env);
  if (noKv) return noKv;
  const parsed = await readJsonBody(request);
  if (!parsed.ok) return jsonResponse({ ok: false, error: 'BAD_JSON', message: parsed.error }, 400);
  if (!Array.isArray(parsed.body)) {
    return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: '请求体必须是 JSON 数组。' }, 400);
  }
  const entries = [];
  for (const raw of parsed.body) {
    const e = normalizeIpEntry(raw, null);
    if (!e) {
      return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: `无效的 IP 条目: ${JSON.stringify(raw)}。每条须含合法的 ip 字段。` }, 400);
    }
    entries.push(e);
  }
  const list = dedupeIpList(entries);
  const saved = await saveKvIps(env, list);
  if (!saved) return jsonResponse({ ok: false, error: 'KV_WRITE_FAILED', message: '写入 KV 失败，请稍后重试。' }, 500);
  return jsonResponse({ ok: true, ips: list, total: list.length });
}

async function handleApiIpsPut(request, env) {
  const noKv = requireKvResponse(env);
  if (noKv) return noKv;
  const parsed = await readJsonBody(request);
  if (!parsed.ok) return jsonResponse({ ok: false, error: 'BAD_JSON', message: parsed.error }, 400);
  const pool = await loadKvIps(env);
  const key = String(parsed.body?.ip || '').trim().toLowerCase();
  const idx = pool.findIndex((e) => String(e.ip || '').toLowerCase() === key);
  const entry = normalizeIpEntry(parsed.body, idx >= 0 ? pool[idx] : null);
  if (!entry) {
    return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: '无效的 IP 条目：ip 必须是合法的 IPv4 或 IPv6 地址。' }, 400);
  }
  if (idx >= 0) pool[idx] = entry;
  else pool.push(entry);
  const saved = await saveKvIps(env, pool);
  if (!saved) return jsonResponse({ ok: false, error: 'KV_WRITE_FAILED', message: '写入 KV 失败，请稍后重试。' }, 500);
  return jsonResponse({ ok: true, entry, total: pool.length, updated: idx >= 0 });
}

async function handleApiIpsDelete(request, env) {
  const noKv = requireKvResponse(env);
  if (noKv) return noKv;
  const url = new URL(request.url);
  const ip = (url.searchParams.get('ip') || '').trim().toLowerCase();
  if (!ip) {
    return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: '缺少 ?ip= 参数。' }, 400);
  }
  const pool = await loadKvIps(env);
  const next = pool.filter((e) => String(e.ip || '').toLowerCase() !== ip);
  if (next.length === pool.length) {
    return jsonResponse({ ok: false, error: 'NOT_FOUND', message: `IP 库中没有 ${ip}。` }, 404);
  }
  const saved = await saveKvIps(env, next);
  if (!saved) return jsonResponse({ ok: false, error: 'KV_WRITE_FAILED', message: '写入 KV 失败，请稍后重试。' }, 500);
  return jsonResponse({ ok: true, deleted: ip, total: next.length });
}

async function handleApiIpsImport(request, env) {
  const noKv = requireKvResponse(env);
  if (noKv) return noKv;
  const text = await request.text();
  const parsed = parseIpImportText(text);
  const pool = await loadKvIps(env);
  const existing = new Set(pool.map((e) => String(e.ip || '').toLowerCase()));
  let added = 0;
  let skipped = 0;
  let invalid = 0;
  for (const raw of parsed) {
    const entry = normalizeIpEntry(raw, null);
    if (!entry) {
      invalid++;
      skipped++;
      continue;
    }
    if (existing.has(entry.ip.toLowerCase())) {
      skipped++;
      continue;
    }
    existing.add(entry.ip.toLowerCase());
    pool.push(entry);
    added++;
  }
  const saved = await saveKvIps(env, pool);
  if (!saved) return jsonResponse({ ok: false, error: 'KV_WRITE_FAILED', message: '写入 KV 失败，请稍后重试。' }, 500);
  return jsonResponse({ ok: true, added, skipped, invalid, total: pool.length });
}

/**
 * POST /api/ips/detect — one-click IP region detection.
 * Body: {"ip": "1.2.3.4"} or {"ips": ["1.2.3.4", ...]}.
 * Looks each IP up (ipwho.is) and returns its detected label in the form
 * [flag]-[country]-[city]-[serial], e.g. 🇺🇸-US-LAX-01, plus the region
 * (country code) to store on the entry. Entries that fail detection are
 * reported in `failed` and omitted from `detected`. Nothing is saved
 * here; the caller stores the label with PUT /api/ips.
 */
async function handleApiIpsDetect(request, env) {
  const parsed = await readJsonBody(request);
  if (!parsed.ok) return jsonResponse({ ok: false, error: 'BAD_JSON', message: parsed.error }, 400);
  const body = parsed.body || {};
  let ips = [];
  if (typeof body.ip === 'string' && body.ip.trim()) ips = [body.ip.trim()];
  else if (Array.isArray(body.ips)) ips = body.ips.map((x) => String(x || '').trim()).filter(Boolean);
  if (ips.length === 0) {
    return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: '请求体须含 ip（字符串）或 ips（字符串数组）。' }, 400);
  }
  if (ips.length > 100) {
    return jsonResponse({ ok: false, error: 'VALIDATION_FAILED', message: '一次最多识别 100 个 IP。' }, 400);
  }
  const pool = await loadKvIps(env);
  const detected = await detectIpLabels(ips, pool);
  const okIps = new Set(detected.map((d) => d.ip.toLowerCase()));
  const failed = ips.filter((ip) => !okIps.has(ip.toLowerCase()));
  return jsonResponse({ ok: true, detected, failed, total: detected.length });
}

/**
 * GET /api/ips/online — the IPs currently contributed by the IPLIST
 * online lists (fetched live, cached 1h), each with its `source` URL.
 * Query params: ?region= and ?enabled= filter the same way as /api/ips.
 * These entries are not stored in KV; the KV library is returned by
 * /api/ips instead.
 */
async function handleApiIpsOnline(request, env, cfg) {
  const url = new URL(request.url);
  const region = (url.searchParams.get('region') || '').trim().toLowerCase();
  const enabledParam = url.searchParams.get('enabled');
  const kvPool = await loadKvIps(env);
  let list = await loadOnlineIps(cfg, kvPool);
  if (region) list = list.filter((e) => String(e.region || '').toLowerCase() === region);
  if (enabledParam === '1') list = list.filter((e) => e.enabled !== false);
  if (enabledParam === '0') list = list.filter((e) => e.enabled === false);
  return jsonResponse({ ok: true, ips: list, total: list.length, kvBound: !!env?.OMNI_KV });
}

// ---------------------------------------------------------------------------
// Aggregation pipeline (aggregate -> dedupe -> prefer)
// ---------------------------------------------------------------------------

async function getNodes(cfg, request) {
  const { nodes, stats } = await aggregateNodes(cfg, request);
  const deduped = dedupeNodes(nodes);
  return { nodes: deduped, stats: { ...stats, total: deduped.length } };
}

/**
 * Resolve the preferred IP / domain for this request.
 * Priority: query param > KV config > env var > default.
 * `autoPick` is true when no explicit IP was given anywhere (or when the
 * query explicitly asks for `?ip=auto`): the caller then picks one from
 * the KV IP pool. `?ip=auto` ignores the PREFER_IP env var on purpose.
 */
function resolvePrefer(url, cfg) {
  const qIp = (url.searchParams.get('ip') || url.searchParams.get('preferIp') || '').trim();
  const domain = (
    url.searchParams.get('domain') ||
    url.searchParams.get('preferDomain') ||
    (cfg.PREFER_DOMAIN || '').trim()
  );
  if (qIp.toLowerCase() === 'auto') return { ip: '', domain, autoPick: true };
  if (qIp) return { ip: qIp, domain, autoPick: false };
  const envIp = splitCsv(cfg.PREFER_IP)[0] || '';
  if (envIp) return { ip: envIp.trim(), domain, autoPick: false };
  return { ip: '', domain, autoPick: true };
}

// ---------------------------------------------------------------------------
// Cache (Cache API, TTL = SUBUPTIME hours)
// ---------------------------------------------------------------------------

// Bump this whenever the generated subscription output changes in a way
// that must invalidate previously cached responses (e.g. a fix to the
// Clash/sing-box generator). Old entries are then orphaned and expire
// on their own; new requests compute a fresh key and re-aggregate.
const CACHE_VERSION = '2';

function cacheTtlSeconds(env) {
  const h = parseInt(env.SUBUPTIME, 10);
  const hours = Number.isFinite(h) && h > 0 ? h : DEFAULT_UPTIME_HOURS;
  return hours * 3600;
}

/** Cache key: normalized subscription request (token & nocache stripped). */
function cacheRequestFor(request, target, preferIp, preferDomain) {
  const u = new URL(request.url);
  u.pathname = '/sub';
  u.searchParams.delete('token');
  u.searchParams.delete('nocache');
  u.searchParams.delete('preferIp');
  u.searchParams.delete('preferDomain');
  u.searchParams.delete('region'); // region only affects the auto-pick, which the resolved ip already captures
  u.searchParams.set('target', target);
  u.searchParams.set('v', CACHE_VERSION);
  if (preferIp) u.searchParams.set('ip', preferIp);
  else u.searchParams.delete('ip');
  if (preferDomain) u.searchParams.set('domain', preferDomain);
  else u.searchParams.delete('domain');
  return new Request(u.toString(), { method: 'GET' });
}

// ---------------------------------------------------------------------------
// HTML pages
// ---------------------------------------------------------------------------

/**
 * Shared page stylesheet, following modern-web-guidance:
 * - `color-scheme: light dark` on :root plus a <meta name="color-scheme">
 *   so native UI (scrollbars, form controls) follows the system theme and
 *   the first paint does not flash un-themed.
 * - `light-dark()` tokens with a `prefers-color-scheme` fallback for
 *   browsers without light-dark() support.
 * - Form controls use `font: inherit` and stay at least 1rem / 48px so
 *   they do not trigger iOS zoom and remain tappable.
 * - `:user-invalid` (never bare `:invalid`) for validation styling, so
 *   empty required fields are not flagged before interaction.
 * - A visible `:focus-visible` outline on every control.
 * - Tables live in a scrollable region (tabindex="0", role="region")
 *   with a sticky header, and collapse to labelled cards under a
 *   @container query on narrow widths.
 */
const PAGE_CSS = `
:root{
  color-scheme:light dark;
  --bg:#ffffff;--fg:#1a1a1a;--muted:#5f6368;--line:#dfe1e5;
  --surface:#f8f9fa;--code-bg:#f2f2f2;--accent:#0b57d0;--accent-fg:#ffffff;
  --ok-bg:#e6f4ea;--ok-fg:#137333;--err-bg:#fce8e6;--err-fg:#a50e0e;
  --focus:#0b57d0;
  accent-color:var(--accent);
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#121212;--fg:#e8eaed;--muted:#9aa0a6;--line:#3c4043;
    --surface:#1f1f1f;--code-bg:#2b2b2b;--accent:#8ab4f8;--accent-fg:#0b1220;
    --ok-bg:#1e3a2a;--ok-fg:#81c995;--err-bg:#3d1a1a;--err-fg:#f28b82;
    --focus:#8ab4f8;
  }
}
@supports (color: light-dark(#fff, #000)){
  :root{
    --bg:light-dark(#ffffff,#121212);--fg:light-dark(#1a1a1a,#e8eaed);
    --muted:light-dark(#5f6368,#9aa0a6);--line:light-dark(#dfe1e5,#3c4043);
    --surface:light-dark(#f8f9fa,#1f1f1f);--code-bg:light-dark(#f2f2f2,#2b2b2b);
    --accent:light-dark(#0b57d0,#8ab4f8);--accent-fg:light-dark(#ffffff,#0b1220);
    --ok-bg:light-dark(#e6f4ea,#1e3a2a);--ok-fg:light-dark(#137333,#81c995);
    --err-bg:light-dark(#fce8e6,#3d1a1a);--err-fg:light-dark(#a50e0e,#f28b82);
    --focus:light-dark(#0b57d0,#8ab4f8);
  }
}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:860px;margin:32px auto;padding:0 20px;line-height:1.6;color:var(--fg);background:var(--bg)}
h1{font-size:24px}h2{font-size:18px;margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:4px}h3{font-size:16px}
a{color:var(--accent)}
code{background:var(--code-bg);padding:2px 6px;border-radius:4px;word-break:break-all}
label{display:block;margin:8px 0;font-size:14px}
input[type=text],input[type=password],input[type=number],textarea{width:100%;padding:10px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg);font:inherit;font-size:max(1rem,1em);min-height:48px}
textarea{font-family:ui-monospace,Menlo,monospace}
input:user-invalid,textarea:user-invalid{border-color:var(--err-fg)}
button{padding:10px 16px;margin:6px 6px 6px 0;cursor:pointer;border:1px solid var(--line);background:var(--surface);color:var(--fg);border-radius:4px;font:inherit;font-size:max(1rem,1em);min-height:48px}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.hint{color:var(--muted);font-size:13px}
.row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:180px}
.table-wrapper{overflow:auto;max-inline-size:100%;max-block-size:min(500px,80vh);container-type:inline-size}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px;margin-top:8px}
caption{text-align:left;font-weight:600;padding:4px 0}
thead{position:sticky;inset-block-start:0;z-index:1}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;background:var(--bg)}
th{background:var(--surface)}
tbody th{position:sticky;inset-inline-start:0}
td input{width:100%;padding:4px}
#msg{padding:10px;border-radius:4px;margin:12px 0;display:none}
#msg.ok{display:block;background:var(--ok-bg);color:var(--ok-fg)}
#msg.err{display:block;background:var(--err-bg);color:var(--err-fg)}
@container (width < 600px){
  table,thead,tbody,tr,th,td{display:block}
  thead{display:none}
  tr{margin-block-end:1.5rem;border:1px solid var(--line)}
  tbody th{position:sticky;inset-block-start:0;z-index:2;background:var(--surface)}
  td::before{content:attr(data-label) ": ";font-weight:600}
}
`;

function landingPageHtml(env) {
  const name = escapeHtml(env.SUBNAME || DEFAULT_SUBNAME);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${name}</title>
<style>${PAGE_CSS}</style>
</head>
<body>
<h1>${name}</h1>
<p>订阅聚合服务：将多个节点链接与订阅链接整合成一个统一订阅，并按客户端自动转换格式。</p>
<h2>使用方法</h2>
<p>在订阅地址后加上访问口令，两种写法都可以：</p>
<p><code>/sub/YOUR_TOKEN</code> 或 <code>/sub?token=YOUR_TOKEN</code></p>
<p>输出格式：<code>?target=base64</code>（默认）、<code>raw</code>、<code>clash</code>、<code>singbox</code>，其它格式（surge / quanx / loon / shadowrocket）需要配置 <code>SUBAPI</code> 转换后端。</p>
<h2>edgeTunnel 优选</h2>
<p>对部署在 Cloudflare 上的 edgeTunnel 节点，可用优选 IP / 域名替换连接地址：</p>
<p><code>?ip=1.2.3.4</code> 或 <code>?domain=example.com</code>（两者都给时 IP 优先）。原始域名的 TLS SNI 与 Host 头会被保留。未带 <code>ip</code> 时自动从 IP 库（KV + 在线列表）中挑选（见管理页）。</p>
<h2>管理</h2>
<p>主口令持有者可打开 <code>/admin/YOUR_TOKEN</code> 管理配置与 IP 库（需要绑定 KV 命名空间 <code>OMNI_KV</code>）。</p>
<p>未配置访问口令时本服务公开访问；配置 <code>TOKEN</code> 后需要鉴权。</p>
</body>
</html>`;
}

function dashboardHtml(env, nodes, stats, url, tokens) {
  const name = escapeHtml(env.SUBNAME || DEFAULT_SUBNAME);
  const origin = url.origin;
  const guest = tokens ? tokens.daily : '';
  const mk = (target) =>
    `${origin}/sub/${encodeURIComponent(guest)}?target=${target}`;
  const targets = ['base64', 'raw', 'clash', 'singbox', 'surge', 'quanx', 'loon', 'shadowrocket'];
  const rows = targets
    .map((t) => `<li><a href="${escapeHtml(mk(t))}">${t}</a></li>`)
    .join('\n');
  const preferExample =
    `${origin}/sub/${encodeURIComponent(guest)}?target=clash&ip=104.21.0.1&domain=example.com`;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${name} — 订阅管理</title>
<style>${PAGE_CSS}</style>
</head>
<body>
<h1>${name}</h1>
<p>当前节点数：<strong>${nodes.length}</strong>（直连 ${stats.direct}，订阅成功 ${stats.subsOk}，订阅失败 ${stats.subsFailed}，解析失败 ${stats.parseFailed}）</p>
<h2>订阅链接（访客 token，每日轮换）</h2>
<ul>
${rows}
</ul>
<h2>edgeTunnel 优选示例</h2>
<p><code>${escapeHtml(preferExample)}</code></p>
<p>说明：<code>ip</code> 替换连接地址，<code>domain</code> 替换为优选域名；两者都给时 IP 优先。原始域名的 TLS SNI 与 Host 头会被保留，带标签的优选 IP 会把节点名换成标签（如 🇺🇸-US-LAX-01），没有标签时节点名后追加“(优选)”。也可用 <code>preferIp</code> / <code>preferDomain</code> 作为同义参数，或直接配置环境变量 <code>PREFER_IP</code> / <code>PREFER_DOMAIN</code>。</p>
<h2>固定访客 token</h2>
<p><code>${escapeHtml(tokens ? tokens.fixed : '')}</code></p>
<p>缓存：${escapeHtml(String(parseInt(env.SUBUPTIME, 10) || DEFAULT_UPTIME_HOURS))} 小时；加 <code>?nocache=1</code> 可绕过缓存。</p>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

async function handleFetch(request, env, ctx) {
  const url = new URL(request.url);
  const userAgent = request.headers.get('User-Agent') || '';

  // Health check (no auth, no KV).
  if (url.pathname === '/health') {
    return new Response(JSON.stringify({ status: 'ok' }), {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  }

  // Effective config: KV config wins over env vars, env wins over defaults.
  // The rest of this handler reads settings from `cfg` (same key names as
  // env), while `env` is only used for the KV binding itself.
  const cfg = await resolveEffectiveConfig(env);

  // Admin UI + management APIs (master token only, see handleAdmin).
  // /admin/<token> carries the token in the path; /api/* takes it from
  // ?token= or a Bearer header (see adminTokenFromRequest).
  if (url.pathname === '/admin' || url.pathname.startsWith('/admin/') || url.pathname.startsWith('/api/')) {
    return await handleAdmin(request, env, cfg);
  }

  // Auth: TOKEN empty => public; otherwise master / fixed guest / daily guest.
  // The master token is the effective TOKEN (KV config token wins over env).
  // Tokens may be passed as ?token=<redacted> as the first path segment (/<token>),
  // or in the path after /sub/ or /admin/ (see isAuthorized).
  const master = (cfg.TOKEN || '').trim();
  let tokens = null;
  if (master) tokens = await buildTokens(master);
  const authed = !master || isAuthorized(url, tokens);
  if (!authed) {
    return new Response(landingPageHtml(cfg), {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  // Authenticated browser visit to `/` => dashboard with live node count.
  const target = resolveTarget(url, userAgent);
  const isBrowser = userAgent.toLowerCase().includes('mozilla');
  if (url.pathname === '/' && !url.searchParams.has('target') && isBrowser) {
    const { nodes, stats } = await getNodes(cfg, request);
    return new Response(dashboardHtml(cfg, nodes, stats, url, tokens), {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  // --- Subscription flow ---
  const { ip: preferIp0, domain: preferDomain, autoPick } = resolvePrefer(url, cfg);
  let preferIp = preferIp0;
  let preferLabel = '';
  if (autoPick) {
    // No explicit IP anywhere: pick one from the preferred-IP pool
    // (KV library + online IPLIST lists), region-aware. Empty pool =>
    // no replacement, same behaviour as before KV existed.
    const pool = await loadPreferredIpPool(env, cfg);
    const pickedEntry = pickPreferredIpEntry(pool, url.searchParams.get('region') || '');
    if (pickedEntry) {
      preferIp = pickedEntry.ip;
      preferLabel = pickedEntry.label || '';
    }
  } else if (preferIp) {
    // Explicit ?ip= (or PREFER_IP): reuse the pool label when this IP is
    // known, so the node name still reflects the detected location.
    const pool = await loadPreferredIpPool(env, cfg);
    const known = pool.find((e) => String(e.ip || '').toLowerCase() === preferIp.toLowerCase());
    if (known && known.label) preferLabel = known.label;
  }
  const noCache = url.searchParams.get('nocache') === '1';
  const edgeHosts = splitCsv(cfg.EDGETUNNEL_HOSTS || '');
  const ttl = cacheTtlSeconds(cfg);

  const cache = caches.default;
  const cacheReq = cacheRequestFor(request, target, preferIp, preferDomain);
  if (!noCache) {
    const hit = await cache.match(cacheReq);
    if (hit) return hit;
  }

  const { nodes, stats } = await getNodes(cfg, request);
  applyPrefer(nodes, preferIp, preferDomain, edgeHosts, preferLabel);

  let body = '';
  let contentType = 'text/plain; charset=utf-8';
  let fallback = false;

  if (target === 'clash') {
    body = toClash(nodes);
    contentType = 'text/yaml; charset=utf-8';
  } else if (target === 'singbox') {
    body = toSingbox(nodes);
    contentType = 'application/json; charset=utf-8';
  } else if (target === 'raw') {
    body = toRaw(nodes);
  } else if (target === 'base64') {
    body = toBase64(nodes);
  } else {
    // surge / quanx / loon / shadowrocket / ... via external converter.
    const selfUrl = new URL(request.url);
    selfUrl.pathname = '/sub';
    selfUrl.searchParams.set('target', 'base64');
    selfUrl.searchParams.delete('nocache');
    selfUrl.searchParams.delete('ip');
    selfUrl.searchParams.delete('domain');
    selfUrl.searchParams.delete('preferIp');
    selfUrl.searchParams.delete('preferDomain');
    if (tokens) selfUrl.searchParams.set('token', tokens.daily);
    const converted = await forwardToConverter(target, selfUrl.toString(), cfg, userAgent);
    if (converted) {
      body = converted.body;
      contentType = converted.contentType;
    } else {
      body = toBase64(nodes);
      fallback = true;
    }
  }

  const headers = subHeaders(cfg, userAgent, {
    'content-type': contentType,
    'Cache-Control': `public, max-age=${ttl}`,
  });
  if (fallback) headers['X-Fallback'] = 'base64';
  const response = new Response(body, { headers });

  if (!noCache) {
    // Store a clone; the original is returned to the client.
    await cache.put(cacheReq, response.clone());
  }
  return response;
}
