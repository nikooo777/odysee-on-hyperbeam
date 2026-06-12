// HyperBEAM node client. The node is treated as an untrusted courier: every
// byte that feeds a verification verdict is re-checked client-side, so this
// module only handles transport mechanics:
//  - JSON requests via `accept: application/json`
//  - ao-types annotations (atoms/integers arrive as strings)
//  - submessage links: nested maps come back as `<key>+link` entries whose
//    value is a message ID, dereferenced with GET /<id> from the node cache.
// Every request is recorded in an exchange ledger (`exchanges`) so the UI can
// show the full protocol conversation without the network tab. Requests are
// attributed via step-bound handles (`hb.step('resolve')`), never a mutable
// global, because blob sweeps and committed-form fetches run concurrently
// with step execution.
const DEVICE = '~odysee@1.0';

// Response headers worth surfacing in the ledger. The node sends
// `access-control-expose-headers: *`, so all of these are readable.
const PICKED_HEADERS = [
  'signature',
  'signature-input',
  'content-digest',
  'device',
  'ao-types',
  'ao-body-key',
  'content-type',
  'content-range',
  'byte-size-source',
];

export class HbError extends Error {
  constructor(status, body, path) {
    super(`HTTP ${status} from ${path}`);
    this.status = status;
    this.body = body;
    this.path = path;
  }
}

export class HbClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.exchanges = [];
    this.label = 'general';
  }

  // A handle that attributes every request made through it to `label`.
  // The handle shares the root client's state (including the ledger)
  // through its prototype, so concurrent handles never clobber each other.
  step(label) {
    const bound = Object.create(this);
    bound.label = label;
    return bound;
  }

  async fetchJson(path) {
    const { response, entry } = await this.tracedFetch(
      path,
      { headers: { accept: 'application/json' } },
      'json'
    );
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      // Error pages are HTML; keep the raw text for diagnostics.
    }
    if (json !== null && typeof json === 'object' && !Array.isArray(json)) {
      entry.commitments = json.commitments ?? null;
    }
    if (!response.ok) {
      throw new HbError(response.status, json ?? text, path);
    }
    return decodeAoTypes(json);
  }

  async fetchBytes(path) {
    const { response } = await this.tracedFetch(path, undefined, 'bytes');
    if (!response.ok) {
      throw new HbError(response.status, await response.text(), path);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  // Fetch the committed (HTTPSig) form of an object by its native store key.
  // Deliberately NOT the JSON path: the node picks the reply codec from the
  // Accept header, and a JSON-accept response carries no Signature /
  // Signature-Input headers at all. All response headers are captured
  // before the body is touched and handed to the viewer together with a
  // copyable URL.
  async fetchCommittedForm(key) {
    const path = `/~cache@1.0/read?read=${encodeURIComponent(key)}`;
    const { response } = await this.tracedFetch(path, undefined, 'committed');
    const headers = {};
    for (const [name, value] of response.headers) {
      headers[name] = value;
    }
    let bodyLength = null;
    try {
      bodyLength = (await response.arrayBuffer()).byteLength;
    } catch {
      // The headers are the evidence here; an unreadable body only means
      // the length stays unknown.
    }
    return {
      url: this.baseUrl + path,
      status: response.status,
      ok: response.ok,
      headers,
      bodyLength,
    };
  }

  // The node fronts upstream LBRY infrastructure that occasionally returns
  // transient errors; retry a 5xx once before concluding anything from it.
  // All requests here are idempotent GETs, and fail-closed conclusions
  // (like the anonymous verified-stream case) remain valid after a retry.
  async fetchWithRetry(path, options) {
    const response = await fetch(this.baseUrl + path, options);
    if (response.status < 500) return response;
    await new Promise((resolve) => setTimeout(resolve, 400));
    return fetch(this.baseUrl + path, options);
  }

  async tracedFetch(path, options, kind) {
    const started = Date.now();
    const entry = {
      label: this.label,
      method: 'GET',
      path,
      kind,
      status: null,
      ms: null,
      headers: {},
      commitments: null,
      error: null,
    };
    this.exchanges.push(entry);
    let response;
    try {
      response = await this.fetchWithRetry(path, options);
    } catch (err) {
      entry.ms = Date.now() - started;
      entry.error = String(err);
      throw err;
    }
    entry.ms = Date.now() - started;
    entry.status = response.status;
    for (const name of PICKED_HEADERS) {
      const value = response.headers.get(name);
      if (value !== null) entry.headers[name] = value;
    }
    return { response, entry };
  }

  async deref(msg, key) {
    if (msg == null) return null;
    if (msg[key] !== undefined && typeof msg[key] === 'object') {
      return msg[key];
    }
    const linkId = msg[`${key}+link`];
    if (typeof linkId === 'string') {
      return this.fetchJson(`/${linkId}`);
    }
    return msg[key] ?? null;
  }

  // Walk a path through a message, dereferencing links as needed.
  async derefPath(msg, keys) {
    let current = msg;
    for (const key of keys) {
      current = await this.deref(current, key);
      if (current === null || typeof current !== 'object') break;
    }
    return current;
  }

  claim(target) {
    return this.fetchJson(`/${DEVICE}/claim?${targetQuery(target)}`);
  }

  transaction(txid) {
    return this.fetchJson(
      `/${DEVICE}/transaction?txid=${encodeURIComponent(txid)}`
    );
  }

  verifiedStream(target) {
    return this.fetchJson(
      `/${DEVICE}/verified-stream?${targetQuery(target)}`
    );
  }

  blob(hash) {
    return this.fetchBytes(`/${DEVICE}/blob?hash=${encodeURIComponent(hash)}`);
  }

  mediaUrl(sdHash) {
    return `${this.baseUrl}/${DEVICE}/media?sd-hash=${encodeURIComponent(sdHash)}`;
  }

  // Probe the media endpoint with a one-byte range and read the node's
  // reported totals from Content-Range, for cross-checking against the
  // client-computed exact size.
  async mediaProbe(sdHash) {
    const path = `/${DEVICE}/media?sd-hash=${encodeURIComponent(sdHash)}`;
    const { response } = await this.tracedFetch(
      path,
      { headers: { Range: 'bytes=0-0' } },
      'probe'
    );
    if (!response.ok) {
      throw new HbError(response.status, await response.text(), 'media probe');
    }
    await response.arrayBuffer();
    const contentRange = response.headers.get('content-range') ?? '';
    const match = contentRange.match(/^bytes \d+-\d+\/(\d+|\*)$/);
    return {
      total: match && match[1] !== '*' ? parseInt(match[1], 10) : null,
      sizeSource: response.headers.get('byte-size-source'),
    };
  }
}

export function classifyTarget(input) {
  const value = input.trim();
  const outpoint = value.match(/^([0-9a-fA-F]{64}):(\d+)$/);
  if (outpoint) {
    return {
      param: 'txid',
      value: outpoint[1].toLowerCase(),
      nout: parseInt(outpoint[2], 10),
      kind: 'outpoint',
    };
  }
  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    return { param: 'txid', value: value.toLowerCase(), kind: 'txid' };
  }
  if (/^[0-9a-fA-F]{40}$/.test(value)) {
    return { param: 'claim-id', value: value.toLowerCase(), kind: 'claim-id' };
  }
  if (/^(lbry|https?):\/\//.test(value)) {
    return { param: 'url', value, kind: 'url' };
  }
  return { param: 'name', value, kind: 'name' };
}

// Render-by-ID targets skip the resolve locator entirely.
export function isTxidTarget(target) {
  return target.kind === 'txid' || target.kind === 'outpoint';
}

function targetQuery(target) {
  return `${target.param}=${encodeURIComponent(target.value)}`;
}

// `ao-types: key="atom", other="integer"` annotates JSON values that HTTP
// flattened to strings. Decode the common scalar types in place.
export function decodeAoTypes(msg) {
  if (msg == null || typeof msg !== 'object' || Array.isArray(msg)) return msg;
  const types = parseAoTypes(msg['ao-types']);
  const out = {};
  for (const [key, value] of Object.entries(msg)) {
    if (key === 'ao-types') continue;
    out[key] = decodeValue(value, types.get(key));
  }
  return out;
}

function parseAoTypes(header) {
  const types = new Map();
  if (typeof header !== 'string') return types;
  for (const part of header.split(',')) {
    const match = part.trim().match(/^(.+?)="(.+?)"$/);
    if (match) types.set(match[1], match[2]);
  }
  return types;
}

function decodeValue(value, type) {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return decodeAoTypes(value);
  }
  if (type === 'atom') {
    if (value === 'true') return true;
    if (value === 'false') return false;
    return value;
  }
  if (type === 'integer') return parseInt(value, 10);
  if (type === 'float') return parseFloat(value);
  return value;
}
