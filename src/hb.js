// HyperBEAM node client. The node is treated as an untrusted courier: every
// byte that feeds a verification verdict is re-checked client-side, so this
// module only handles transport mechanics:
//  - JSON requests via `accept: application/json`
//  - ao-types annotations (atoms/integers arrive as strings)
//  - submessage links: nested maps come back as `<key>+link` entries whose
//    value is a message ID, dereferenced with GET /<id> from the node cache.
const DEVICE = '~odysee@1.0';

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
  }

  async fetchJson(path) {
    const response = await fetch(this.baseUrl + path, {
      headers: { accept: 'application/json' },
    });
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      // Error pages are HTML; keep the raw text for diagnostics.
    }
    if (!response.ok) {
      throw new HbError(response.status, json ?? text, path);
    }
    return decodeAoTypes(json);
  }

  async fetchBytes(path) {
    const response = await fetch(this.baseUrl + path);
    if (!response.ok) {
      throw new HbError(response.status, await response.text(), path);
    }
    return new Uint8Array(await response.arrayBuffer());
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
    const response = await fetch(this.mediaUrl(sdHash), {
      headers: { Range: 'bytes=0-0' },
    });
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
  if (/^[0-9a-fA-F]{40}$/.test(value)) {
    return { param: 'claim-id', value: value.toLowerCase(), kind: 'claim-id' };
  }
  if (/^(lbry|https?):\/\//.test(value)) {
    return { param: 'url', value, kind: 'url' };
  }
  return { param: 'name', value, kind: 'name' };
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
