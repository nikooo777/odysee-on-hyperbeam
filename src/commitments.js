// Commitment parsing and classification. The canonical object is the
// message's `commitments` map: `Signature`/`Signature-Input` headers are its
// HTTPSig wire encoding, and JSON replies carry the same map in the body.
// Both encodings normalize into one display shape here, and one shared
// classifier decides what each commitment means:
//   - alg `lbry-*`: a source-format commitment (the litmus line)
//   - alg `rsa-pss-sha512` / `publickey:` keyid: the node transport signature
//   - alg `hmac-sha256` + keyid `constant:ao`: the derived message-id
//     commitment (HyperBEAM's content addressing)

// Parse the RFC 9421 Signature-Input dictionary subset HyperBEAM emits:
//   label=("field" "field");param="value";param2="value", label2=(...)...
export function parseSignatureInput(header) {
  if (typeof header !== 'string' || header.trim() === '') return [];
  const entries = [];
  let i = 0;
  const skipSpace = () => {
    while (i < header.length && (header[i] === ' ' || header[i] === '\t')) i++;
  };
  const readQuoted = () => {
    i++;
    let out = '';
    while (i < header.length && header[i] !== '"') {
      if (header[i] === '\\' && i + 1 < header.length) i++;
      out += header[i];
      i++;
    }
    i++;
    return out;
  };
  while (i < header.length) {
    skipSpace();
    let start = i;
    while (i < header.length && header[i] !== '=') i++;
    const label = header.slice(start, i);
    i++;
    if (header[i] !== '(') {
      throw new Error(`signature-input member ${label} is not an inner list`);
    }
    i++;
    const covered = [];
    while (i < header.length && header[i] !== ')') {
      skipSpace();
      if (header[i] === '"') {
        covered.push(readQuoted());
      } else {
        i++;
      }
    }
    i++;
    const params = {};
    while (i < header.length && header[i] === ';') {
      i++;
      start = i;
      while (i < header.length && header[i] !== '=' && header[i] !== ';' && header[i] !== ',') {
        i++;
      }
      const key = header.slice(start, i);
      if (header[i] === '=') {
        i++;
        if (header[i] === '"') {
          params[key] = readQuoted();
        } else {
          start = i;
          while (i < header.length && header[i] !== ';' && header[i] !== ',') i++;
          params[key] = header.slice(start, i);
        }
      } else {
        params[key] = true;
      }
    }
    entries.push({ label, covered, params });
    skipSpace();
    if (header[i] === ',') i++;
  }
  return entries;
}

// Parse the matching Signature dictionary: label=:base64:, label2=:base64:
export function parseSignatureHeader(header) {
  const out = new Map();
  if (typeof header !== 'string') return out;
  for (const match of header.matchAll(/([^,=\s][^=]*)=:([^:]*):/g)) {
    out.set(match[1].trim(), match[2]);
  }
  return out;
}

// Body commitments carry no `alg` field; derive it with the codec's own
// rule (commitment_to_alg in dev_httpsig_siginfo): the `httpsig@1.0`
// device's alg is the bare `type`, every other device encodes as
// `commitment-device` plus `/type` when a type is present.
export function commitmentAlg(commitment) {
  const device = commitment['commitment-device'];
  const type = commitment.type;
  if (device === 'httpsig@1.0') return type ?? '';
  if (typeof device !== 'string') return '';
  return type ? `${device}/${type}` : device;
}

// Normalize a body `commitments` map into the same shape the header parser
// produces, so one classifier serves both encodings.
export function normalizeBodyCommitments(map) {
  if (map === null || typeof map !== 'object') return [];
  return Object.entries(map).map(([id, commitment]) => {
    const params = { alg: commitmentAlg(commitment) };
    for (const key of ['keyid', 'native-id', 'native-id-type', 'tag']) {
      if (typeof commitment[key] === 'string') params[key] = commitment[key];
    }
    return {
      label: id,
      covered: Array.isArray(commitment.committed) ? commitment.committed : [],
      params,
    };
  });
}

// The shared classifier. Takes the params of a normalized entry (either
// encoding) and names the commitment's role.
export function classifyCommitment(params) {
  const alg = params.alg ?? '';
  const keyid = params.keyid ?? '';
  if (alg.startsWith('lbry-')) return 'source';
  if (alg === 'hmac-sha256' && keyid === 'constant:ao') return 'derived';
  if (alg === 'rsa-pss-sha512' || keyid.startsWith('publickey:')) {
    return 'transport';
  }
  return 'unknown';
}

export const CLASS_LABELS = {
  source: 'source-format commitment',
  transport: 'node transport signature',
  derived: 'derived message-id commitment',
  unknown: 'unrecognized commitment',
};

export const CLASS_NOTES = {
  source:
    'the litmus line: a commitment in the source format itself, naming the ' +
    'lbry device and the native identifier',
  transport: 'the node vouching for this response — not the source object',
  derived: "HyperBEAM's content addressing for this message",
  unknown: '',
};

// One entry point for a ledger exchange: render the commitments map from
// whichever encoding the response used — parsed headers for HTTPSig
// responses, the body `commitments` key for JSON responses.
export function commitmentEntries({ headers, commitments }) {
  const signatureInput = headers?.['signature-input'];
  if (signatureInput) {
    return parseSignatureInput(signatureInput).map((entry) => ({
      ...entry,
      cls: classifyCommitment(entry.params),
      encoding: 'httpsig',
    }));
  }
  if (commitments) {
    return normalizeBodyCommitments(commitments).map((entry) => ({
      ...entry,
      cls: classifyCommitment(entry.params),
      encoding: 'json',
    }));
  }
  return [];
}

// Recover the HyperBEAM message id from a committed (HTTPSig) response: the
// derived hmac commitment's signature value IS the message id, carried as
// standard base64 in the Signature dictionary.
export function messageIdFromHeaders(headers) {
  const entries = parseSignatureInput(headers?.['signature-input'] ?? '');
  const signatures = parseSignatureHeader(headers?.signature ?? '');
  for (const entry of entries) {
    if (classifyCommitment(entry.params) !== 'derived') continue;
    const value = signatures.get(entry.label);
    if (value) {
      return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
  }
  return null;
}
