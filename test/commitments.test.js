import { describe, it, expect } from 'vitest';
import {
  parseSignatureInput,
  parseSignatureHeader,
  commitmentAlg,
  normalizeBodyCommitments,
  classifyCommitment,
  commitmentEntries,
  messageIdFromHeaders,
} from '../src/commitments.js';
import { ONCHAIN_TXID, ONCHAIN_CLAIM_ID, ONCHAIN_SD_HASH } from './fixtures.js';

// Vectors captured verbatim from a live dev node on 2026-06-12: committed
// store reads of the frozen on-chain fixture objects. The transaction
// vector carries all three alg classes as dictionary members in one header.
const TX_SIGNATURE_INPUT =
  'comm-dnyepeqnvoy82vu0as7vtwqjfxm8rulfdmxy9inca8e=("content-digest" "content-type" "device" "txid");alg="lbry-transaction@1.0/sha-256d";native-id="51d3cd6a27420addb648347410233931b862ab52660c1dba58806b5b0f38a460";native-id-type="txid", ' +
  'comm-o3lhkxruvopkzkgzweg29qnwmbvgl3t8r0mvi1dl5hy=("ao-types" "content-digest" "content-type" "device" "inputs+link" "lock-time" "outputs+link" "status" "txid" "version");alg="hmac-sha256";keyid="constant:ao", ' +
  'comm-rizjhe6pf5mngrgzdkvr2qncvzx5o5-roq_ws-zhie8=("ao-types" "content-digest" "content-type" "device" "inputs+link" "lock-time" "outputs+link" "status" "txid" "version");alg="rsa-pss-sha512";keyid="publickey:mllGNv6nk1t1NndSCsLlkQQZhtyMK6+5J42+TPTAsjlUHsMeGfLzjk/rDMqufU/zRi7mZ6UyaK8AJZiUrYgpXIDQrWLbuYJ2pF9TevsrBLT1xfHSAb66HQdKcjGXqZNJolwgR7k9CvmRJCbRsOTmfktRf/o8lx2GC1baYYH+DaV0x1ChsvkwrsyQ7GNzAqx2z/XUVZE3lMYXb75GWtCjOzs+tBuEUuWaK4QKK7XGGoRJ3LKruH9Wbz6+OAYSaBCWdMY5zT7UlYYwEQ/SIUCmJjPXTtlrxpFP+mWTHaShM/umTMZSKShSAyJa5QMp0XdknvqNFG2lOvFkHPfhGJI7cakotkfWFo4MHyYuDXXwsikae5zLfzs1cLKv55SC9w2MrcduE5CjeJFGoE8Q1QtdxQCFtpoA3GP94nb/QQF5Qk9JXsYqKIIo9X6lpoKUWSY5B5NvHGeFna8WttoMG6Rj2BLkwFcXJXoRHkphpb4Gon0LNeci9rdWoPps2Xuy/8sKPIvJO99m2uCYODC38aLA33XA3YR24ahca5+qo7YQL1jQ+SczVF48mwOM1xJV+70CMkhD90mn5gPfJefa61DdI+zR5OzKKKBtVBJyEI/fBbFYdMWRsmrbGGhkFpRb6eQNICy0+c2uEmyeXd/pT1HFNV1GzXf0ylLWMQm7e+AS878=";tag="6slomYGPNzgbLgEip_029ifg8Bz9Xhn--fPtrJCWmlc/du2OKjcsgj2uG92IeBhJotRvTkfVU2ldWPu7o3NUnC8"';

// The claim-output member exercises hyphenated parameters beyond
// native-id/native-id-type: claim-id, claim-op, claim-proof-strength.
const CLAIM_MEMBER =
  'comm-varoxo18t9mf8wftk3rvzph908uvjydg8z2z3zgqxmk=("claim-id" "claim-name" "claim-op" "claim-proof-strength" "content-digest" "content-type" "device" "nout" "txid");alg="lbry-claim@1.0/hash160-outpoint";claim-id="9cc7f0e3de8db3b2ffd6dc0b4f1a0f0ca48a6b49";claim-op="create";claim-proof-strength="hash-derived";native-id="51d3cd6a27420addb648347410233931b862ab52660c1dba58806b5b0f38a46000000000";native-id-type="outpoint"';

const BLOB_MEMBER =
  'comm-rqqea8ei7jtdet4awxp3mgwsvbel55dhmnl4ymedl60=("ao-body-key" "blob-hash" "content-digest" "device");alg="lbry-blob@1.0/sha-384";native-id="3da16b833f169c21caeb62ca66111227413f30f63c9d2f52f2a787643e086c334ee6949e05875cfe94a816aba02e492e";native-id-type="blob-hash"';

// A real facade (verified-stream sublink) JSON body commitments map: the
// node transport signature plus the hmac, and nothing else — facade views
// never carry LBRY commitments. Long signature values truncated; the
// classifier only reads commitment-device, type, and keyid.
const FACADE_BODY_COMMITMENTS = {
  IRLpl_KlQq2zbpdXCro0dnUhqNX86k34527KKFV85yw: {
    'commitment-device': 'httpsig@1.0',
    committed: ['ao-types', 'claim-id', 'device', 'name', 'nout', 'raw', 'signing-channel', 'status', 'txid'],
    committer: '1xlmbBNLA9KXE8A99EWIs3pL11pizmuTih0iY3x7',
    keyid: 'publickey:mllGNv6nk1t1NndSCsLlkQQZhtyMK6',
    signature: 'WD4C8cVeZBsAO3QzvHjoxPserf173TaGJNqXbKUc',
    tag: 'XFc5ZTtJUqT-Hr8w_mDMZ9peznBmyM7kTofOeDWs',
    type: 'rsa-pss-sha512',
  },
  MDmWpyFMKBGJRtkVuk1FocHeuJjStd_ygbibBv7P_lM: {
    'commitment-device': 'httpsig@1.0',
    committed: ['ao-types', 'claim-id', 'device', 'name', 'nout', 'raw', 'signing-channel', 'status', 'txid'],
    keyid: 'constant:ao',
    signature: 'MDmWpyFMKBGJRtkVuk1FocHeuJjStd_ygbibBv7P',
    type: 'hmac-sha256',
  },
};

// JSON-encoded committed store reads do not occur on the wire (the JSON
// codec rejects raw binary fields), so the LBRY body-commitment fixture is
// synthetic — built from the same values the real HTTPSig wire form above
// carries, which is exactly what a body-encoded LBRY commitment contains.
const COMMITTED_READ_BODY_COMMITMENT = {
  UdPNaidCCt22SDR0ECM5Mbhiq1JmDB26WIBrWw84pGA: {
    'commitment-device': 'lbry-transaction@1.0',
    committed: ['device', 'raw', 'txid'],
    'native-id': ONCHAIN_TXID,
    'native-id-type': 'txid',
    signature: 'UdPNaidCCt22SDR0ECM5Mbhiq1JmDB26WIBrWw84pGA',
    type: 'sha-256d',
  },
};

describe('parseSignatureInput', () => {
  it('parses all three alg classes from one real multi-member header', () => {
    const entries = parseSignatureInput(TX_SIGNATURE_INPUT);
    expect(entries).toHaveLength(3);
    const [lbry, hmac, rsa] = entries;
    expect(lbry.params.alg).toBe('lbry-transaction@1.0/sha-256d');
    expect(lbry.params['native-id']).toBe(ONCHAIN_TXID);
    expect(lbry.params['native-id-type']).toBe('txid');
    expect(lbry.covered).toEqual([
      'content-digest',
      'content-type',
      'device',
      'txid',
    ]);
    expect(hmac.params.alg).toBe('hmac-sha256');
    expect(hmac.params.keyid).toBe('constant:ao');
    expect(hmac.covered).toContain('inputs+link');
    expect(rsa.params.alg).toBe('rsa-pss-sha512');
    expect(rsa.params.keyid.startsWith('publickey:')).toBe(true);
    expect(rsa.params.tag).toBeDefined();
  });

  it('parses the claim member with its hyphenated parameters', () => {
    const [entry] = parseSignatureInput(CLAIM_MEMBER);
    expect(entry.params.alg).toBe('lbry-claim@1.0/hash160-outpoint');
    expect(entry.params['claim-id']).toBe(ONCHAIN_CLAIM_ID);
    expect(entry.params['claim-op']).toBe('create');
    expect(entry.params['claim-proof-strength']).toBe('hash-derived');
    expect(entry.params['native-id']).toBe(`${ONCHAIN_TXID}00000000`);
    expect(entry.params['native-id-type']).toBe('outpoint');
  });

  it('parses the blob member with the body-encoded covered list', () => {
    const [entry] = parseSignatureInput(BLOB_MEMBER);
    expect(entry.params.alg).toBe('lbry-blob@1.0/sha-384');
    expect(entry.params['native-id']).toBe(ONCHAIN_SD_HASH);
    expect(entry.covered).toContain('ao-body-key');
    expect(entry.covered).toContain('content-digest');
  });

  it('returns an empty list for missing headers', () => {
    expect(parseSignatureInput(undefined)).toEqual([]);
    expect(parseSignatureInput('')).toEqual([]);
  });
});

describe('parseSignatureHeader', () => {
  it('parses dictionary members with byte-sequence values', () => {
    const parsed = parseSignatureHeader('a=:Zm9v:, b=:YmFy:');
    expect(parsed.get('a')).toBe('Zm9v');
    expect(parsed.get('b')).toBe('YmFy');
  });
});

describe('commitmentAlg', () => {
  it('uses the bare type for the httpsig device', () => {
    expect(
      commitmentAlg({ 'commitment-device': 'httpsig@1.0', type: 'rsa-pss-sha512' })
    ).toBe('rsa-pss-sha512');
    expect(
      commitmentAlg({ 'commitment-device': 'httpsig@1.0', type: 'hmac-sha256' })
    ).toBe('hmac-sha256');
  });

  it('uses device/type for every other commitment device', () => {
    expect(
      commitmentAlg({ 'commitment-device': 'lbry-blob@1.0', type: 'sha-384' })
    ).toBe('lbry-blob@1.0/sha-384');
    expect(commitmentAlg({ 'commitment-device': 'lbry-stream@1.0' })).toBe(
      'lbry-stream@1.0'
    );
  });
});

describe('shared classification across encodings', () => {
  it('classifies the facade JSON body fixture as transport plus derived', () => {
    const entries = normalizeBodyCommitments(FACADE_BODY_COMMITMENTS);
    const classes = entries.map((entry) => classifyCommitment(entry.params));
    expect(classes.sort()).toEqual(['derived', 'transport']);
    expect(classes).not.toContain('source');
  });

  it('maps the synthetic committed-read body commitment to the same class as its header form', () => {
    const [bodyEntry] = normalizeBodyCommitments(COMMITTED_READ_BODY_COMMITMENT);
    const [headerEntry] = parseSignatureInput(TX_SIGNATURE_INPUT);
    expect(bodyEntry.params.alg).toBe(headerEntry.params.alg);
    expect(bodyEntry.params['native-id']).toBe(headerEntry.params['native-id']);
    expect(classifyCommitment(bodyEntry.params)).toBe('source');
    expect(classifyCommitment(headerEntry.params)).toBe('source');
  });

  it('classifies header members consistently with the body rule', () => {
    const entries = parseSignatureInput(TX_SIGNATURE_INPUT);
    expect(entries.map((e) => classifyCommitment(e.params))).toEqual([
      'source',
      'derived',
      'transport',
    ]);
  });
});

describe('commitmentEntries', () => {
  it('renders from headers when signature-input is present', () => {
    const entries = commitmentEntries({
      headers: { 'signature-input': BLOB_MEMBER },
      commitments: FACADE_BODY_COMMITMENTS,
    });
    expect(entries).toHaveLength(1);
    expect(entries[0].encoding).toBe('httpsig');
    expect(entries[0].cls).toBe('source');
  });

  it('falls back to body commitments for JSON responses', () => {
    const entries = commitmentEntries({
      headers: { 'content-type': 'application/json' },
      commitments: FACADE_BODY_COMMITMENTS,
    });
    expect(entries).toHaveLength(2);
    expect(entries.every((entry) => entry.encoding === 'json')).toBe(true);
  });

  it('returns nothing for plain byte responses', () => {
    expect(commitmentEntries({ headers: {}, commitments: null })).toEqual([]);
  });
});

describe('messageIdFromHeaders', () => {
  it('recovers the message id from the derived hmac signature value', () => {
    // Real pair from a committed transaction read: the hmac member's
    // Signature dictionary value is the message id in standard base64.
    const headers = {
      'signature-input':
        'comm-o3lhkxruvopkzkgzweg29qnwmbvgl3t8r0mvi1dl5hy=("device" "txid");alg="hmac-sha256";keyid="constant:ao"',
      signature:
        'comm-o3lhkxruvopkzkgzweg29qnwmbvgl3t8r0mvi1dl5hy=:vLGb3HMghMqndr8FqHmOk7/DsS+yphHe6Mxb0qs3WOI=:',
    };
    expect(messageIdFromHeaders(headers)).toBe(
      'vLGb3HMghMqndr8FqHmOk7_DsS-yphHe6Mxb0qs3WOI'
    );
  });

  it('returns null when no derived commitment is present', () => {
    expect(messageIdFromHeaders({ 'signature-input': BLOB_MEMBER })).toBe(null);
    expect(messageIdFromHeaders({})).toBe(null);
  });
});
