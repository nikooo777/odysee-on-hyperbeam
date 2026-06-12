import { describe, it, expect } from 'vitest';
import { runPipeline } from '../src/pipeline.js';
import { concatBytes, bytesToHex, le32 } from '../src/lbry/bytes.js';
import { txid as txidOf } from '../src/lbry/tx.js';
import { protoField } from './fixtures.js';

// Synthetic on-chain material: minimal but fully parseable transactions
// whose claim scripts carry real v2 protobuf envelopes, so the txid-mode
// pipeline semantics are pinned without any network or frozen hex blobs.
const SD_HASH_BYTES = Uint8Array.from({ length: 48 }, (_, i) => i + 1);
const SD_HASH_HEX = bytesToHex(SD_HASH_BYTES);

function streamClaimBytes() {
  const source = concatBytes(
    protoField(4, new TextEncoder().encode('video/mp4')),
    protoField(6, SD_HASH_BYTES)
  );
  return concatBytes(Uint8Array.of(0), protoField(1, protoField(1, source)));
}

function channelClaimBytes() {
  const publicKey = Uint8Array.from({ length: 33 }, (_, i) => i);
  return concatBytes(
    Uint8Array.of(0),
    protoField(2, protoField(1, publicKey))
  );
}

function push(bytes) {
  if (bytes.length >= 0x4c) throw new Error('test push helper: too long');
  return concatBytes(Uint8Array.of(bytes.length), bytes);
}

// OP_CLAIM_NAME <name> <claim> OP_2DROP OP_DROP — a create claim script.
function claimScript(name, claimBytes) {
  return concatBytes(
    Uint8Array.of(0xb5),
    push(new TextEncoder().encode(name)),
    push(claimBytes),
    Uint8Array.of(0x6d, 0x75)
  );
}

function varint(value) {
  if (value >= 0xfd) throw new Error('test varint helper: too large');
  return Uint8Array.of(value);
}

function buildTx(outputScripts) {
  const input = concatBytes(
    new Uint8Array(32),
    le32(0),
    Uint8Array.of(0),
    Uint8Array.of(0xff, 0xff, 0xff, 0xff)
  );
  return concatBytes(
    le32(1),
    varint(1),
    input,
    varint(outputScripts.length),
    ...outputScripts.map((script) =>
      concatBytes(new Uint8Array(8), varint(script.length), script)
    ),
    le32(0)
  );
}

function stubHb(overrides = {}) {
  const hb = {
    step() {
      return hb;
    },
    async claim() {
      throw new Error('claim not stubbed');
    },
    async transaction() {
      throw new Error('transaction not stubbed');
    },
    async verifiedStream() {
      throw new Error('verified-stream unavailable');
    },
    async blob() {
      throw new Error('blob fetch not stubbed');
    },
    async mediaProbe() {
      throw new Error('media probe not stubbed');
    },
    async deref(msg, key) {
      if (msg == null) return null;
      const value = msg[key];
      return typeof value === 'object' ? value : (value ?? null);
    },
    ...overrides,
  };
  return hb;
}

async function run(input, hbOverrides) {
  const calls = [];
  const report = (step, status, detail = '', evidence = []) =>
    calls.push({ step, status, detail, evidence });
  const state = await runPipeline({
    input,
    hb: stubHb(hbOverrides),
    report,
  });
  const final = new Map();
  for (const call of calls) final.set(call.step, call);
  return { state, calls, final };
}

function servesRaw(raw) {
  return { transaction: async () => ({ 'raw-hex': bytesToHex(raw) }) };
}

describe('txid-mode pipeline semantics', () => {
  it('runs render-by-ID for a bare txid: resolve na, auto-selected stream output', async () => {
    const raw = buildTx([claimScript('a', streamClaimBytes())]);
    const { state, final } = await run(txidOf(raw), servesRaw(raw));
    expect(final.get('input').status).toBe('verified');
    expect(final.get('resolve').status).toBe('na');
    expect(final.get('resolve').detail).toContain('no locator used');
    expect(final.get('stream-tx').status).toBe('verified');
    expect(final.get('claim-output').status).toBe('verified');
    expect(final.get('claim-output').detail).toContain('selected output 0');
    expect(final.get('sd-hash').status).toBe('verified');
    expect(state.sdHash).toBe(SD_HASH_HEX);
    expect(state.resolved.contentType).toBe('video/mp4');
    expect(final.get('descriptor').status).toBe('failed');
  });

  it('does not flag auto-selection for an explicit txid:nout outpoint', async () => {
    const raw = buildTx([claimScript('a', streamClaimBytes())]);
    const { final } = await run(`${txidOf(raw)}:0`, servesRaw(raw));
    expect(final.get('resolve').status).toBe('na');
    expect(
      final.get('resolve').evidence.some((line) => line.startsWith('nout (typed): 0'))
    ).toBe(true);
    expect(final.get('claim-output').status).toBe('verified');
    expect(final.get('claim-output').detail).not.toContain('selected output');
  });

  it('fails early when an explicit outpoint is a channel claim', async () => {
    const raw = buildTx([claimScript('ch', channelClaimBytes())]);
    const { final } = await run(`${txidOf(raw)}:0`, servesRaw(raw));
    expect(final.get('claim-output').status).toBe('failed');
    expect(final.get('claim-output').detail).toContain('channel claim');
  });

  it('asks for the explicit form when several stream claim outputs exist', async () => {
    const raw = buildTx([
      claimScript('a', streamClaimBytes()),
      claimScript('b', streamClaimBytes()),
    ]);
    const { final } = await run(txidOf(raw), servesRaw(raw));
    expect(final.get('claim-output').status).toBe('failed');
    expect(final.get('claim-output').detail).toContain('txid:nout');
  });

  it('fails a bare txid whose transaction has no stream claim output', async () => {
    const raw = buildTx([new Uint8Array(0)]);
    const { final } = await run(txidOf(raw), servesRaw(raw));
    expect(final.get('claim-output').status).toBe('failed');
    expect(final.get('claim-output').detail).toContain('no stream claim output');
  });

  it('reports the cross-check as na when the server attests a different outpoint', async () => {
    const raw = buildTx([claimScript('a', streamClaimBytes())]);
    const otherTxid = 'ff'.repeat(32);
    const { final, calls } = await run(`${txidOf(raw)}:0`, {
      ...servesRaw(raw),
      verifiedStream: async () => ({
        stream: { txid: otherTxid, nout: 1 },
        txid: otherTxid,
      }),
    });
    expect(final.get('cross-check').status).toBe('na');
    expect(final.get('cross-check').detail).toContain('different outpoint');
    expect(calls.some((call) => call.status === 'mismatch')).toBe(false);
  });

  it('runs the full matrix when the server attests the requested outpoint', async () => {
    const raw = buildTx([claimScript('a', streamClaimBytes())]);
    const id = txidOf(raw);
    const { final } = await run(`${id}:0`, {
      ...servesRaw(raw),
      verifiedStream: async () => ({
        stream: { txid: id, nout: 0 },
        txid: id,
        attestation: { valid: true, 'signature-valid': true, 'channel-hash-valid': true },
        'signed-sd-hash': SD_HASH_HEX,
        'claim-op': 'create',
        'channel-claim-op': 'create',
        'claim-proof-strength': 'hash-derived',
        'channel-claim-proof-strength': 'hash-derived',
        'proof-strength': 'hash-derived',
      }),
    });
    // The client chain failed at the descriptor (no blob stub), so a
    // matrix that ran must diverge — the point here is the outpoint gate
    // opening, not agreement.
    expect(final.get('cross-check').status).toBe('mismatch');
    expect(final.get('cross-check').detail).toContain('divergence');
  });
});
