import { describe, it, expect } from 'vitest';
import { parseTxHex, parseClaimEnvelope, claimOutputAt, TxParseError } from '../src/lbry/tx.js';
import { utf8Decode } from '../src/lbry/bytes.js';
import {
  ONCHAIN_TX_HEX,
  ONCHAIN_TXID,
  ONCHAIN_PREV_TXID,
  ONCHAIN_CLAIM_ID,
  ONCHAIN_SIGNING_CHANNEL_ID,
} from './fixtures.js';

describe('parseTxHex (real on-chain vector)', () => {
  const tx = parseTxHex(ONCHAIN_TX_HEX);

  it('computes the txid', () => {
    expect(tx.txid).toBe(ONCHAIN_TXID);
  });

  it('parses the first input outpoint', () => {
    expect(tx.inputs).toHaveLength(1);
    expect(tx.inputs[0].prevTxid).toBe(ONCHAIN_PREV_TXID);
    expect(tx.inputs[0].prevNout).toBe(1);
    expect(tx.inputs[0].signatureDigestPiece).toHaveLength(36);
  });

  it('parses output amounts', () => {
    expect(tx.outputs).toHaveLength(2);
    expect(tx.outputs[0].amount).toBe(100000n);
    expect(tx.outputs[1].amount).toBe(344174550n);
  });

  it('derives the create-claim claim id via hash160', () => {
    const output = claimOutputAt(tx, 0);
    expect(output.claimOp).toBe('create');
    expect(output.claimId).toBe(ONCHAIN_CLAIM_ID);
  });

  it('parses the signed v2 claim envelope', () => {
    const envelope = claimOutputAt(tx, 0).claimEnvelope;
    expect(envelope.encoding).toBe('v2-protobuf');
    expect(envelope.signed).toBe(true);
    expect(envelope.signingChannelId).toBe(ONCHAIN_SIGNING_CHANNEL_ID);
    expect(envelope.claimSignature).toHaveLength(64);
    expect(envelope.message.length).toBeGreaterThan(0);
  });

  it('decodes the claim name', () => {
    const output = claimOutputAt(tx, 0);
    expect(utf8Decode(output.claimName)).toContain('Affaire');
  });
});

describe('parseClaimEnvelope', () => {
  it('parses unsigned v2 envelopes', () => {
    const envelope = parseClaimEnvelope(Uint8Array.from([0, 1, 2, 3]));
    expect(envelope.signed).toBe(false);
    expect(envelope.encoding).toBe('v2-protobuf');
    expect(envelope.message).toEqual(Uint8Array.from([1, 2, 3]));
  });

  it('classifies v0 JSON envelopes', () => {
    const raw = new TextEncoder().encode('{"ver":"0.0.1"}');
    expect(parseClaimEnvelope(raw).encoding).toBe('v0-json');
  });

  it('classifies v1 protobuf envelopes', () => {
    expect(parseClaimEnvelope(Uint8Array.from([8, 1])).encoding).toBe(
      'v1-protobuf'
    );
  });

  it('rejects truncated signed envelopes', () => {
    expect(() => parseClaimEnvelope(Uint8Array.from([1, 2, 3]))).toThrow(
      TxParseError
    );
  });
});

describe('parse failures', () => {
  it('rejects truncated transactions', () => {
    expect(() => parseTxHex(ONCHAIN_TX_HEX.slice(0, 100))).toThrow(TxParseError);
  });

  it('rejects trailing bytes', () => {
    expect(() => parseTxHex(ONCHAIN_TX_HEX + '00')).toThrow(TxParseError);
  });
});
