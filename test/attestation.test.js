import { describe, it, expect } from 'vitest';
import * as secp from '@noble/secp256k1';
import {
  signatureDigest,
  verifyClaimSignature,
  normalizePublicKey,
} from '../src/lbry/attestation.js';
import { parseTxHex, claimOutputAt } from '../src/lbry/tx.js';
import { hexToBytes, bytesToHex, concatBytes } from '../src/lbry/bytes.js';
import { TASK0_TX_HEX, TASK0_CHANNEL_PUBKEY_HEX } from './fixtures.js';

function task0Parts() {
  const tx = parseTxHex(TASK0_TX_HEX);
  return {
    firstInput: tx.inputs[0],
    envelope: claimOutputAt(tx, 0).claimEnvelope,
    publicKey: hexToBytes(TASK0_CHANNEL_PUBKEY_HEX),
  };
}

describe('verifyClaimSignature (Task-0 real on-chain signature)', () => {
  it('verifies the real channel signature', () => {
    const { firstInput, envelope, publicKey } = task0Parts();
    const digest = signatureDigest(firstInput, envelope);
    expect(
      verifyClaimSignature(envelope.claimSignature, digest, publicKey)
    ).toBe(true);
  });

  it('rejects a tampered signature', () => {
    const { firstInput, envelope, publicKey } = task0Parts();
    const digest = signatureDigest(firstInput, envelope);
    const tampered = Uint8Array.from(envelope.claimSignature);
    tampered[10] ^= 0xff;
    expect(verifyClaimSignature(tampered, digest, publicKey)).toBe(false);
  });

  it('rejects a tampered message', () => {
    const { firstInput, envelope, publicKey } = task0Parts();
    const tamperedMessage = Uint8Array.from(envelope.message);
    tamperedMessage[0] ^= 0x01;
    const digest = signatureDigest(firstInput, {
      ...envelope,
      message: tamperedMessage,
    });
    expect(
      verifyClaimSignature(envelope.claimSignature, digest, publicKey)
    ).toBe(false);
  });

  it('rejects the wrong public key', () => {
    const { firstInput, envelope } = task0Parts();
    const digest = signatureDigest(firstInput, envelope);
    const wrongKey = hexToBytes(
      '0378ff344cc1f8a5451e7b8f348670b20c44ae44704ac05c59fb936ac1a4f26769'
    );
    expect(
      verifyClaimSignature(envelope.claimSignature, digest, wrongKey)
    ).toBe(false);
  });

  it('rejects malformed inputs without throwing', () => {
    const { firstInput, envelope, publicKey } = task0Parts();
    const digest = signatureDigest(firstInput, envelope);
    expect(verifyClaimSignature(new Uint8Array(63), digest, publicKey)).toBe(
      false
    );
    expect(
      verifyClaimSignature(envelope.claimSignature, digest, new Uint8Array(32))
    ).toBe(false);
  });
});

describe('normalizePublicKey', () => {
  const compressed = hexToBytes(TASK0_CHANNEL_PUBKEY_HEX);
  const uncompressed = secp.Point.fromBytes(compressed).toBytes(false);

  it('passes through a valid compressed key', () => {
    expect(bytesToHex(normalizePublicKey(compressed))).toBe(
      TASK0_CHANNEL_PUBKEY_HEX
    );
  });

  it('compresses a bare uncompressed point', () => {
    expect(bytesToHex(normalizePublicKey(uncompressed))).toBe(
      TASK0_CHANNEL_PUBKEY_HEX
    );
  });

  it('normalizes a legacy DER/SPKI uncompressed key', () => {
    const spki = concatBytes(
      hexToBytes('3056301006072a8648ce3d020106052b8104000a034200'),
      uncompressed
    );
    expect(spki).toHaveLength(88);
    expect(bytesToHex(normalizePublicKey(spki))).toBe(
      TASK0_CHANNEL_PUBKEY_HEX
    );
  });

  it('normalizes a DER/SPKI compressed key', () => {
    const spki = concatBytes(
      hexToBytes('3036301006072a8648ce3d020106052b8104000a032200'),
      compressed
    );
    expect(spki).toHaveLength(56);
    expect(bytesToHex(normalizePublicKey(spki))).toBe(
      TASK0_CHANNEL_PUBKEY_HEX
    );
  });

  it('rejects SPKI for a different curve (P-256)', () => {
    const p256Spki = concatBytes(
      hexToBytes('3059301306072a8648ce3d020106082a8648ce3d030107034200'),
      uncompressed
    );
    expect(() => normalizePublicKey(p256Spki)).toThrow(
      /unsupported_channel_public_key/
    );
  });

  it('rejects off-curve points', () => {
    // x = 0 is not on secp256k1 (7 is not a quadratic residue mod p).
    const offCurve = new Uint8Array(33);
    offCurve[0] = 0x02;
    expect(() => normalizePublicKey(offCurve)).toThrow(
      /invalid_channel_public_key/
    );
  });

  it('rejects unrecognized key shapes', () => {
    expect(() => normalizePublicKey(new Uint8Array(40))).toThrow(
      /unsupported_channel_public_key/
    );
  });
});
