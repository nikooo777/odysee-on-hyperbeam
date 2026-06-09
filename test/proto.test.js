import { describe, it, expect } from 'vitest';
import { streamSdHash, channelPublicKey, ProtoError } from '../src/lbry/proto.js';
import { parseTxHex, claimOutputAt } from '../src/lbry/tx.js';
import {
  ONCHAIN_TX_HEX,
  ONCHAIN_SD_HASH,
  protoField,
} from './fixtures.js';

describe('streamSdHash', () => {
  it('extracts the sd_hash from the on-chain signed claim message', () => {
    const tx = parseTxHex(ONCHAIN_TX_HEX);
    const envelope = claimOutputAt(tx, 0).claimEnvelope;
    expect(streamSdHash(envelope.message)).toBe(ONCHAIN_SD_HASH);
  });

  it('fails on a message without a stream field', () => {
    const message = protoField(2, Uint8Array.from([1, 2, 3]));
    expect(() => streamSdHash(message)).toThrow(/missing_stream/);
  });

  it('fails on a stream without a source field', () => {
    const message = protoField(1, protoField(2, Uint8Array.from([1])));
    expect(() => streamSdHash(message)).toThrow(/missing_source/);
  });

  it('fails on a source without an sd_hash field', () => {
    const message = protoField(1, protoField(1, protoField(5, Uint8Array.from([1]))));
    expect(() => streamSdHash(message)).toThrow(/missing_sd_hash/);
  });

  it('fails on an sd_hash of the wrong length', () => {
    const message = protoField(
      1,
      protoField(1, protoField(6, new Uint8Array(47)))
    );
    expect(() => streamSdHash(message)).toThrow(/invalid_sd_hash_length/);
  });
});

describe('channelPublicKey', () => {
  it('extracts the raw key bytes from Claim.channel.public_key', () => {
    const key = new Uint8Array(33).fill(7);
    const message = protoField(2, protoField(1, key));
    expect(channelPublicKey(message)).toEqual(key);
  });

  it('returns DER/SPKI bytes for legacy channels untouched', () => {
    const spki = new Uint8Array(88).fill(9);
    const message = protoField(2, protoField(1, spki));
    expect(channelPublicKey(message)).toEqual(spki);
  });

  it('fails when the channel field is missing', () => {
    const message = protoField(1, Uint8Array.from([1]));
    expect(() => channelPublicKey(message)).toThrow(/missing_channel/);
  });

  it('fails when the public key field is missing', () => {
    const message = protoField(2, protoField(2, Uint8Array.from([1])));
    expect(() => channelPublicKey(message)).toThrow(/missing_public_key/);
  });

  it('propagates malformed protobuf errors', () => {
    expect(() => channelPublicKey(Uint8Array.from([0x12]))).toThrow(ProtoError);
  });
});
