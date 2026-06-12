import { describe, it, expect } from 'vitest';
import {
  commitmentIdFromNative,
  conversionRule,
  nativeBytesFor,
  identityTriplet,
} from '../src/identity.js';
import { ONCHAIN_TXID, ONCHAIN_CLAIM_ID, ONCHAIN_SD_HASH } from './fixtures.js';

// Expected values produced by the Erlang side
// (hb_lbry_commitment:commitment_id/1) for the frozen on-chain fixtures.
const ERLANG_VECTORS = [
  {
    kind: 'txid',
    value: ONCHAIN_TXID,
    id: 'UdPNaidCCt22SDR0ECM5Mbhiq1JmDB26WIBrWw84pGA',
    rule: '32-byte native id → base64url, directly',
  },
  {
    kind: 'blob',
    value: ONCHAIN_SD_HASH,
    id: 'RQqeA8EI7jTdET4aWxp3MGWsvbEl55DhMNl4ymEdl60',
    rule: 'SHA-256 of the 48-byte native id → base64url',
  },
  {
    kind: 'outpoint',
    value: `${ONCHAIN_TXID}:0`,
    id: 'VaROxo18t9mf8WfTk3rvzpH908uVJydg8Z2Z3zgqXmk',
    rule: 'SHA-256 of the 36-byte native id → base64url',
  },
  {
    kind: 'claim-id',
    value: ONCHAIN_CLAIM_ID,
    id: '4KX1y2h-r7UYE-4yVyEOOqoLHRm2gS7i9v9emjV1BXo',
    rule: 'SHA-256 of the 20-byte native id → base64url',
  },
];

describe('commitment id conversion', () => {
  for (const vector of ERLANG_VECTORS) {
    it(`matches the Erlang value for the ${vector.kind} fixture`, () => {
      const triplet = identityTriplet(vector.kind, vector.value);
      expect(triplet.commitmentId).toBe(vector.id);
      expect(triplet.rule).toBe(vector.rule);
    });
  }

  it('encodes 32-byte ids directly and hashes everything else', () => {
    const txidBytes = nativeBytesFor('txid', ONCHAIN_TXID);
    expect(txidBytes).toHaveLength(32);
    expect(commitmentIdFromNative(txidBytes)).toBe(ERLANG_VECTORS[0].id);
    const claimBytes = nativeBytesFor('claim-id', ONCHAIN_CLAIM_ID);
    expect(claimBytes).toHaveLength(20);
    expect(conversionRule(claimBytes)).toContain('SHA-256');
  });

  it('builds outpoint bytes as txid bytes plus big-endian nout', () => {
    const bytes = nativeBytesFor('outpoint', `${ONCHAIN_TXID}:1`);
    expect(bytes).toHaveLength(36);
    expect([...bytes.slice(32)]).toEqual([0, 0, 0, 1]);
  });
});
