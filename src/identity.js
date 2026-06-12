// Native LBRY identifier → HyperBEAM commitment id conversion, matching the
// backend's hb_lbry_commitment:commitment_id/1 exactly: 32-byte native ids
// (transaction ids) encode directly as the base64url human id; everything
// else (blob hashes, outpoints, claim ids) is SHA-256 hashed first so the
// key survives wire round-trips at a fixed width. The original native bytes
// are never lost: the commitment message carries them verbatim in its
// `native-id` field and (encoded) in its `signature` field.
import { sha256, hexToBytes, concatBytes, be32 } from './lbry/bytes.js';

export function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function commitmentIdFromNative(nativeBytes) {
  const id = nativeBytes.length === 32 ? nativeBytes : sha256(nativeBytes);
  return base64url(id);
}

export function conversionRule(nativeBytes) {
  if (nativeBytes.length === 32) {
    return '32-byte native id → base64url, directly';
  }
  return `SHA-256 of the ${nativeBytes.length}-byte native id → base64url`;
}

// The native byte forms per object kind, mirroring the Erlang constructors:
// display-order txid bytes for transactions, raw hash bytes for blobs,
// txid bytes plus the big-endian output index for outpoints, and the
// 20-byte claim id bytes for claim ids.
export function nativeBytesFor(kind, value) {
  switch (kind) {
    case 'txid':
    case 'blob':
    case 'claim-id':
      return hexToBytes(value);
    case 'outpoint': {
      const [txid, nout] = value.split(':');
      return concatBytes(hexToBytes(txid), be32(parseInt(nout, 10)));
    }
    default:
      throw new Error(`unknown identity kind: ${kind}`);
  }
}

export function identityTriplet(kind, value) {
  const nativeBytes = nativeBytesFor(kind, value);
  return {
    kind,
    native: value,
    commitmentId: commitmentIdFromNative(nativeBytes),
    rule: conversionRule(nativeBytes),
  };
}
