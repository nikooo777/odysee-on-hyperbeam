// Port of HyperBEAM's hb_lbry_attestation digest construction and ECDSA
// verification. The v2 LBRY claim-signature digest is a single SHA-256 over:
//   first_input.prev_tx_hash (32B, internal order)
//   first_input.vout         (4B, little-endian)
//   signing_channel_hash     (20B, internal order)
//   bare protobuf message    (claim value without the envelope)
//
// Verification options are deliberately explicit and must not change:
// prehash:false because the digest above is the exact signed payload
// (@noble/secp256k1 v3 hashes the message with SHA-256 by default), and
// lowS:false because on-chain LBRY signatures may be high-S — the
// server-side OpenSSL verifier accepts them and this verifier must not be
// stricter.
import * as secp from '@noble/secp256k1';
import { sha256, concatBytes, hexToBytes } from './bytes.js';

// DER SubjectPublicKeyInfo prefixes for secp256k1 EC keys, matched
// byte-exactly: SEQUENCE { SEQUENCE { OID ecPublicKey, OID secp256k1 },
// BIT STRING { 0x00, point } }. Old lbry-sdk channels stored their public
// key in this form; matching the full prefix (curve OID included) means
// unknown curves or encodings fail closed instead of being misread.
const SPKI_SECP256K1_UNCOMPRESSED = hexToBytes(
  '3056301006072a8648ce3d020106052b8104000a034200'
);
const SPKI_SECP256K1_COMPRESSED = hexToBytes(
  '3036301006072a8648ce3d020106052b8104000a032200'
);

export class PublicKeyError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// Normalize a channel public key to 33-byte compressed SEC1, validating
// that the point is actually on the secp256k1 curve.
export function normalizePublicKey(bytes) {
  const point = rawPoint(bytes);
  try {
    return secp.Point.fromBytes(point).toBytes(true);
  } catch {
    throw new PublicKeyError('invalid_channel_public_key');
  }
}

function rawPoint(bytes) {
  if (bytes.length === 33 || (bytes.length === 65 && bytes[0] === 0x04)) {
    return bytes;
  }
  if (startsWith(bytes, SPKI_SECP256K1_UNCOMPRESSED) && bytes.length === 88) {
    return bytes.subarray(SPKI_SECP256K1_UNCOMPRESSED.length);
  }
  if (startsWith(bytes, SPKI_SECP256K1_COMPRESSED) && bytes.length === 56) {
    return bytes.subarray(SPKI_SECP256K1_COMPRESSED.length);
  }
  throw new PublicKeyError('unsupported_channel_public_key');
}

function startsWith(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix[i]) return false;
  }
  return true;
}

export function signatureDigest(firstInput, envelope) {
  return sha256(
    concatBytes(
      firstInput.signatureDigestPiece,
      envelope.signingChannelHash,
      envelope.message
    )
  );
}

export function verifyClaimSignature(signature, digest, publicKey) {
  if (signature.length !== 64) return false;
  if (publicKey.length !== 33) return false;
  try {
    return secp.verify(signature, digest, publicKey, {
      prehash: false,
      lowS: false,
    });
  } catch {
    return false;
  }
}
