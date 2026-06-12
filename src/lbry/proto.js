// Port of HyperBEAM's hb_lbry_claim_proto: a minimal protobuf wire-format
// walker that extracts exactly the fields the verification chain needs.
// Field paths (LBRY claim schema):
//   Claim.stream  = field 1 -> Stream.source = field 1 -> Source.sd_hash = field 6
//   Claim.channel = field 2 -> Channel.public_key = field 1
import { bytesToHex } from './bytes.js';

export class ProtoError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function readVarint(bytes, offset) {
  let value = 0n;
  let shift = 0n;
  let pos = offset;
  for (;;) {
    if (pos >= bytes.length) throw new ProtoError('truncated_varint');
    const byte = bytes[pos];
    value |= BigInt(byte & 0x7f) << shift;
    pos += 1;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
    if (shift > 63n) throw new ProtoError('varint_overflow');
  }
  return [value, pos];
}

function* fields(message) {
  let offset = 0;
  while (offset < message.length) {
    const [key, afterKey] = readVarint(message, offset);
    const fieldNumber = Number(key >> 3n);
    const wireType = Number(key & 7n);
    offset = afterKey;
    if (wireType === 0) {
      const [value, next] = readVarint(message, offset);
      offset = next;
      yield { fieldNumber, wireType, value };
    } else if (wireType === 1) {
      if (offset + 8 > message.length) throw new ProtoError('truncated_fixed64');
      yield { fieldNumber, wireType, value: message.subarray(offset, offset + 8) };
      offset += 8;
    } else if (wireType === 2) {
      const [length, next] = readVarint(message, offset);
      const size = Number(length);
      if (next + size > message.length) {
        throw new ProtoError('truncated_length_delimited');
      }
      yield { fieldNumber, wireType, value: message.subarray(next, next + size) };
      offset = next + size;
    } else if (wireType === 5) {
      if (offset + 4 > message.length) throw new ProtoError('truncated_fixed32');
      yield { fieldNumber, wireType, value: message.subarray(offset, offset + 4) };
      offset += 4;
    } else {
      throw new ProtoError('unsupported_wire_type');
    }
  }
}

export function lengthField(message, fieldNumber) {
  for (const field of fields(message)) {
    if (field.fieldNumber === fieldNumber && field.wireType === 2) {
      return field.value;
    }
  }
  return null;
}

export function streamSdHash(message) {
  const stream = lengthField(message, 1);
  if (stream === null) throw new ProtoError('missing_stream');
  const source = lengthField(stream, 1);
  if (source === null) throw new ProtoError('missing_source');
  const sdHash = lengthField(source, 6);
  if (sdHash === null) throw new ProtoError('missing_sd_hash');
  if (sdHash.length !== 48) throw new ProtoError('invalid_sd_hash_length');
  return bytesToHex(sdHash);
}

// Source.media_type (field 4) of the signed stream claim, or null when the
// message does not carry one — callers fall back to a default. Best-effort
// by design: a malformed message returns null rather than failing the chain.
export function streamMediaType(message) {
  try {
    const stream = lengthField(message, 1);
    if (stream === null) return null;
    const source = lengthField(stream, 1);
    if (source === null) return null;
    const mediaType = lengthField(source, 4);
    if (mediaType === null) return null;
    return new TextDecoder('utf-8', { fatal: true }).decode(mediaType);
  } catch {
    return null;
  }
}

// Returns the raw public-key field bytes: 33-byte compressed SEC1 for
// modern channels, DER/SPKI for channels created by old lbry-sdk versions.
// Shape normalization happens in attestation.normalizePublicKey.
export function channelPublicKey(message) {
  const channel = lengthField(message, 2);
  if (channel === null) throw new ProtoError('missing_channel');
  const publicKey = lengthField(channel, 1);
  if (publicKey === null || publicKey.length === 0) {
    throw new ProtoError('missing_public_key');
  }
  return publicKey;
}
