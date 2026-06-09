import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, sha256, sha384 };

export function reverseBytes(bytes) {
  return Uint8Array.from(bytes).reverse();
}

export function reverseHex(bytes) {
  return bytesToHex(reverseBytes(bytes));
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function doubleSha256(bytes) {
  return sha256(sha256(bytes));
}

export function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

export function le32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

export function be32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function utf8Decode(bytes) {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function isValidHex(value, byteLength) {
  return (
    typeof value === 'string' &&
    value.length === byteLength * 2 &&
    /^[0-9a-f]+$/.test(value)
  );
}

export function isHexString(value) {
  return (
    typeof value === 'string' &&
    value.length % 2 === 0 &&
    /^[0-9a-f]*$/.test(value)
  );
}
