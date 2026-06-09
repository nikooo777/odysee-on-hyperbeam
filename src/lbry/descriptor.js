// Port of HyperBEAM's hb_lbry_stream_descriptor: stream descriptor parsing,
// structural validation, SHA-384 verification, AES-128-CBC blob decryption
// (WebCrypto strips PKCS7 padding), and exact stream size computation.
//
// Hashing rules: every blob hash is SHA-384 over the ENCRYPTED bytes; the
// descriptor's own hash (the sd_hash) is SHA-384 over the raw descriptor
// JSON bytes exactly as fetched — no canonicalization.
import {
  bytesToHex,
  hexToBytes,
  sha384,
  isValidHex,
  isHexString,
  utf8Decode,
  concatBytes,
} from './bytes.js';

export const MAX_BLOB_SIZE = 2097152;
export const PLAIN_BLOB_STRIDE = MAX_BLOB_SIZE - 1;

export class DescriptorError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}

export function blobHashHex(bytes) {
  return bytesToHex(sha384(bytes));
}

export function parseDescriptor(rawBytes, expectedSdHash) {
  const actualHash = blobHashHex(rawBytes);
  if (actualHash !== expectedSdHash.toLowerCase()) {
    throw new DescriptorError('sd_hash_mismatch', actualHash);
  }
  let decoded;
  try {
    decoded = JSON.parse(utf8Decode(rawBytes));
  } catch {
    throw new DescriptorError('invalid_descriptor_json');
  }
  if (typeof decoded !== 'object' || decoded === null) {
    throw new DescriptorError('invalid_descriptor_json');
  }
  if (typeof decoded.stream_type !== 'string' || decoded.stream_type.length === 0) {
    throw new DescriptorError('invalid_stream_type');
  }
  if (!isHexString(decoded.stream_name)) {
    throw new DescriptorError('invalid_stream_name');
  }
  if (!isHexString(decoded.suggested_file_name)) {
    throw new DescriptorError('invalid_suggested_file_name');
  }
  if (!isValidHex(decoded.key, 16)) {
    throw new DescriptorError('invalid_key');
  }
  if (!isValidHex(decoded.stream_hash, 48)) {
    throw new DescriptorError('invalid_stream_hash');
  }
  if (!Array.isArray(decoded.blobs) || decoded.blobs.length < 2) {
    throw new DescriptorError('invalid_blobs');
  }
  const blobs = decoded.blobs.map((entry, index) =>
    validateBlobEntry(entry, index, decoded.blobs.length)
  );
  return {
    raw: rawBytes,
    sdHash: actualHash,
    streamType: decoded.stream_type,
    streamNameHex: decoded.stream_name,
    suggestedFileNameHex: decoded.suggested_file_name,
    fileName: safeHexUtf8(decoded.suggested_file_name),
    keyHex: decoded.key,
    streamHash: decoded.stream_hash,
    blobs,
    stride: PLAIN_BLOB_STRIDE,
  };
}

function safeHexUtf8(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) return null;
  try {
    return utf8Decode(hexToBytes(hex));
  } catch {
    return null;
  }
}

function validateBlobEntry(entry, index, total) {
  if (typeof entry !== 'object' || entry === null) {
    throw new DescriptorError('invalid_blob_entry', `#${index}`);
  }
  if (entry.blob_num !== index) {
    throw new DescriptorError('blob_order_mismatch', `#${index}`);
  }
  if (!isValidHex(entry.iv, 16)) {
    throw new DescriptorError('invalid_iv', `#${index}`);
  }
  const isLast = index === total - 1;
  if (isLast) {
    if (entry.blob_hash !== undefined || entry.length !== 0) {
      throw new DescriptorError('missing_terminator');
    }
    return { blobNum: index, length: 0, ivHex: entry.iv, terminator: true };
  }
  if (!isValidHex(entry.blob_hash, 48)) {
    throw new DescriptorError('invalid_blob_hash', `#${index}`);
  }
  const isFinalData = index === total - 2;
  if (!Number.isInteger(entry.length) || entry.length <= 0) {
    throw new DescriptorError('invalid_blob_length', `#${index}`);
  }
  if (isFinalData) {
    if (entry.length > MAX_BLOB_SIZE || entry.length % 16 !== 0) {
      throw new DescriptorError('invalid_blob_length', `#${index}`);
    }
  } else if (entry.length !== MAX_BLOB_SIZE) {
    throw new DescriptorError('invalid_blob_length', `#${index}`);
  }
  return {
    blobNum: index,
    length: entry.length,
    ivHex: entry.iv,
    blobHash: entry.blob_hash,
    terminator: false,
  };
}

export function dataBlobs(descriptor) {
  return descriptor.blobs.filter((blob) => !blob.terminator);
}

export function verifyBlobBytes(blob, bytes) {
  if (bytes.length !== blob.length) {
    throw new DescriptorError('length_mismatch', `#${blob.blobNum}`);
  }
  const actual = blobHashHex(bytes);
  if (actual !== blob.blobHash) {
    throw new DescriptorError('hash_mismatch', `#${blob.blobNum}`);
  }
}

export async function decryptBlob(keyHex, ivHex, cipherBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(keyHex),
    { name: 'AES-CBC' },
    false,
    ['decrypt']
  );
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: hexToBytes(ivHex) },
    key,
    cipherBytes
  );
  return new Uint8Array(plain);
}

export function streamSize(descriptor, lastPlaintextLength) {
  const count = dataBlobs(descriptor).length;
  return descriptor.stride * (count - 1) + lastPlaintextLength;
}

export async function reassemble(descriptor, fetchBlob) {
  const chunks = [];
  for (const blob of dataBlobs(descriptor)) {
    const cipher = await fetchBlob(blob.blobHash);
    verifyBlobBytes(blob, cipher);
    chunks.push(await decryptBlob(descriptor.keyHex, blob.ivHex, cipher));
  }
  return concatBytes(...chunks);
}
