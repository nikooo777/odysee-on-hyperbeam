import { describe, it, expect } from 'vitest';
import {
  parseDescriptor,
  dataBlobs,
  verifyBlobBytes,
  decryptBlob,
  streamSize,
  reassemble,
  blobHashHex,
  MAX_BLOB_SIZE,
  PLAIN_BLOB_STRIDE,
  DescriptorError,
} from '../src/lbry/descriptor.js';
import { bytesToHex } from '../src/lbry/bytes.js';

const KEY = Uint8Array.from({ length: 16 }, (_, i) => i);
const IV = Uint8Array.from({ length: 16 }, (_, i) => 16 + i);
const PLAINTEXT = new TextEncoder().encode('hello verified legacy stream');

async function encryptBlob(keyBytes, ivBytes, plaintext) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: ivBytes },
    key,
    plaintext
  );
  return new Uint8Array(cipher);
}

async function sampleDescriptor() {
  const cipher = await encryptBlob(KEY, IV, PLAINTEXT);
  const descriptor = {
    stream_type: 'lbryfile',
    stream_name: bytesToHex(new TextEncoder().encode('sample.mp4')),
    key: bytesToHex(KEY),
    suggested_file_name: bytesToHex(new TextEncoder().encode('sample.mp4')),
    stream_hash: blobHashHex(new TextEncoder().encode('stream hash test')),
    blobs: [
      {
        length: cipher.length,
        blob_num: 0,
        iv: bytesToHex(IV),
        blob_hash: blobHashHex(cipher),
      },
      { length: 0, blob_num: 1, iv: bytesToHex(new Uint8Array(16)) },
    ],
  };
  const raw = new TextEncoder().encode(JSON.stringify(descriptor));
  return { raw, sdHash: blobHashHex(raw), cipher, json: descriptor };
}

describe('parseDescriptor', () => {
  it('parses and verifies a valid descriptor', async () => {
    const { raw, sdHash, cipher } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    expect(descriptor.fileName).toBe('sample.mp4');
    expect(descriptor.keyHex).toBe(bytesToHex(KEY));
    expect(dataBlobs(descriptor)).toHaveLength(1);
    expect(dataBlobs(descriptor)[0].blobHash).toBe(blobHashHex(cipher));
    expect(descriptor.stride).toBe(PLAIN_BLOB_STRIDE);
  });

  it('rejects a descriptor whose hash does not match', async () => {
    const { raw } = await sampleDescriptor();
    const wrong = blobHashHex(new Uint8Array([1]));
    expect(() => parseDescriptor(raw, wrong)).toThrow(/sd_hash_mismatch/);
  });

  it('rejects a short non-final data blob', async () => {
    const { json } = await sampleDescriptor();
    json.blobs = [
      { ...json.blobs[0], blob_num: 0, length: 1024 },
      { ...json.blobs[0], blob_num: 1 },
      { length: 0, blob_num: 2, iv: json.blobs[1].iv },
    ];
    const raw = new TextEncoder().encode(JSON.stringify(json));
    expect(() => parseDescriptor(raw, blobHashHex(raw))).toThrow(
      /invalid_blob_length/
    );
  });

  it('rejects a missing terminator', async () => {
    const { json } = await sampleDescriptor();
    json.blobs = [json.blobs[0]];
    const raw = new TextEncoder().encode(JSON.stringify(json));
    expect(() => parseDescriptor(raw, blobHashHex(raw))).toThrow(
      DescriptorError
    );
  });

  it('rejects a missing stream_type', async () => {
    const { json } = await sampleDescriptor();
    delete json.stream_type;
    const raw = new TextEncoder().encode(JSON.stringify(json));
    expect(() => parseDescriptor(raw, blobHashHex(raw))).toThrow(
      /invalid_stream_type/
    );
  });

  it('rejects a non-hex stream_name', async () => {
    const { json } = await sampleDescriptor();
    json.stream_name = 'not hex!';
    const raw = new TextEncoder().encode(JSON.stringify(json));
    expect(() => parseDescriptor(raw, blobHashHex(raw))).toThrow(
      /invalid_stream_name/
    );
  });

  it('rejects a non-hex suggested_file_name', async () => {
    const { json } = await sampleDescriptor();
    json.suggested_file_name = 'abc';
    const raw = new TextEncoder().encode(JSON.stringify(json));
    expect(() => parseDescriptor(raw, blobHashHex(raw))).toThrow(
      /invalid_suggested_file_name/
    );
  });

  it('rejects out-of-order blob numbers', async () => {
    const { json } = await sampleDescriptor();
    json.blobs[0].blob_num = 1;
    json.blobs[1].blob_num = 0;
    const raw = new TextEncoder().encode(JSON.stringify(json));
    expect(() => parseDescriptor(raw, blobHashHex(raw))).toThrow(
      /blob_order_mismatch/
    );
  });
});

describe('blob verification and decryption', () => {
  it('verifies and decrypts a blob, stripping PKCS7 padding', async () => {
    const { raw, sdHash, cipher } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    const [blob] = dataBlobs(descriptor);
    verifyBlobBytes(blob, cipher);
    const plain = await decryptBlob(descriptor.keyHex, blob.ivHex, cipher);
    expect(plain).toEqual(PLAINTEXT);
  });

  it('rejects corrupted blob bytes', async () => {
    const { raw, sdHash, cipher } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    const [blob] = dataBlobs(descriptor);
    const corrupted = Uint8Array.from(cipher);
    corrupted[0] ^= 0xff;
    expect(() => verifyBlobBytes(blob, corrupted)).toThrow(/hash_mismatch/);
  });

  it('rejects truncated blob bytes', async () => {
    const { raw, sdHash, cipher } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    const [blob] = dataBlobs(descriptor);
    expect(() => verifyBlobBytes(blob, cipher.subarray(1))).toThrow(
      /length_mismatch/
    );
  });
});

describe('streamSize and reassemble', () => {
  it('computes exact size from the final blob plaintext', async () => {
    const { raw, sdHash } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    expect(streamSize(descriptor, PLAINTEXT.length)).toBe(PLAINTEXT.length);
  });

  it('uses the stride for multi-blob streams', async () => {
    const { raw, sdHash } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    const fake = {
      ...descriptor,
      blobs: [
        { blobNum: 0, length: MAX_BLOB_SIZE, terminator: false },
        { blobNum: 1, length: 1024, terminator: false },
        { blobNum: 2, length: 0, terminator: true },
      ],
    };
    expect(streamSize(fake, 1000)).toBe(PLAIN_BLOB_STRIDE + 1000);
  });

  it('reassembles the full plaintext via a fetch callback', async () => {
    const { raw, sdHash, cipher } = await sampleDescriptor();
    const descriptor = parseDescriptor(raw, sdHash);
    const bytes = await reassemble(descriptor, async () => cipher);
    expect(bytes).toEqual(PLAINTEXT);
  });
});
