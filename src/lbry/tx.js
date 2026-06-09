// Port of HyperBEAM's hb_lbry_tx: raw LBRY transaction and claim-script
// parsing. Mirrors its semantics exactly, including the limitations:
// non-segwit serialization only, fail closed on anything unparseable.
import {
  bytesToHex,
  hexToBytes,
  reverseHex,
  concatBytes,
  doubleSha256,
  hash160,
  be32,
  le32,
} from './bytes.js';

const OP_CLAIM_NAME = 0xb5;
const OP_UPDATE_CLAIM = 0xb7;
const OP_2DROP = 0x6d;
const OP_DROP = 0x75;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  take(size) {
    if (this.offset + size > this.bytes.length) {
      throw new TxParseError('truncated_binary');
    }
    const out = this.bytes.subarray(this.offset, this.offset + size);
    this.offset += size;
    return out;
  }

  uint8() {
    return this.take(1)[0];
  }

  int32le() {
    const value = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return value;
  }

  uint32le() {
    if (this.offset + 4 > this.bytes.length) {
      throw new TxParseError('truncated_uint32');
    }
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  uint64le() {
    if (this.offset + 8 > this.bytes.length) {
      throw new TxParseError('truncated_uint64');
    }
    const value = this.view.getBigUint64(this.offset, true);
    this.offset += 8;
    return value;
  }

  varint() {
    const first = this.uint8();
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const bytes = this.take(2);
      return bytes[0] | (bytes[1] << 8);
    }
    if (first === 0xfe) return this.uint32le();
    const value = this.uint64le();
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new TxParseError('invalid_varint');
    }
    return Number(value);
  }

  varbytes() {
    return this.take(this.varint());
  }

  atEnd() {
    return this.offset === this.bytes.length;
  }
}

export class TxParseError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function txid(raw) {
  return reverseHex(doubleSha256(raw));
}

export function parseTxHex(hex) {
  return parseTx(hexToBytes(hex));
}

export function parseTx(raw) {
  const reader = new Reader(raw);
  const version = reader.int32le();
  const inputCount = reader.varint();
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxHash = reader.take(32);
    const prevNout = reader.uint32le();
    const script = reader.varbytes();
    const sequence = reader.uint32le();
    inputs.push({
      prevTxHash,
      prevTxid: reverseHex(prevTxHash),
      prevNout,
      script,
      sequence,
      signatureDigestPiece: concatBytes(prevTxHash, le32(prevNout)),
    });
  }
  const outputCount = reader.varint();
  const txHash = doubleSha256(raw);
  const outputs = [];
  for (let position = 0; position < outputCount; position++) {
    const amount = reader.uint64le();
    const script = reader.varbytes();
    const output = { amount, nout: position, script };
    const claim = parseClaimScript(script, txHash, position);
    if (claim) Object.assign(output, claim);
    outputs.push(output);
  }
  const lockTime = reader.uint32le();
  if (!reader.atEnd()) {
    throw new TxParseError('trailing_bytes');
  }
  return {
    raw,
    version,
    txid: txid(raw),
    inputs,
    outputs,
    lockTime,
  };
}

function readPush(reader) {
  const first = reader.uint8();
  if (first === 0) return new Uint8Array(0);
  if (first > 0 && first < OP_PUSHDATA1) return reader.take(first);
  if (first === OP_PUSHDATA1) return reader.take(reader.uint8());
  if (first === OP_PUSHDATA2) {
    const bytes = reader.take(2);
    return reader.take(bytes[0] | (bytes[1] << 8));
  }
  if (first === OP_PUSHDATA4) return reader.take(reader.uint32le());
  throw new TxParseError('invalid_pushdata');
}

function parseClaimScript(script, txHash, position) {
  if (script.length === 0) return null;
  try {
    if (script[0] === OP_CLAIM_NAME) {
      const reader = new Reader(script.subarray(1));
      const name = readPush(reader);
      const claimBytes = readPush(reader);
      if (reader.uint8() !== OP_2DROP || reader.uint8() !== OP_DROP) {
        return null;
      }
      const claimHash = hash160(concatBytes(txHash, be32(position)));
      return {
        claimOp: 'create',
        claimName: name,
        claim: claimBytes,
        claimId: reverseHex(claimHash),
        claimHash,
        claimEnvelope: parseClaimEnvelope(claimBytes),
        paymentScript: reader.bytes.subarray(reader.offset),
      };
    }
    if (script[0] === OP_UPDATE_CLAIM) {
      const reader = new Reader(script.subarray(1));
      const name = readPush(reader);
      const claimHash = readPush(reader);
      const claimBytes = readPush(reader);
      if (reader.uint8() !== OP_2DROP || reader.uint8() !== OP_2DROP) {
        return null;
      }
      return {
        claimOp: 'update',
        claimName: name,
        claim: claimBytes,
        claimId: reverseHex(claimHash),
        claimHash,
        claimEnvelope: parseClaimEnvelope(claimBytes),
        paymentScript: reader.bytes.subarray(reader.offset),
      };
    }
  } catch (err) {
    if (err instanceof TxParseError) return null;
    throw err;
  }
  return null;
}

export function parseClaimEnvelope(raw) {
  if (raw.length === 0) {
    throw new TxParseError('invalid_claim_envelope');
  }
  if (raw[0] === 0) {
    return {
      raw,
      encoding: 'v2-protobuf',
      signed: false,
      message: raw.subarray(1),
    };
  }
  if (raw[0] === 1) {
    if (raw.length < 1 + 20 + 64 + 1) {
      throw new TxParseError('invalid_claim_envelope');
    }
    const signingChannelHash = raw.subarray(1, 21);
    return {
      raw,
      encoding: 'v2-protobuf',
      signed: true,
      signingChannelHash,
      signingChannelId: reverseHex(signingChannelHash),
      claimSignature: raw.subarray(21, 85),
      message: raw.subarray(85),
    };
  }
  if (raw[0] === 0x7b) {
    return { raw, encoding: 'v0-json', signed: false, message: raw };
  }
  return { raw, encoding: 'v1-protobuf', signed: false, message: raw };
}

export function claimOutputAt(tx, nout) {
  return (
    tx.outputs.find(
      (output) => output.nout === nout && output.claimEnvelope !== undefined
    ) ?? null
  );
}

export { bytesToHex };
