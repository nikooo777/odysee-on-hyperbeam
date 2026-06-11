// The verification pipeline: eleven steps from user input to playable,
// client-verified bytes. Every cryptographic claim the node makes is
// re-derived here; the node is only trusted as a transport for
// content-addressed or signature-bound material.
import { classifyTarget, HbError } from './hb.js';
import { parseTxHex, claimOutputAt, txid as txidOf } from './lbry/tx.js';
import { hexToBytes, bytesToHex, reverseHex } from './lbry/bytes.js';
import { streamSdHash, channelPublicKey } from './lbry/proto.js';
import {
  signatureDigest,
  verifyClaimSignature,
  normalizePublicKey,
} from './lbry/attestation.js';
import {
  parseDescriptor,
  dataBlobs,
  verifyBlobBytes,
  decryptBlob,
  streamSize,
  blobHashHex,
} from './lbry/descriptor.js';

const identity = (value) => value;

export async function runPipeline({ input, hb, report, tamper = {} }) {
  const hooks = {
    txHex: tamper.txHex ?? identity,
    resolveSdHash: tamper.resolveSdHash ?? identity,
    channelPublicKey: tamper.channelPublicKey ?? identity,
    blobBytes: tamper.blobBytes ?? ((hash, bytes) => bytes),
    serverVerdict: tamper.serverVerdict ?? identity,
  };
  const state = {
    verdicts: {
      signatureValid: null,
      channelHashValid: null,
      signedSdHash: null,
      contentRoot: null,
      chainFailed: null,
    },
  };

  // Step 1 — parse input.
  report('input', 'running');
  const target = classifyTarget(input);
  state.target = target;
  report(
    'input',
    target.kind === 'claim-id' ? 'verified' : 'trusted',
    target.kind === 'claim-id'
      ? `claim_id root: ${target.value}`
      : `${target.kind} input — winning-claim mapping is SDK-trusted`,
    [`kind: ${target.kind}`, `target: ${target.value}`]
  );

  try {
    await resolveStep(state, hb, hooks, report);
    await streamTxStep(state, hb, hooks, report);
    await claimOutputStep(state, report);
    if (state.envelope.signed) {
      await channelEvidenceStep(state, hb, hooks, report);
      await signatureStep(state, report);
    } else {
      report('channel', 'na', 'not applicable — unsigned claim');
      report('signature', 'na', 'not applicable — unsigned claim');
    }
    await claimSdHashStep(state, report);
    await descriptorStep(state, hb, hooks, report);
    await blobSpotCheckStep(state, hb, hooks, report);
  } catch (err) {
    state.verdicts.chainFailed = err;
    if (err.step) {
      report(err.step, 'failed', err.message, err.evidence ?? []);
    } else {
      report('input', 'failed', String(err));
    }
  }

  await serverCrossCheckStep(state, hb, hooks, report);
  return state;
}

function fail(step, message, evidence) {
  const err = new Error(message);
  err.step = step;
  err.evidence = evidence;
  return err;
}

async function resolveStep(state, hb, hooks, report) {
  report('resolve', 'running');
  let msg;
  let raw;
  let value;
  let source;
  let signingChannel;
  try {
    msg = await hb.claim(state.target);
    raw = await hb.deref(msg, 'raw');
    value = await hb.deref(raw, 'value');
    source = await hb.deref(value, 'source');
    signingChannel = await hb.deref(raw, 'signing_channel');
  } catch (err) {
    throw fail('resolve', describeHttpError(err));
  }
  state.resolved = {
    claimId: msg['claim-id'] ?? raw?.claim_id,
    name: msg.name ?? raw?.name,
    txid: msg.txid ?? raw?.txid,
    nout: Number(msg.nout ?? raw?.nout),
    title: value?.title ?? null,
    contentType: source?.media_type ?? null,
    declaredSize: source?.size != null ? Number(source.size) : null,
    sdHash: hooks.resolveSdHash(source?.sd_hash?.toLowerCase() ?? null),
    channelClaimId: signingChannel?.claim_id ?? null,
    channelName: signingChannel?.name ?? null,
  };
  const r = state.resolved;
  if (!r.claimId || !r.txid || !Number.isInteger(r.nout)) {
    throw fail('resolve', 'resolve response missing claim_id/txid/nout');
  }
  if (
    state.target.kind === 'claim-id' &&
    r.claimId.toLowerCase() !== state.target.value
  ) {
    throw fail('resolve', 'node resolved a different claim than requested', [
      `requested: ${state.target.value}`,
      `resolved:  ${r.claimId.toLowerCase()}`,
    ]);
  }
  report('resolve', 'server', `${r.name ?? '?'} — claim ${r.claimId}`, [
    `claim_id: ${r.claimId}`,
    `name: ${r.name}`,
    `title: ${r.title ?? '(none)'}`,
    `outpoint: ${r.txid}:${r.nout}`,
    `sd_hash (SDK-reported): ${r.sdHash ?? '(none)'}`,
    `media_type: ${r.contentType ?? '(unknown)'}`,
    `declared size: ${r.declaredSize ?? '(unknown)'}`,
    `channel: ${r.channelName ?? '(anonymous)'} ${r.channelClaimId ?? ''}`,
    'all values above are server-claimed until verified by later steps',
  ]);
}

async function fetchVerifiedTx(hb, hooks, expectedTxid, role, step) {
  let msg;
  try {
    msg = await hb.transaction(expectedTxid);
  } catch (err) {
    throw fail(step, describeHttpError(err));
  }
  const rawHex = hooks.txHex(msg['raw-hex'], role);
  if (typeof rawHex !== 'string' || rawHex.length === 0) {
    throw fail(step, 'transaction response carries no raw-hex');
  }
  let raw;
  try {
    raw = hexToBytes(rawHex);
  } catch (err) {
    throw fail(step, `raw-hex is not valid hex: ${err.message}`);
  }
  const computedTxid = txidOf(raw);
  if (computedTxid !== expectedTxid.toLowerCase()) {
    throw fail(step, `txid mismatch: SHA256d(raw) = ${computedTxid}`, [
      `expected: ${expectedTxid}`,
      `computed: ${computedTxid}`,
      'the raw transaction bytes do not match the requested txid',
    ]);
  }
  try {
    return { rawHex, tx: parseTxHex(rawHex) };
  } catch (err) {
    throw fail(step, `transaction parse failed: ${err.message}`, [
      'fail-closed: includes segwit-serialized transactions, which this PoC does not parse',
    ]);
  }
}

async function streamTxStep(state, hb, hooks, report) {
  report('stream-tx', 'running');
  const { rawHex, tx } = await fetchVerifiedTx(
    hb,
    hooks,
    state.resolved.txid,
    'stream',
    'stream-tx'
  );
  state.rawHex = rawHex;
  state.tx = tx;
  report('stream-tx', 'verified', `txid re-computed from ${rawHex.length / 2} raw bytes`, [
    `txid: ${tx.txid}`,
    `version: ${tx.version}, inputs: ${tx.inputs.length}, outputs: ${tx.outputs.length}`,
    `first input outpoint: ${tx.inputs[0].prevTxid}:${tx.inputs[0].prevNout}`,
    'txid equality binds these raw bytes to the resolve-reported outpoint',
  ]);
}

async function claimOutputStep(state, report) {
  report('claim-output', 'running');
  const output = claimOutputAt(state.tx, state.resolved.nout);
  if (!output) {
    throw fail(
      'claim-output',
      `no claim output at nout ${state.resolved.nout}`
    );
  }
  // For claim-id inputs the binding root is the USER-TYPED value, never the
  // node-supplied resolve response — otherwise a malicious node could answer
  // claim A with claim B's internally-consistent materials.
  const typedRoot =
    state.target.kind === 'claim-id' ? state.target.value : null;
  if (typedRoot && output.claimId !== typedRoot) {
    throw fail('claim-output', 'claim id does not match your input', [
      `script-derived: ${output.claimId}`,
      `your input:     ${typedRoot}`,
      'the node served a transaction for a different claim than you asked for',
    ]);
  }
  if (output.claimId !== state.resolved.claimId.toLowerCase()) {
    throw fail('claim-output', 'claim id mismatch', [
      `script-derived: ${output.claimId}`,
      `resolved: ${state.resolved.claimId}`,
    ]);
  }
  state.claimOutput = output;
  state.envelope = output.claimEnvelope;
  if (state.envelope.encoding !== 'v2-protobuf') {
    throw fail(
      'claim-output',
      `unsupported claim encoding: ${state.envelope.encoding}`,
      ['v0/v1 legacy claims fail closed in this PoC']
    );
  }
  const inputIsRoot = state.target.kind === 'claim-id';
  const evidence = [
    `claim op: ${output.claimOp}`,
    `claim_id (${output.claimOp === 'create' ? 'hash160-derived' : 'asserted by update script'}): ${output.claimId}`,
    `envelope: ${state.envelope.encoding}, signed: ${state.envelope.signed}`,
  ];
  if (state.envelope.signed) {
    evidence.push(
      `signing channel id: ${state.envelope.signingChannelId}`,
      `signature: ${shortHex(bytesToHex(state.envelope.claimSignature))}`
    );
  }
  if (output.claimOp === 'update') {
    evidence.push(
      'update claims assert their claim_id in-script; the create-tx chain is not walked'
    );
  }
  report(
    'claim-output',
    output.claimOp === 'create' ? 'verified' : 'trusted',
    inputIsRoot && output.claimOp === 'create'
      ? 'claim_id derived from raw tx equals your input — root equality holds'
      : `claim_id ${output.claimOp === 'create' ? 'derived' : 'asserted'}: ${output.claimId}`,
    evidence
  );
}

async function channelEvidenceStep(state, hb, hooks, report) {
  report('channel', 'running');
  const expectedChannelId = state.envelope.signingChannelId;
  let channelMsg;
  try {
    channelMsg = await hb.claim({ param: 'claim-id', value: expectedChannelId });
  } catch (err) {
    throw fail('channel', `channel claim lookup failed: ${describeHttpError(err)}`);
  }
  const channelTxid = channelMsg.txid;
  const channelNout = Number(channelMsg.nout);
  if (!channelTxid || !Number.isInteger(channelNout)) {
    throw fail('channel', 'channel locator missing txid/nout');
  }
  const { tx: channelTx } = await fetchVerifiedTx(
    hb,
    hooks,
    channelTxid,
    'channel',
    'channel'
  );
  const channelOutput = claimOutputAt(channelTx, channelNout);
  if (!channelOutput) {
    throw fail('channel', `no claim output at channel nout ${channelNout}`);
  }
  if (channelOutput.claimId !== expectedChannelId) {
    throw fail('channel', 'channel claim id mismatch', [
      `expected (from stream envelope): ${expectedChannelId}`,
      `channel output claim_id: ${channelOutput.claimId}`,
    ]);
  }
  let rawKey;
  let publicKey;
  try {
    rawKey = channelPublicKey(channelOutput.claimEnvelope.message);
    publicKey = hooks.channelPublicKey(normalizePublicKey(rawKey));
  } catch (err) {
    throw fail('channel', `channel public key extraction failed: ${err.message}`);
  }
  state.channel = {
    claimId: expectedChannelId,
    txid: channelTxid,
    nout: channelNout,
    publicKey,
    claimOp: channelOutput.claimOp,
  };
  state.verdicts.channelHashValid = true;
  // An update claim only asserts its claim_id in-script, so the binding of
  // this public key to the channel id is assertion-level until the create-tx
  // chain is walked — mirror the claim-output step's honesty about it.
  const assertedBinding = channelOutput.claimOp !== 'create';
  report(
    'channel',
    assertedBinding ? 'trusted' : 'verified',
    assertedBinding
      ? `channel ${expectedChannelId} bound via update claim — assertion-level binding`
      : `channel ${expectedChannelId} bound to raw on-chain claim`,
    [
      `channel outpoint: ${channelTxid}:${channelNout}`,
      `channel claim op: ${channelOutput.claimOp}`,
      `claim_id equality: envelope signing-channel hash == channel output claim_id`,
      `public key (from raw channel protobuf, not SDK): ${bytesToHex(publicKey)}`,
      rawKey.length !== 33
        ? `normalized from ${rawKey.length}-byte DER/SPKI encoding (legacy channel)`
        : null,
      assertedBinding
        ? 'update claims assert their claim_id in-script; the create-tx chain is not walked'
        : null,
    ].filter(Boolean)
  );
}

async function signatureStep(state, report) {
  report('signature', 'running');
  const digest = signatureDigest(state.tx.inputs[0], state.envelope);
  const valid = verifyClaimSignature(
    state.envelope.claimSignature,
    digest,
    state.channel.publicKey
  );
  state.verdicts.signatureValid = valid;
  if (!valid) {
    throw fail('signature', 'secp256k1 signature verification failed', [
      `digest: ${bytesToHex(digest)}`,
      `public key: ${bytesToHex(state.channel.publicKey)}`,
      `signature: ${shortHex(bytesToHex(state.envelope.claimSignature))}`,
    ]);
  }
  report('signature', 'verified', 'channel signature verifies over the claim digest', [
    `digest = SHA256(outpoint ‖ channel_hash ‖ message): ${bytesToHex(digest)}`,
    'verified with secp256k1 (prehash: false, lowS: false)',
    `signer: channel ${state.channel.claimId}`,
  ]);
}

async function claimSdHashStep(state, report) {
  report('sd-hash', 'running');
  let extracted;
  try {
    extracted = streamSdHash(state.envelope.message);
  } catch (err) {
    throw fail('sd-hash', `sd_hash extraction failed: ${err.message}`, [
      'the on-chain claim message does not carry a stream source sd_hash',
    ]);
  }
  if (state.resolved.sdHash && extracted !== state.resolved.sdHash) {
    throw fail('sd-hash', 'sd_hash mismatch between claim and resolve', [
      `on-chain claim message: ${extracted}`,
      `SDK resolve reported: ${state.resolved.sdHash}`,
      'the server (or SDK) reported a different content root than the claim signs',
    ]);
  }
  state.sdHash = extracted;
  state.verdicts.signedSdHash = state.envelope.signed ? extracted : null;
  state.verdicts.contentRoot = state.envelope.signed
    ? 'channel-signed'
    : 'raw-claim root — no channel attestation';
  report(
    'sd-hash',
    'verified',
    state.envelope.signed
      ? `content root is channel-signed: ${shortHex(extracted)}`
      : `raw-claim root — no channel attestation: ${shortHex(extracted)}`,
    [
      `sd_hash (from on-chain claim protobuf): ${extracted}`,
      state.envelope.signed
        ? 'this hash is inside the channel-signed payload'
        : 'unsigned claim: the root binds to the claim output, no channel signs it',
      'the SDK-reported sd_hash is never used as the root',
    ]
  );
}

async function descriptorStep(state, hb, hooks, report) {
  report('descriptor', 'running');
  let rawBytes;
  try {
    rawBytes = hooks.blobBytes(state.sdHash, await hb.blob(state.sdHash), 'descriptor');
  } catch (err) {
    throw fail('descriptor', describeHttpError(err));
  }
  let descriptor;
  try {
    descriptor = parseDescriptor(rawBytes, state.sdHash);
  } catch (err) {
    throw fail('descriptor', `descriptor rejected: ${err.message}`, [
      `fetched ${rawBytes.length} bytes for sd_hash ${shortHex(state.sdHash)}`,
    ]);
  }
  state.descriptor = descriptor;
  const blobs = dataBlobs(descriptor);
  report(
    'descriptor',
    'verified',
    `SHA384(descriptor) == sd_hash; ${blobs.length} data blob(s)`,
    [
      `file name: ${descriptor.fileName ?? '(undecodable)'}`,
      `key: ${descriptor.keyHex}`,
      `data blobs: ${blobs.length} (stride ${descriptor.stride})`,
      ...blobs
        .slice(0, 5)
        .map(
          (b) => `  #${b.blobNum} len=${b.length} hash=${shortHex(b.blobHash)}`
        ),
      blobs.length > 5 ? `  … ${blobs.length - 5} more` : null,
    ].filter(Boolean)
  );
}

async function blobSpotCheckStep(state, hb, hooks, report) {
  report('blobs', 'running');
  const blobs = dataBlobs(state.descriptor);
  const first = blobs[0];
  const last = blobs[blobs.length - 1];
  const spot = first === last ? [first] : [first, last];
  for (const blob of spot) {
    let bytes;
    try {
      bytes = hooks.blobBytes(blob.blobHash, await hb.blob(blob.blobHash), 'data');
    } catch (err) {
      throw fail('blobs', `blob #${blob.blobNum}: ${describeHttpError(err)}`);
    }
    try {
      verifyBlobBytes(blob, bytes);
    } catch (err) {
      throw fail('blobs', `blob #${blob.blobNum} rejected: ${err.message}`, [
        `expected SHA-384: ${blob.blobHash}`,
        `actual SHA-384:   ${blobHashHex(bytes)}`,
        `fetched length: ${bytes.length}, descriptor length: ${blob.length}`,
      ]);
    }
    if (blob === last) {
      const plain = await decryptBlob(
        state.descriptor.keyHex,
        blob.ivHex,
        bytes
      );
      state.exactSize = streamSize(state.descriptor, plain.length);
    }
  }
  // Cross-compare against the node's media totals (an exact-size lie in
  // Content-Range would otherwise go unnoticed until playback). The spot
  // check itself is client-verified either way; a missing probe only means
  // the server-honesty cross-check could not run, shown as "trusted".
  let nodeTotal = null;
  let nodeSizeSource = null;
  let probeFailed = false;
  try {
    const probe = await hb.mediaProbe(state.sdHash);
    nodeTotal = probe.total;
    nodeSizeSource = probe.sizeSource;
    probeFailed = probe.total === null;
  } catch {
    probeFailed = true;
  }
  const nodeDiffers = nodeTotal !== null && nodeTotal !== state.exactSize;
  const declared = state.resolved.declaredSize;
  const status = nodeDiffers ? 'mismatch' : probeFailed ? 'trusted' : 'verified';
  report(
    'blobs',
    status,
    nodeDiffers
      ? `node reports ${nodeTotal} bytes where the client computed ${state.exactSize}`
      : probeFailed
        ? `spot check ok (${state.exactSize} bytes) — node total unavailable for cross-check`
        : `spot check ok — exact stream size ${state.exactSize} bytes`,
    [
      `verified blobs: ${spot.map((b) => `#${b.blobNum}`).join(', ')} of ${blobs.length}`,
      `SHA-384 over encrypted bytes matches the descriptor for each`,
      `exact size (stride × ${blobs.length - 1} + last plaintext): ${state.exactSize}`,
      nodeTotal !== null
        ? `node media total: ${nodeTotal} via ${nodeSizeSource ?? '?'} (${nodeDiffers ? 'DIFFERS' : 'matches'})`
        : 'node media total unavailable — blob verification is client-side, but the server-honesty cross-check did not run',
      declared != null
        ? `claim-declared size: ${declared} (${declared === state.exactSize ? 'matches' : 'differs — informational'})`
        : 'claim declares no size',
      blobs.length > 2
        ? 'remaining blobs verify during full sweep / verified playback'
        : null,
    ].filter(Boolean)
  );
  if (nodeDiffers) {
    state.verdicts.chainFailed = new Error('node media total mismatch');
  }
}

async function serverCrossCheckStep(state, hb, hooks, report) {
  report('cross-check', 'running');
  const clientFailed = state.verdicts.chainFailed != null;
  let server;
  try {
    server = hooks.serverVerdict(await hb.verifiedStream(state.target));
  } catch (err) {
    const reason = describeHttpError(err);
    if (state.envelope && !state.envelope.signed) {
      report(
        'cross-check',
        'na',
        'server fails closed on unsigned claims (verified-stream requires a channel signature)',
        [`server: fail-closed (${reason})`, 'client: channel attestation not applicable — consistent']
      );
      return;
    }
    if (clientFailed) {
      report('cross-check', 'verified', 'agreement: both client and server fail this stream', [
        `server: fail-closed (${reason})`,
        `client: failed (${state.verdicts.chainFailed.message})`,
      ]);
    } else {
      report(
        'cross-check',
        'mismatch',
        'server fails closed where the client verified the full chain',
        [`server: fail-closed (${reason})`, 'client: full chain verified']
      );
    }
    return;
  }
  const attestation = await hb.deref(server, 'attestation');
  // The server labels its claim-id binding strength per side
  // (claim-proof-strength, channel-claim-proof-strength) and combined
  // (proof-strength). The client re-derives what it can: a create binds
  // hash-derived, an update binds asserted unless the server proved create
  // ancestry — ancestor-derived — which the client cannot re-derive (yet)
  // and accepts as trusted, after checking the labels are internally
  // consistent: each side label must match its claim op, and the combined
  // label must be the weakest side. A server overclaiming hash-derived (or
  // any label on a create side other than hash-derived) is a divergence.
  const serverVerdict = {
    valid: attestation?.valid ?? null,
    signatureValid: attestation?.['signature-valid'] ?? null,
    channelHashValid: attestation?.['channel-hash-valid'] ?? null,
    signedSdHash: server['signed-sd-hash'] ?? null,
    claimOp: server['claim-op'] ?? null,
    channelClaimOp: server['channel-claim-op'] ?? null,
    claimStrength: server['claim-proof-strength'] ?? null,
    channelStrength: server['channel-claim-proof-strength'] ?? null,
    proofStrength: server['proof-strength'] ?? null,
  };
  const clientVerdict = {
    valid: clientFailed
      ? false
      : state.verdicts.signatureValid === true &&
        state.verdicts.channelHashValid === true,
    signatureValid: clientFailed ? false : state.verdicts.signatureValid,
    channelHashValid: clientFailed ? false : state.verdicts.channelHashValid,
    signedSdHash: state.verdicts.signedSdHash,
    claimOp: state.claimOutput?.claimOp ?? null,
    channelClaimOp: state.channel?.claimOp ?? null,
  };
  const strengthRow = (key, serverValue, claimOp) => {
    const expected = clientFailed ? [] : expectedSideStrengths(claimOp);
    return [
      key,
      serverValue,
      expected.length > 0 ? expected.join(' | ') : null,
      expected.includes(serverValue),
    ];
  };
  const claimStrengthRow = strengthRow(
    'claim-proof-strength',
    serverVerdict.claimStrength,
    clientVerdict.claimOp
  );
  const channelStrengthRow = strengthRow(
    'channel-claim-proof-strength',
    serverVerdict.channelStrength,
    clientVerdict.channelClaimOp
  );
  const expectedCombined = clientFailed
    ? null
    : weakestStrength(serverVerdict.claimStrength, serverVerdict.channelStrength);
  const rows = [
    ['valid', serverVerdict.valid, clientVerdict.valid],
    ['signature-valid', serverVerdict.signatureValid, clientVerdict.signatureValid],
    ['channel-hash-valid', serverVerdict.channelHashValid, clientVerdict.channelHashValid],
    ['signed-sd-hash', serverVerdict.signedSdHash, clientVerdict.signedSdHash],
    ['claim-op', serverVerdict.claimOp, clientVerdict.claimOp],
    ['channel-claim-op', serverVerdict.channelClaimOp, clientVerdict.channelClaimOp],
  ]
    .map(([key, s, c]) => [key, s, c, s === c])
    .concat([
      claimStrengthRow,
      channelStrengthRow,
      [
        'proof-strength',
        serverVerdict.proofStrength,
        expectedCombined,
        serverVerdict.proofStrength != null &&
          serverVerdict.proofStrength === expectedCombined,
      ],
    ]);
  const disagreements = rows.filter(([, , , agree]) => !agree);
  state.crossCheck = { rows, disagreements };
  const evidence = rows.map(
    ([key, s, c, agree]) =>
      `${key}: server=${fmt(s)} client=${fmt(c)} ${agree ? 'agree' : '** DISAGREE **'}`
  );
  if (disagreements.length > 0) {
    report(
      'cross-check',
      'mismatch',
      `divergence on: ${disagreements.map(([k]) => k).join(', ')}`,
      evidence
    );
  } else {
    const trustedUpgrade =
      serverVerdict.claimStrength === 'ancestor-derived' ||
      serverVerdict.channelStrength === 'ancestor-derived';
    report(
      'cross-check',
      'verified',
      trustedUpgrade
        ? 'server attestation matches client verdicts (ancestor-derived accepted as trusted: ancestry not re-derived client-side)'
        : 'server attestation matches client verdicts',
      evidence
    );
  }
}

// An on-chain create binds its claim id by hash derivation; an update only
// asserts it, unless the node walked a signature-authorized ancestry chain
// back to the create (ancestor-derived) — a proof the client accepts as
// trusted until it can replay the walk itself.
function expectedSideStrengths(claimOp) {
  if (claimOp === 'create') return ['hash-derived'];
  if (claimOp === 'update') return ['asserted', 'ancestor-derived'];
  return [];
}

const RANKED_STRENGTHS = ['asserted', 'ancestor-derived', 'hash-derived'];

function weakestStrength(a, b) {
  const rankA = RANKED_STRENGTHS.indexOf(a);
  const rankB = RANKED_STRENGTHS.indexOf(b);
  if (rankA < 0 || rankB < 0) return null;
  return RANKED_STRENGTHS[Math.min(rankA, rankB)];
}

export async function verifyAllBlobs(state, hb, tamper, onProgress) {
  const hooks = { blobBytes: tamper?.blobBytes ?? ((hash, bytes) => bytes) };
  const blobs = dataBlobs(state.descriptor);
  if (!Number.isInteger(state.exactSize)) {
    throw new Error('exact stream size unknown — run the spot check first');
  }
  // Decrypt directly into one preallocated buffer of the known exact size;
  // keeping per-blob chunks and concatenating would double peak memory.
  const out = new Uint8Array(state.exactSize);
  let offset = 0;
  for (const blob of blobs) {
    const bytes = hooks.blobBytes(blob.blobHash, await hb.blob(blob.blobHash), 'data');
    verifyBlobBytes(blob, bytes);
    const plain = await decryptBlob(state.descriptor.keyHex, blob.ivHex, bytes);
    if (offset + plain.length > out.length) {
      throw new Error('stream exceeds the computed exact size');
    }
    out.set(plain, offset);
    offset += plain.length;
    onProgress(blob.blobNum + 1, blobs.length);
  }
  if (offset !== out.length) {
    throw new Error('stream smaller than the computed exact size');
  }
  state.verifiedBytes = out;
  return out;
}

function describeHttpError(err) {
  if (err instanceof HbError) {
    const detail =
      typeof err.body === 'object' && err.body !== null
        ? err.body.error ?? err.body.details ?? ''
        : '';
    return `HTTP ${err.status}${detail ? ` (${detail})` : ''}`;
  }
  return err.message;
}

function shortHex(hex) {
  if (typeof hex !== 'string' || hex.length <= 40) return hex;
  return `${hex.slice(0, 32)}…${hex.slice(-8)}`;
}

function fmt(value) {
  if (value === null || value === undefined) return '∅';
  if (typeof value === 'string' && value.length > 40) return shortHex(value);
  return String(value);
}
