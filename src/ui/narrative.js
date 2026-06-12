// Plain-language narratives for each verification step. The step ladder
// shows three layers of detail: the always-visible outcome line, this
// story (what question the step answers, how the browser answers it, and
// what a lying node would look like), and the raw proof values beneath it.
// Keep these honest: where a step trusts something, the text says so.
export const STEP_NARRATIVES = {
  input: {
    question: 'What exactly are we trying to verify?',
    how:
      'A claim id is a 40-character fingerprint that is mathematically ' +
      'tied to the original publish transaction. If you typed one, every ' +
      'step below must trace back to it. Names and URLs are convenience ' +
      'lookups: the node decides which claim they map to, so that mapping ' +
      'is taken on trust.',
    catches:
      'nothing yet — this step fixes the root that everything else is ' +
      'checked against.',
  },
  resolve: {
    question: 'What does the node say this content is?',
    how:
      'We ask the node to describe the claim: title, file type, size, ' +
      'content fingerprint, channel. At this point it is all just the ' +
      "node's word — shown for context, believed for nothing. Every value " +
      'that matters is re-checked against on-chain bytes in the steps ' +
      'below.',
    catches:
      'nothing here by itself — lies in this answer are caught by the ' +
      'later steps that re-derive each value.',
  },
  'stream-tx': {
    question: 'Are these the real on-chain transaction bytes?',
    how:
      'The node hands over the raw publish transaction. Your browser ' +
      'hashes those bytes twice with SHA-256: the result IS the ' +
      'transaction id. Changing a single byte anywhere changes the id ' +
      'completely, so matching the requested id proves the bytes are ' +
      'genuine.',
    catches:
      'a node serving modified or substituted transaction bytes — the ' +
      'recomputed id would not match.',
  },
  'claim-output': {
    question: 'Is this the exact claim you asked about?',
    how:
      'Inside the verified transaction we find the publish output. For an ' +
      'original publish, the claim id re-derives as hash160(transaction ' +
      'hash ‖ output position) — pure math links your typed id to these ' +
      'bytes, leaving the node no room to swap in a different video. ' +
      'Update claims assert their id instead; the node can prove their ' +
      'descent from the original publish, which the cross-check step ' +
      'examines.',
    catches:
      "a node answering your claim id with a different video's " +
      'internally-consistent records.',
  },
  channel: {
    question: 'Whose channel supposedly published this?',
    how:
      'The signed claim itself names its channel. We fetch that ' +
      "channel's own on-chain record — verified the same way as the " +
      "stream transaction — and read the channel's public key out of the " +
      "raw bytes, never out of the node's convenient summary.",
    catches:
      'a node substituting a different channel or a different public key ' +
      'to make a forged signature look valid.',
  },
  signature: {
    question: "Did that channel really sign this video's metadata?",
    how:
      "Your browser rebuilds the exact digest the creator's wallet " +
      'signed — covering the outpoint, the channel hash, and the claim ' +
      'content — and verifies the secp256k1 signature against the channel ' +
      'key from the previous step. If anything in the metadata changed ' +
      'after signing, this fails.',
    catches:
      "forged attribution, or any tampering with the claim's content " +
      'after it was signed.',
  },
  'sd-hash': {
    question: 'Which content does that signature actually cover?',
    how:
      'The signed claim embeds the content root (sd_hash): the ' +
      "fingerprint of the stream's table of contents. We extract it from " +
      'the signed bytes themselves. The node also reports one — if they ' +
      'differ, the node is pointing the player at content the creator ' +
      'never signed.',
    catches:
      'a bait-and-switch: signed metadata for one video, content of ' +
      'another.',
  },
  descriptor: {
    question: 'Does the table of contents match its fingerprint?',
    how:
      'We download the stream descriptor — the list of every encrypted ' +
      "chunk, with each chunk's own fingerprint and decryption " +
      'parameters — and hash it with SHA-384. It must equal the signed ' +
      'content root exactly.',
    catches: 'a tampered descriptor: extra, missing, or substituted chunks.',
  },
  blobs: {
    question: 'Are the actual video bytes what the descriptor promises?',
    how:
      'We download the first and last encrypted chunks, check each ' +
      'against its fingerprint from the descriptor, decrypt them with the ' +
      "descriptor's key, and compute the file's exact size from the final " +
      "chunk. The node's advertised streaming size must agree.",
    catches:
      'corrupted or truncated content, and a node that streams different ' +
      'bytes than it indexed.',
  },
  'cross-check': {
    question:
      "Does the node's own verdict agree with everything this browser found?",
    how:
      'The node publishes its own verification result: signature ' +
      'validity, the signed content root, and how strongly each claim id ' +
      'is bound — hash-derived for original publishes, ancestor-derived ' +
      "when the node walked an update's history back to the original " +
      'with a signature check at every hop, asserted otherwise. Every ' +
      "field is compared against this browser's independent verdicts, and " +
      'the strength labels must be consistent with the claim types. An ' +
      'ancestor-derived label is accepted as trusted: this browser checks ' +
      'its consistency but does not replay the walk itself yet.',
    catches:
      'a node overstating its verification — for example claiming a ' +
      'hash-derived binding for an updated claim.',
  },
  playback: {
    question: 'What am I about to watch, and how much of it is verified?',
    how:
      'Streamed playback fetches chunks through the node on demand — ' +
      "convenient, spot-checked, but transport-trusted. 'Verified " +
      "playback' first downloads every chunk, re-checks each fingerprint, " +
      'decrypts in your browser, and plays only from those verified ' +
      'bytes.',
    catches:
      'with verified playback: any served chunk that differs from what ' +
      "the creator's signed descriptor promises.",
  },
};

// Render-by-ID (txid / txid:nout) entry changes what the early steps and
// the cross-check mean; these variants replace the defaults in that mode.
export const TXID_NARRATIVES = {
  input: {
    question: 'What exactly are we trying to verify?',
    how:
      'A transaction id is the double-SHA256 fingerprint of the raw ' +
      'publish transaction itself. Typing one skips every lookup: no name ' +
      'resolution, no claim tree, no node-chosen mapping. Everything below ' +
      'is bound to your typed id by hashing alone — an even stronger root ' +
      'than a claim id.',
    catches:
      'nothing yet — this step fixes the root that everything else is ' +
      'checked against.',
  },
  resolve: {
    question: 'What does the node say this content is?',
    how:
      'Nothing — and that is the point. In render-by-ID mode the node is ' +
      'never asked to describe or locate the content; the transaction ' +
      'bytes themselves carry everything the later steps need. Skipping ' +
      'the locator increases trust: there is no server-chosen mapping left ' +
      'to lie about.',
    catches:
      'not applicable — there is no resolve answer to check in this mode.',
  },
  'cross-check': {
    question:
      "Does the node's own verdict agree with everything this browser found?",
    how:
      'In render-by-ID mode this is a diagnostic comparison, not part of ' +
      "the proof: nothing above depended on the node's claim resolution. " +
      'The browser asks the node about the claim id it derived from the ' +
      'raw bytes and compares verdicts — but only when the node attests ' +
      'the same outpoint you asked for. If the node has a newer state of ' +
      'the claim, the comparison is skipped as not applicable rather than ' +
      'reported as a mismatch.',
    catches:
      'a node overstating its verification for this same outpoint — and ' +
      'nothing else: a different-outpoint answer is not evidence of lying.',
  },
};

export function narrativeFor(id, mode) {
  if (mode === 'txid' && TXID_NARRATIVES[id]) return TXID_NARRATIVES[id];
  return STEP_NARRATIVES[id];
}

export const CHIP_EXPLANATIONS = {
  pending: 'Waiting for earlier steps.',
  running: 'Working…',
  verified:
    'Re-computed in this browser from raw on-chain or content-addressed ' +
    'bytes — requires no trust in the node.',
  server:
    "The node's own statement, displayed for context. Not believed until " +
    'a later step re-derives it.',
  trusted:
    'Accepted without full in-browser proof — explicitly marked, never ' +
    'silent.',
  na: 'Not applicable to this claim.',
  failed: 'The proof did not hold. Nothing downstream is believed.',
  mismatch:
    "The node's claims disagree with what this browser derived " +
    'independently.',
};
