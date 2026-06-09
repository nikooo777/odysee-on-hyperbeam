# odysee-on-hb

Proof-of-concept verification frontend for the Odysee/LBRY → HyperBEAM read
bridge. This is an operator/developer instrument, not a consumer UI: you drop
in a claim id, claim name, or URL, and it walks step by step through
resolution and verification — re-deriving every cryptographic claim **in the
browser**, so a lying HyperBEAM node is caught, not believed. The final step
plays the stream in a video.js player.

## Trust model

The HyperBEAM node is treated as an untrusted courier. Every byte feeding a
verdict is either content-addressed (re-hashed locally) or chained to the
typed claim id through the LBRY transaction and signature chain:

1. Parse input (claim id / name / URL — name lookups are SDK-trusted, tier 3).
2. Resolve via the node's `odysee@1.0` device (server-claimed metadata only).
3. Fetch the raw stream transaction; recompute `txid = reverse(SHA256d(raw))`.
4. Parse the claim script; derive `claim_id = hash160(tx_hash ‖ nout)` and
   require equality with the input; parse the claim envelope.
5. Fetch the **channel's** raw transaction; bind its derived claim id to the
   envelope's signing-channel hash; extract the channel public key from the
   raw channel protobuf (never from SDK metadata).
6. Verify the secp256k1 claim signature over the v2 digest
   (`prehash: false, lowS: false` — high-S signatures are accepted on-chain).
7. Extract `sd_hash` from the on-chain claim protobuf (signed or unsigned);
   never use the SDK-reported value as the content root.
8. Fetch the stream descriptor blob; require `SHA384(bytes) == sd_hash`;
   validate its structure.
9. Spot-check the first and last data blobs (SHA-384 over encrypted bytes,
   AES-128-CBC decryption, exact stream size from the final blob).
10. Cross-check the node's own `verified-stream` attestation against the
    client verdicts; any divergence raises a red banner.
11. Playback: streamed via the node's Range-serving `media` endpoint
    (transport-trusted), or — after a full blob sweep — **verified playback**
    from a Blob URL where every played byte passed client-side verification.

A built-in tamper harness corrupts evidence in memory (flip a tx byte, swap
the channel key, lie about the sd_hash, corrupt the descriptor, corrupt a
data blob, forge the server verdict) to prove each step actually fails when
it should — `scripts/live-check.js` asserts each scenario goes red at
exactly its prescribed step.

## Running

Requires a HyperBEAM node with the `odysee@1.0` device (the `blob` key,
`raw-hex` transaction field, and no-range media default).

```bash
npm install
npm run dev      # frontend on http://localhost:5173
npm test         # vitest unit suite (Task-0 on-chain fixtures)
```

Point the node field at your HyperBEAM instance (default
`http://localhost:8734`) and enter a claim id.

## Layout

```
src/hb.js                HyperBEAM client (JSON, ao-types, link dereference)
src/pipeline.js          the 11-step verification pipeline
src/tamper.js            tamper scenarios
src/lbry/tx.js           raw LBRY tx + claim script parser
src/lbry/proto.js        minimal protobuf walker (sd_hash, channel pubkey)
src/lbry/attestation.js  v2 claim-signature digest + secp256k1 verify
src/lbry/descriptor.js   descriptor parse/validate, SHA-384, AES-CBC
src/ui/                  step ladder + video.js wiring
test/                    vitest suite with frozen Task-0 vectors
```

This project is deliberately temporary: nothing in HyperBEAM depends on it.
