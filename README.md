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

1. Parse input (claim id / name / URL — name lookups are SDK-trusted).
2. Resolve via the node's `odysee@1.0` device (server-claimed metadata only).
3. Fetch the raw stream transaction; recompute `txid = reverse(SHA256d(raw))`.
4. Parse the claim script; derive `claim_id = hash160(tx_hash ‖ nout)` and
   require equality with the input; parse the claim envelope.
5. Fetch the **channel's** raw transaction; bind its derived claim id to the
   envelope's signing-channel hash; extract the channel public key from the
   raw channel protobuf (never from SDK metadata).
6. Verify the secp256k1 claim signature over the v2 digest
   `SHA256(outpoint ‖ channel_hash ‖ message)` (`prehash: false,
   lowS: false` — high-S signatures are accepted on-chain).
7. Extract `sd_hash` from the on-chain claim protobuf (signed or unsigned);
   never use the SDK-reported value as the content root.
8. Fetch the stream descriptor blob; require `SHA384(bytes) == sd_hash`;
   validate its structure.
9. Spot-check the first and last data blobs (SHA-384 over encrypted bytes,
   AES-128-CBC decryption, exact stream size from the final blob), then
   cross-check the node's Content-Range total — read via a one-byte `media`
   probe — against the client-computed exact size. A differing total goes
   red; an unavailable probe only downgrades the step to `trusted`.
10. Cross-check the node's own `verified-stream` attestation against the
    client verdicts; any divergence raises a red banner.
11. Playback: streamed via the node's Range-serving `media` endpoint
    (transport-trusted), or — after a full blob sweep — **verified playback**
    from a Blob URL where every played byte passed client-side verification.

Unsigned (anonymous) claims skip steps 5–6: the content root still binds to
the claim output, but no channel attests to it, and the server's
`verified-stream` endpoint is expected to fail closed — reported as
consistent, not as a mismatch.

Each step carries a status chip: `client-verified` (re-derived locally),
`server-claimed` (displayed, not trusted), `trusted` (accepted without proof,
explicitly marked), `not applicable`, `FAILED`, or `SERVER MISMATCH` (raises
the red banner).

## Tamper harness

A built-in tamper harness corrupts evidence in memory — flip a stream-tx
byte, swap the channel public key, lie about the resolve sd_hash, corrupt the
descriptor blob, corrupt a data blob, forge the server attestation — to prove
each step actually fails when it should. Pick a scenario from the dropdown in
the UI, or run the headless end-to-end check against a live node:

```bash
node scripts/live-check.js [nodeUrl] [target] [scenario]
```

Defaults are `http://localhost:8734`, the test-fixture claim, and scenario
`none`.
A clean run exits 0 only if every step is green; a tamper run exits 0 only if
the first red step is exactly the one the scenario prescribes — a regression
that moves the failure to the wrong stage fails the check. Requires Node 18+
(fetch and WebCrypto).

## Running

Requires a HyperBEAM node with the `odysee@1.0` device (the `blob` key,
`raw-hex` transaction field, and no-range media default).

```bash
npm install
npm run dev      # frontend on http://localhost:5173
npm test         # vitest unit suite (frozen on-chain fixtures)
npm run build    # production bundle in dist/
```

Point the node field at your HyperBEAM instance (default
`http://localhost:8734`) and enter a claim id.

## Limitations (fail closed)

- Segwit-serialized transactions are not parsed; the transaction step rejects
  them.
- v0/v1 legacy claim encodings are rejected; only v2 protobuf claims verify.
- Update claims assert their claim id in-script; the create-tx chain is not
  walked, so the claim-output step reports `trusted` instead of
  `client-verified`.

## Layout

```
src/main.js              UI wiring (verify, full sweep, playback controls)
src/hb.js                HyperBEAM client (JSON, ao-types, link dereference)
src/pipeline.js          the 11-step verification pipeline + full blob sweep
src/tamper.js            tamper scenarios and their prescribed failure steps
src/lbry/bytes.js        hex/byte helpers, SHA-256d, hash160, SHA-384
src/lbry/tx.js           raw LBRY tx + claim script parser
src/lbry/proto.js        minimal protobuf walker (sd_hash, channel pubkey)
src/lbry/attestation.js  v2 claim-signature digest + secp256k1 verify
src/lbry/descriptor.js   descriptor parse/validate, SHA-384, AES-CBC
src/ui/                  step ladder + video.js wiring
scripts/live-check.js    headless E2E + tamper assertions against a live node
test/                    vitest suite with frozen on-chain vectors, mirroring
                         HyperBEAM's Erlang test fixtures
```
