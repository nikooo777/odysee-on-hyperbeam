# odysee-on-hb

Proof-of-concept verification frontend for the Odysee/LBRY → HyperBEAM read
bridge. This is an operator/developer instrument, not a consumer UI: you drop
in a claim id, claim name, URL, or a raw transaction id, and it walks step by
step through resolution and verification — re-deriving every cryptographic
claim **in the browser**, so a lying HyperBEAM node is caught, not believed.
Every HTTP exchange the pipeline performs is on display inside the UI with
its commitment structure parsed and classified — no network tab required.
The final step plays the stream in a video.js player.

## Trust model

The HyperBEAM node is treated as an untrusted courier. Every byte feeding a
verdict is either content-addressed (re-hashed locally) or chained to the
typed claim id through the LBRY transaction and signature chain:

1. Parse input (claim id / name / URL / txid — name lookups are
   SDK-trusted).
2. Resolve via the node's `odysee@1.0` device (server-claimed metadata only).
3. Fetch the raw stream transaction; recompute `txid = reverse(SHA256d(raw))`.
4. Parse the claim script; derive `claim_id = hash160(tx_hash ‖ nout)` and
   require equality with the input; parse the claim envelope.
5. Fetch the **channel's** raw transaction; bind its derived claim id to the
   envelope's signing-channel hash; extract the channel public key from the
   raw channel protobuf (never from SDK metadata). Channel claims that are
   on-chain updates only assert their claim id in-script, so the binding is
   labeled assertion-level (`trusted`) rather than hash-derived.
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
    client verdicts — including the node's `claim-op`, `channel-claim-op`,
    and per-side binding-strength labels. Each side must be consistent with
    its claim op: a create binds `hash-derived`; an update binds `asserted`,
    unless the node walked a signature-authorized ancestry chain back to the
    create and reports `ancestor-derived` — a proof the client accepts as
    **trusted** (it does not re-derive the walk yet). The combined
    `proof-strength` must equal the weakest side. Any inconsistency raises a
    red banner.
11. Playback: streamed via the node's Range-serving `media` endpoint
    (transport-trusted), or — after a full blob sweep — **verified playback**
    from a Blob URL where every played byte passed client-side verification.

Unsigned (anonymous) claims skip steps 5–6: the content root still binds to
the claim output, but no channel attests to it, and the server's
`verified-stream` endpoint is expected to fail closed — reported as
consistent, not as a mismatch.

### Render-by-ID (txid / txid:nout) entry

Typing a 64-hex transaction id — or, preferably, an explicit
`txid:nout` outpoint — skips the locator entirely: no name resolution, no
claim tree, no node-chosen mapping. The typed id is the verification root,
and it is *content-addressed*: the transaction id is the double-SHA256 of
the raw bytes, so root equality in step 3 is even stronger than the
claim-id root. Step 2 reports `not applicable`; with a bare txid the claim
output is auto-selected only when the transaction carries exactly one
*stream* claim output (the step says "selected output N"; several stream
outputs ask for the explicit form, and an explicit outpoint at a channel
claim fails early with a clear message). The derived claim id is
client-verified information for creates and asserted for updates — there
is no typed claim id to compare against. Step 10 becomes a *diagnostic
facade comparison*: the proof chain above does not depend on it, and when
the node resolves the claim to a different (likely newer) outpoint than
the one requested, the comparison reports `not applicable` rather than a
mismatch — rendering a specific outpoint says nothing about whether it is
the claim's latest state, and the UI says so rather than implying it.

### Protocol transparency

- **Exchange ledger**: the client records every request (method, path,
  status, duration, picked response headers, and the body commitments map
  of JSON replies). Each step's expandable body gains a "requests" list —
  one line per exchange, expandable to the parsed commitment detail.
- **Commitment classification**: the message's `commitments` map is the
  canonical object; `Signature`/`Signature-Input` headers are its HTTPSig
  wire encoding and JSON replies carry the same map in the body. The
  viewer renders whichever encoding arrived and one shared classifier
  names each commitment: `lbry-*` algs are **source-format commitments**
  (the litmus line, highlighted, with `native-id` shown prominently),
  `rsa-pss-sha512`/`publickey:` keyids are the **node transport
  signature**, and `hmac-sha256` + `keyid="constant:ao"` is the **derived
  message-id commitment**. Body commitments carry no `alg`; the viewer
  derives it with the codec's own rule (`httpsig@1.0` → bare `type`,
  anything else → `device/type`). Facade views (`verified-stream` and its
  sublinks) carry only the transport signature — in the body map on the
  JSON path — and are annotated as *composition output*, deliberately
  contrasting with the committed source reads.
- **Identity panel**: every evidence object (transactions, claim outputs,
  claim ids, descriptor and data blobs) shows its identity triplet: the
  native LBRY id, the HyperBEAM commitment id with the conversion rule
  (32-byte ids encode directly as base64url; everything else is SHA-256
  hashed first — matching `hb_lbry_commitment:commitment_id/1` exactly,
  vector-tested against Erlang outputs), and the message id once observed.
- **Committed-form fetch**: per evidence object, an on-demand button reads
  the object back through the node's store path
  (`/~cache@1.0/read?read=<native key>`) using a dedicated raw fetch (no
  JSON accept — JSON replies carry no signature headers) and renders the
  parsed `Signature-Input` on screen, where the `lbry-*@1.0` commitment
  device appears: blobs by 96-hex hash (`lbry-blob@1.0/sha-384`),
  transactions by 64-hex txid (`lbry-transaction@1.0/sha-256d`), claim
  outputs by `txid:nout` (`lbry-claim@1.0/<type>`, where the type names
  the binding strength). Claim-output reads on ancestry-enabled nodes can
  take tens of seconds — they are on-demand for exactly that reason.

Each step carries a status chip: `client-verified` (re-derived locally),
`server-claimed` (displayed, not trusted), `trusted` (accepted without proof,
explicitly marked), `not applicable`, `FAILED`, or `SERVER MISMATCH` (raises
the red banner).

Every step presents three layers of detail, so both non-technical and
technical readers get the depth they want: the one-line outcome is always
visible; clicking a step opens its plain-language story (the question the
step answers, how the browser answers it, and what a lying node would look
like); and a `proof` panel inside holds the raw values the verdict rests on
(txids, digests, keys, equality checks). Failed or mismatched steps unfold
themselves with their proof open.

## Tamper harness

A built-in tamper harness corrupts evidence in memory — flip a stream-tx
byte, swap the channel public key, lie about the resolve sd_hash, corrupt the
descriptor blob, corrupt a data blob, forge the server attestation, forge the
server's proof-strength label, overclaim the channel binding strength — to
prove each step actually fails when it should. Pick a scenario from the
dropdown in the UI, or run the headless end-to-end check against a live
node:

```bash
node scripts/live-check.js [nodeUrl] [target] [scenario]
node scripts/live-battery.js [nodeUrl]   # the full battery in one command
```

Defaults are `http://localhost:8734`, the test-fixture claim, and scenario
`none`.
A clean run exits 0 only if every step is green; a tamper run exits 0 only if
the first red step is exactly the one the scenario prescribes — a regression
that moves the failure to the wrong stage fails the check. The battery runs
every canonical clean target (claim id, bare txid, explicit `txid:nout`)
plus every tamper scenario and exits non-zero on any failure. Requires
Node 18+ (fetch and WebCrypto).

## Running

Requires a HyperBEAM node with the `odysee@1.0` device (the `blob` key,
`raw-hex` transaction field, no-range media default, and the
`claim-op`/`channel-claim-op`/`claim-proof-strength`/
`channel-claim-proof-strength`/`proof-strength` fields on `verified-stream`
from the device/codec/store alignment and create-ancestry work). Nodes with
the `walk-ancestry` store option enabled report `ancestor-derived` for
update claims whose create ancestry verified.

The committed-form fetch additionally needs the LBRY stores mounted in the
node's store list so store-path reads resolve. A reproducible demo-node
config (JSON, started with `HB_CONFIG=<file>.json rebar3 shell`):

```json
{
  "port": 8734,
  "lbry-tx-store": {"walk-ancestry": true},
  "store": [
    {
      "ao-types": "store-module=atom",
      "store-module": "hb_store_lmdb",
      "name": "cache-mainnet/lmdb"
    },
    {
      "ao-types": "store-module=atom",
      "store-module": "hb_store_fs",
      "name": "cache-mainnet"
    },
    {
      "ao-types": "store-module=atom",
      "store-module": "hb_store_lbry_blob"
    },
    {
      "ao-types": "store-module=atom",
      "store-module": "hb_store_lbry_transaction"
    },
    {
      "ao-types": "store-module=atom,walk-ancestry=atom",
      "store-module": "hb_store_lbry_claim_output",
      "walk-ancestry": true
    }
  ]
}
```

The claim-output store mounts the generic claim kind (the default), which
serves every claim output including channels. `walk-ancestry` makes
committed claim reads of update outputs show `ancestor-hash160-outpoint`
commitments at the cost of slow first reads; the on-demand fetch design
absorbs the latency. Store reads through this path re-fetch from the
backend on every request (no automatic write-back into the local cache) —
acceptable for the demo. Root-path reads of native hex keys
(`GET /<txid>`) are rejected by the router; `~cache@1.0/read` is the
supported form.

```bash
npm install
npm run dev      # frontend on http://localhost:5173
npm test         # vitest unit suite (frozen on-chain fixtures)
npm run build    # production bundle in dist/
```

Point the node field at your HyperBEAM instance (default
`http://localhost:8734`) and enter a claim id or a `txid:nout` outpoint.

## Limitations (fail closed)

- Segwit-serialized transactions are not parsed; the transaction step rejects
  them.
- v0/v1 legacy claim encodings are rejected; only v2 protobuf claims verify.
- Update claims assert their claim id in-script; the client does not walk
  the create-tx chain itself, so the claim-output step reports `trusted`
  instead of `client-verified`. The same applies to updated channel claims.
  The node can walk the chain server-side (`walk-ancestry`) and report
  `ancestor-derived` — create lineage plus per-hop spend-signature
  authorization, **not** block inclusion or claim currentness — which the
  client accepts as trusted after checking the label is consistent with the
  claim ops. Until the client replays the walk itself, a forged `asserted`
  → `ancestor-derived` upgrade on an update claim is **not detectable
  client-side**; overclaims of `hash-derived` are caught. Most long-lived
  channels are updates, so `asserted` or `ancestor-derived` is the common
  honest outcome.

## Layout

```
src/main.js              UI wiring (verify, full sweep, playback controls)
src/hb.js                HyperBEAM client (JSON, ao-types, link dereference,
                         exchange ledger, raw committed-form fetch)
src/pipeline.js          the 11-step verification pipeline + full blob sweep
src/commitments.js       Signature-Input parser, body-commitment
                         normalization, shared commitment classifier
src/identity.js          native id → HyperBEAM commitment id conversion
src/tamper.js            tamper scenarios and their prescribed failure steps
src/lbry/bytes.js        hex/byte helpers, SHA-256d, hash160, SHA-384
src/lbry/tx.js           raw LBRY tx + claim script parser
src/lbry/proto.js        minimal protobuf walker (sd_hash, channel pubkey,
                         media type)
src/lbry/attestation.js  v2 claim-signature digest + secp256k1 verify
src/lbry/descriptor.js   descriptor parse/validate, SHA-384, AES-CBC
src/ui/                  step ladder, identity panel + video.js wiring
scripts/live-check.js    headless E2E + tamper assertions against a live node
scripts/live-battery.js  the full clean + tamper matrix in one command
test/                    vitest suite with frozen on-chain vectors, mirroring
                         HyperBEAM's Erlang test fixtures, plus real captured
                         Signature-Input vectors and Erlang-checked
                         commitment-id conversion vectors
```
