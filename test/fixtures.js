// Frozen on-chain vectors, identical to the fixtures in HyperBEAM's Erlang
// test suite (hb_lbry_tx, hb_lbry_attestation, hb_lbry_claim_proto), so the
// two implementations stay verifiably in sync.
export const ONCHAIN_TX_HEX =
  '01000000012f6e843a8e0aa69fee0a7cc53a4343760dc548a16d13bfeb31f94f571ddae854010000006a47304402202ee7491d13424d2d06ae2407d48d3280223140dfe19e6d14ceedd2609d19e92b0220069a68ed6cd682ee442d8e39ce7f72f5e772b12614a0ab7796c42d817de25ce301210378ff344cc1f8a5451e7b8f348670b20c44ae44704ac05c59fb936ac1a4f26769ffffffff02a086010000000000fde801b531416666616972652d42726967697474652d5f2dc3a7612d64c3a97261696c6c652d656e2d706c65696e2d6469726563742d4d970101aa287054a918ea5a3c58ed4320d92fb8c7545d58e2bd32941d8256b818f5a72bc5ab16bcecff961261e5ea0036a0d7e26aa24738010ef602e0683690d7601cfe3df9268e46dfbb925a70cd16216e046ed17f3da60ac5010aab010a30cb215d05f21823b1208313edeaf8d7af4b2d2d00acc58fac1a1cf40427351b3b79a636b70f5844f6c691330955a53b18123541666661697265204272696769747465205f20c3a7612064c3a97261696c6c6520656e20706c65696e20646972656374202e6d7034188bcb861e2209766964656f2f6d703432303da16b833f169c21caeb62ca66111227413f30f63c9d2f52f2a787643e086c334ee6949e05875cfe94a816aba02e492e1a044e6f6e6528faa2a0d1065a0908800510e802188a08423141666661697265204272696769747465205f20c3a7612064c3a97261696c6c6520656e20706c65696e206469726563742052412a3f68747470733a2f2f7468756d62732e6f647963646e2e636f6d2f62353765383966656131653333636136623761616536386638363735623235622e77656270620208016d7576a914b462dfca8f203323f9c4375e4160e257f61aca7888acd6af8314000000001976a914b462dfca8f203323f9c4375e4160e257f61aca7888ac00000000';

export const ONCHAIN_TXID =
  '51d3cd6a27420addb648347410233931b862ab52660c1dba58806b5b0f38a460';

export const ONCHAIN_PREV_TXID =
  '54e8da1d574ff931ebbf136da148c50d7643433ac57c0aee9fa60a8e3a846e2f';

export const ONCHAIN_CLAIM_ID = '9cc7f0e3de8db3b2ffd6dc0b4f1a0f0ca48a6b49';

export const ONCHAIN_SIGNING_CHANNEL_ID =
  '585d54c7b82fd92043ed583c5aea18a9547028aa';

export const ONCHAIN_CHANNEL_PUBKEY_HEX =
  '03fa4e5fe9f02f2f1a8c34ec150b91f762d8b07b7be942f26aa80c40902d5dbd11';

export const ONCHAIN_SD_HASH =
  '3da16b833f169c21caeb62ca66111227413f30f63c9d2f52f2a787643e086c334ee6949e05875cfe94a816aba02e492e';

// Minimal protobuf builders for synthetic negative-test messages, mirroring
// the helpers in hb_odysee_device_test.erl.
export function protoVarint(value) {
  const out = [];
  let v = value;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  out.push(v);
  return Uint8Array.from(out);
}

export function protoField(number, value) {
  const key = protoVarint((number << 3) | 2);
  const length = protoVarint(value.length);
  const out = new Uint8Array(key.length + length.length + value.length);
  out.set(key, 0);
  out.set(length, key.length);
  out.set(value, key.length + length.length);
  return out;
}
