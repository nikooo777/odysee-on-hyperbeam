// Tamper harness: corrupts one piece of fetched evidence in memory before
// verification, proving that the right step goes red. A green checklist
// means nothing unless it can fail; this doubles as the demo of "the
// frontend catches a lying server" without building a malicious node.
import { bytesToHex, hexToBytes } from './lbry/bytes.js';

// `expectStep` names the step that must go red first when the scenario is
// active — asserted by scripts/live-check.js so a regression that moves the
// failure to the wrong stage is caught, not just "something failed".
export const SCENARIOS = [
  { id: 'none', label: 'no tampering', expectStep: null },
  {
    id: 'stream-tx-byte',
    label: 'flip a byte in the stream raw tx (step 3 must fail)',
    expectStep: 'stream-tx',
  },
  {
    id: 'channel-pubkey',
    label: 'substitute the channel public key (step 6 must fail)',
    expectStep: 'signature',
  },
  {
    id: 'resolve-sd-hash',
    label: 'lie about the resolve sd_hash (step 7 must fail)',
    expectStep: 'sd-hash',
  },
  {
    id: 'corrupt-descriptor',
    label: 'corrupt the descriptor blob (step 8 must fail)',
    expectStep: 'descriptor',
  },
  {
    id: 'corrupt-blob',
    label: 'corrupt a data blob (step 9 must fail)',
    expectStep: 'blobs',
  },
  {
    id: 'forge-server-verdict',
    label: 'forge the server attestation (step 10 must diverge)',
    expectStep: 'cross-check',
  },
  {
    id: 'forge-proof-strength',
    label: 'forge the server proof-strength label (step 10 must diverge)',
    expectStep: 'cross-check',
  },
  {
    id: 'forge-channel-strength',
    label:
      'overclaim the channel binding as hash-derived (step 10 must diverge; needs an updated channel)',
    expectStep: 'cross-check',
  },
];

export function tamperHooks(scenario) {
  switch (scenario) {
    case 'stream-tx-byte':
      return {
        txHex: (hex, role) => {
          if (role !== 'stream') return hex;
          const bytes = hexToBytes(hex);
          bytes[Math.floor(bytes.length / 2)] ^= 0xff;
          return bytesToHex(bytes);
        },
      };
    case 'channel-pubkey':
      return {
        channelPublicKey: (key) => {
          const forged = Uint8Array.from(key);
          forged[10] ^= 0xff;
          return forged;
        },
      };
    case 'resolve-sd-hash':
      return {
        resolveSdHash: (sdHash) => {
          if (!sdHash) return sdHash;
          const flipped = sdHash[0] === '0' ? '1' : '0';
          return flipped + sdHash.slice(1);
        },
      };
    case 'corrupt-descriptor':
      return {
        blobBytes: (hash, bytes, role) => {
          if (role !== 'descriptor') return bytes;
          const corrupted = Uint8Array.from(bytes);
          corrupted[0] ^= 0xff;
          return corrupted;
        },
      };
    case 'corrupt-blob':
      return {
        blobBytes: (hash, bytes, role) => {
          if (role !== 'data') return bytes;
          const corrupted = Uint8Array.from(bytes);
          corrupted[0] ^= 0xff;
          return corrupted;
        },
      };
    case 'forge-server-verdict':
      return {
        serverVerdict: (msg) => ({
          ...msg,
          'signed-sd-hash':
            '0000000000000000000000000000000000000000000000000000000000000000' +
            '00000000000000000000000000000000',
        }),
      };
    // Catchable in every honest state: hash-derived (both creates) forged
    // to asserted breaks the combined-vs-sides consistency; asserted or
    // ancestor-derived forged to hash-derived breaks it the other way. The
    // residual forgery — upgrading an update's asserted side label to
    // ancestor-derived — is NOT detectable client-side until the client
    // walks ancestry itself; see the README.
    case 'forge-proof-strength':
      return {
        serverVerdict: (msg) => ({
          ...msg,
          'proof-strength':
            msg['proof-strength'] === 'hash-derived' ? 'asserted' : 'hash-derived',
        }),
      };
    // Overclaim the channel side: hash-derived is only consistent with a
    // create channel claim, so on an updated channel the side row diverges.
    case 'forge-channel-strength':
      return {
        serverVerdict: (msg) => ({
          ...msg,
          'channel-claim-proof-strength': 'hash-derived',
          'proof-strength': msg['claim-proof-strength'] ?? msg['proof-strength'],
        }),
      };
    default:
      return {};
  }
}
