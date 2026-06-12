// The tracked live battery: every canonical clean target plus every tamper
// scenario, run through live-check against a real node. Exits non-zero if
// any entry fails, so the full matrix is one command instead of folklore.
//
//   node scripts/live-battery.js [nodeUrl]
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SCENARIOS } from '../src/tamper.js';

const nodeUrl = process.argv[2] ?? 'http://localhost:8734';
const liveCheck = fileURLToPath(new URL('./live-check.js', import.meta.url));

const CLAIM_ID = '9cc7f0e3de8db3b2ffd6dc0b4f1a0f0ca48a6b49';
const TXID =
  '51d3cd6a27420addb648347410233931b862ab52660c1dba58806b5b0f38a460';

const entries = [
  { target: CLAIM_ID, scenario: 'none' },
  { target: TXID, scenario: 'none' },
  { target: `${TXID}:0`, scenario: 'none' },
  ...SCENARIOS.filter((scenario) => scenario.id !== 'none').map(
    (scenario) => ({ target: CLAIM_ID, scenario: scenario.id })
  ),
];

let failed = 0;
for (const { target, scenario } of entries) {
  process.stdout.write(`${scenario.padEnd(24)} ${target} ... `);
  try {
    execFileSync('node', [liveCheck, nodeUrl, target, scenario], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    console.log('ok');
  } catch (err) {
    failed += 1;
    console.log('FAILED');
    process.stdout.write(err.stdout?.toString() ?? '');
    process.stderr.write(err.stderr?.toString() ?? '');
  }
}
console.log('---');
console.log(`${entries.length - failed}/${entries.length} battery entries passed`);
process.exit(failed === 0 ? 0 : 1);
