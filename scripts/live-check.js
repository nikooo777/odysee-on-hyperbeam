// Headless live end-to-end check: runs the verification pipeline against a
// real HyperBEAM node and real LBRY infrastructure, for one or more targets
// and optional tamper scenarios. Node 18+ provides fetch and WebCrypto.
//
//   node scripts/live-check.js [nodeUrl] [target] [scenario]
import { HbClient } from '../src/hb.js';
import { runPipeline } from '../src/pipeline.js';
import { tamperHooks, SCENARIOS } from '../src/tamper.js';

const nodeUrl = process.argv[2] ?? 'http://localhost:8734';
const target = process.argv[3] ?? '9cc7f0e3de8db3b2ffd6dc0b4f1a0f0ca48a6b49';
const scenario = process.argv[4] ?? 'none';

const scenarioDef = SCENARIOS.find((s) => s.id === scenario);
if (!scenarioDef) {
  console.error(`unknown scenario: ${scenario}`);
  process.exit(2);
}

const results = [];
function report(step, status, detail = '') {
  if (status === 'running') return;
  results.push({ step, status });
  console.log(`${step.padEnd(14)} ${status.padEnd(10)} ${detail}`);
}

const hb = new HbClient(nodeUrl);
const state = await runPipeline({
  input: target,
  hb,
  report,
  tamper: tamperHooks(scenario),
});

console.log('---');
console.log(`target: ${target}, scenario: ${scenario}`);
if (state.exactSize) console.log(`exact size: ${state.exactSize}`);
const bad = results.filter((r) => ['failed', 'mismatch'].includes(r.status));
if (scenario === 'none') {
  process.exit(bad.length === 0 ? 0 : 1);
}
// Tamper runs must go red FIRST at the step the scenario prescribes.
if (bad.length === 0) {
  console.error('tamper scenario produced no red step');
  process.exit(1);
}
if (bad[0].step !== scenarioDef.expectStep) {
  console.error(
    `tamper failed at '${bad[0].step}', expected '${scenarioDef.expectStep}'`
  );
  process.exit(1);
}
process.exit(0);
