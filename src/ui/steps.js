// The step ladder: each verification step renders as a card with three
// layers of detail. Always visible: the step title, a status chip, and the
// one-line outcome. One click opens the plain-language story (what question
// the step answers, how the browser answers it, what a lying node would
// look like). Inside the story, "proof" opens the raw values the verdict
// rests on. Failed or mismatched steps unfold themselves.
import { STEP_NARRATIVES, CHIP_EXPLANATIONS } from './narrative.js';

export const STEPS = [
  ['input', '1. Parse input'],
  ['resolve', '2. Resolve claim'],
  ['stream-tx', '3. Stream transaction'],
  ['claim-output', '4. Claim output'],
  ['channel', '5. Channel evidence'],
  ['signature', '6. Channel signature'],
  ['sd-hash', '7. Claim sd_hash'],
  ['descriptor', '8. Descriptor'],
  ['blobs', '9. Blob spot check'],
  ['cross-check', '10. Server cross-check'],
  ['playback', '11. Playback'],
];

const CHIP_LABELS = {
  pending: 'pending',
  running: 'running…',
  verified: 'client-verified',
  server: 'server-claimed',
  trusted: 'trusted',
  na: 'not applicable',
  failed: 'FAILED',
  mismatch: 'SERVER MISMATCH',
};

const AUTO_EXPAND = new Set(['failed', 'mismatch']);

export function createStepLadder(container, banner) {
  container.innerHTML = '';
  const rows = new Map();
  for (const [id, title] of STEPS) {
    const row = document.createElement('li');
    row.className = 'step pending';
    row.innerHTML = `
      <button class="step-head" type="button" aria-expanded="false">
        <span class="step-caret">▸</span>
        <span class="step-title"></span>
        <span class="chip">pending</span>
      </button>
      <div class="step-detail"></div>
      <div class="step-body" hidden>
        <p class="step-question"></p>
        <p class="step-how"></p>
        <p class="step-catches"></p>
        <details class="step-proof" hidden>
          <summary>proof</summary>
          <div class="proof-rows"></div>
        </details>
      </div>`;
    const narrative = STEP_NARRATIVES[id];
    row.querySelector('.step-title').textContent = title;
    row.querySelector('.step-question').textContent = narrative.question;
    row.querySelector('.step-how').textContent = narrative.how;
    row.querySelector('.step-catches').textContent =
      `What this step would catch: ${narrative.catches}`;
    row.querySelector('.step-head').addEventListener('click', () => {
      setExpanded(row, row.querySelector('.step-body').hidden);
    });
    container.appendChild(row);
    rows.set(id, row);
  }

  return function report(id, status, detail = '', evidence = []) {
    const row = rows.get(id);
    if (!row) return;
    row.className = `step ${status}`;
    const chip = row.querySelector('.chip');
    chip.textContent = CHIP_LABELS[status] ?? status;
    chip.title = CHIP_EXPLANATIONS[status] ?? '';
    row.querySelector('.step-detail').textContent = detail;
    const proof = row.querySelector('.step-proof');
    if (evidence.length > 0) {
      proof.hidden = false;
      renderProof(proof.querySelector('.proof-rows'), evidence);
    } else {
      proof.hidden = true;
    }
    if (AUTO_EXPAND.has(status)) {
      setExpanded(row, true);
      proof.open = true;
    }
    if (status === 'mismatch') {
      banner.hidden = false;
      banner.textContent = `SERVER MISMATCH — ${detail}`;
    }
  };
}

function setExpanded(row, expanded) {
  row.querySelector('.step-body').hidden = !expanded;
  row.querySelector('.step-caret').textContent = expanded ? '▾' : '▸';
  row.querySelector('.step-head').setAttribute('aria-expanded', String(expanded));
}

// Evidence lines of the form "label: value" render as aligned proof rows;
// prose lines render as notes. A line only counts as label/value when the
// part before the first ": " is short and does not break a parenthesis —
// "verified with secp256k1 (prehash: false, …)" is prose, not a label.
function renderProof(container, evidence) {
  container.innerHTML = '';
  for (const line of evidence) {
    const split = labelValue(line);
    if (split) {
      const row = document.createElement('div');
      row.className = 'proof-row';
      const label = document.createElement('span');
      label.className = 'proof-label';
      label.textContent = split.label;
      const value = document.createElement('span');
      value.className = 'proof-value';
      value.textContent = split.value;
      row.append(label, value);
      container.appendChild(row);
    } else {
      const note = document.createElement('p');
      note.className = 'proof-note';
      note.textContent = line;
      container.appendChild(note);
    }
  }
}

function labelValue(line) {
  const at = line.indexOf(': ');
  if (at <= 0 || at > 48) return null;
  const label = line.slice(0, at);
  const opens = (label.match(/\(/g) ?? []).length;
  const closes = (label.match(/\)/g) ?? []).length;
  if (opens !== closes) return null;
  return { label, value: line.slice(at + 2) };
}

export function resetBanner(banner) {
  banner.hidden = true;
  banner.textContent = '';
}
