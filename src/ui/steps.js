// The step ladder: each verification step renders as a card with three
// layers of detail. Always visible: the step title, a status chip, and the
// one-line outcome. One click opens the plain-language story (what question
// the step answers, how the browser answers it, what a lying node would
// look like). Inside the story, "proof" opens the raw values the verdict
// rests on, and "requests" lists every HTTP exchange the step caused, each
// expandable to its parsed commitment structure. Failed or mismatched steps
// unfold themselves.
import { narrativeFor, CHIP_EXPLANATIONS } from './narrative.js';
import {
  commitmentEntries,
  CLASS_LABELS,
  CLASS_NOTES,
} from '../commitments.js';

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

export function createStepLadder(container, banner, options = {}) {
  const { mode = 'default', exchanges = [] } = options;
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
        <details class="step-requests" hidden>
          <summary>requests</summary>
          <div class="request-rows"></div>
        </details>
      </div>`;
    const narrative = narrativeFor(id, mode);
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

  function refreshRequests() {
    for (const [id, row] of rows) {
      const entries = exchanges.filter((entry) => entry.label === id);
      const requests = row.querySelector('.step-requests');
      if (entries.length === 0) {
        requests.hidden = true;
        continue;
      }
      requests.hidden = false;
      renderRequests(requests.querySelector('.request-rows'), entries);
    }
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
    refreshRequests();
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

// One line per exchange (method, short path, status), expandable to the
// parsed commitment detail rendered from whichever encoding the response
// used — Signature-Input headers or the body commitments map.
function renderRequests(container, entries) {
  container.innerHTML = '';
  for (const entry of entries) {
    const item = document.createElement('details');
    item.className = 'request';
    const summary = document.createElement('summary');
    const status =
      entry.error !== null
        ? 'network error'
        : entry.status === null
          ? 'in flight'
          : String(entry.status);
    summary.textContent = `${entry.method} ${shortPath(entry.path)} → ${status}${entry.ms !== null ? ` (${entry.ms}ms)` : ''}`;
    item.appendChild(summary);
    const body = document.createElement('div');
    body.className = 'request-detail';
    if (entry.error !== null) {
      appendNote(body, `request failed before a response arrived: ${entry.error}`);
    }
    renderCommitmentEntries(body, entry);
    item.appendChild(body);
    container.appendChild(item);
  }
}

export function renderCommitmentEntries(container, entry) {
  const parsed = commitmentEntries(entry);
  if (parsed.length === 0) {
    if (entry.error === null) {
      appendNote(
        container,
        entry.kind === 'bytes' || entry.kind === 'probe'
          ? 'content-addressed bytes — verified by re-hashing, no commitment structure to parse'
          : 'no commitment structure in this response'
      );
    }
    return;
  }
  if (parsed[0].encoding === 'json' && isCompositionPath(entry.path)) {
    appendNote(
      container,
      'composition output: a node-signed view assembled for this request, ' +
        'not a source object — the transport signature below arrives in ' +
        'the body commitments map of the JSON response'
    );
  }
  for (const commitment of parsed) {
    container.appendChild(renderCommitment(commitment));
  }
  const rawHeader = entry.headers?.['signature-input'];
  if (rawHeader) {
    const raw = document.createElement('details');
    raw.className = 'raw-header';
    const summary = document.createElement('summary');
    summary.textContent = 'raw signature-input header';
    raw.appendChild(summary);
    const pre = document.createElement('pre');
    pre.textContent = rawHeader;
    raw.appendChild(pre);
    container.appendChild(raw);
  }
}

function renderCommitment(commitment) {
  const block = document.createElement('div');
  block.className = `commitment ${commitment.cls}`;
  const head = document.createElement('div');
  head.className = 'commitment-head';
  const chip = document.createElement('span');
  chip.className = `chip-sample ${commitment.cls === 'source' ? 'verified' : commitment.cls}`;
  chip.textContent = CLASS_LABELS[commitment.cls];
  chip.title = CLASS_NOTES[commitment.cls];
  const alg = document.createElement('code');
  alg.textContent = `alg="${commitment.params.alg ?? ''}"`;
  head.append(chip, alg);
  block.appendChild(head);
  const facts = [];
  if (commitment.params['native-id']) {
    facts.push(
      `native-id (${commitment.params['native-id-type'] ?? 'unknown type'}): ${commitment.params['native-id']}`
    );
  }
  if (commitment.params.keyid) {
    facts.push(`keyid: ${truncate(commitment.params.keyid, 60)}`);
  }
  if (commitment.covered.length > 0) {
    facts.push(`covers: ${commitment.covered.join(', ')}`);
  }
  facts.push(`commitment label: ${truncate(commitment.label, 60)}`);
  for (const fact of facts) {
    const line = document.createElement('div');
    line.className = 'commitment-fact';
    line.textContent = fact;
    block.appendChild(line);
  }
  return block;
}

function isCompositionPath(path) {
  return typeof path === 'string' && path.startsWith('/~odysee@1.0/');
}

function appendNote(container, text) {
  const note = document.createElement('p');
  note.className = 'proof-note';
  note.textContent = text;
  container.appendChild(note);
}

function shortPath(path) {
  if (typeof path !== 'string') return String(path);
  return path.length > 64 ? `${path.slice(0, 56)}…` : path;
}

function truncate(value, max) {
  if (typeof value !== 'string' || value.length <= max) return value;
  return `${value.slice(0, max)}…`;
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
