// The step ladder: each verification step renders as a row with a status
// chip and an expandable evidence panel.
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

export function createStepLadder(container, banner) {
  container.innerHTML = '';
  const rows = new Map();
  for (const [id, title] of STEPS) {
    const row = document.createElement('li');
    row.className = 'step pending';
    row.innerHTML = `
      <div class="step-head">
        <span class="step-title"></span>
        <span class="chip">pending</span>
      </div>
      <div class="step-detail"></div>
      <details class="step-evidence" hidden>
        <summary>evidence</summary>
        <pre></pre>
      </details>`;
    row.querySelector('.step-title').textContent = title;
    container.appendChild(row);
    rows.set(id, row);
  }

  return function report(id, status, detail = '', evidence = []) {
    const row = rows.get(id);
    if (!row) return;
    row.className = `step ${status}`;
    row.querySelector('.chip').textContent = CHIP_LABELS[status] ?? status;
    row.querySelector('.step-detail').textContent = detail;
    const panel = row.querySelector('.step-evidence');
    if (evidence.length > 0) {
      panel.hidden = false;
      panel.querySelector('pre').textContent = evidence.join('\n');
    } else {
      panel.hidden = true;
    }
    if (status === 'mismatch') {
      banner.hidden = false;
      banner.textContent = `SERVER MISMATCH — ${detail}`;
    }
  };
}

export function resetBanner(banner) {
  banner.hidden = true;
  banner.textContent = '';
}
