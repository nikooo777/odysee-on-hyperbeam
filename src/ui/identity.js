// The identity panel: for each evidence object the pipeline verified, show
// the identity triplet — native LBRY id, HyperBEAM commitment id (with the
// conversion rule), and the message id once one has been observed — plus an
// on-demand "fetch committed form" action that retrieves the object's
// committed message through the node's store path and renders the parsed
// Signature-Input, the litmus line included.
import { identityTriplet } from '../identity.js';
import { messageIdFromHeaders } from '../commitments.js';
import { renderCommitmentEntries } from './steps.js';
import { dataBlobs } from '../lbry/descriptor.js';

export function evidenceObjects(state) {
  const rows = [];
  if (state.tx) {
    rows.push({
      title: 'stream transaction',
      kind: 'txid',
      native: state.tx.txid,
      storeKey: state.tx.txid,
      expectedAlg: 'lbry-transaction@1.0/sha-256d',
    });
  }
  if (state.tx && Number.isInteger(state.resolved?.nout)) {
    rows.push({
      title: 'stream claim output',
      kind: 'outpoint',
      native: `${state.tx.txid}:${state.resolved.nout}`,
      storeKey: `${state.tx.txid}:${state.resolved.nout}`,
      expectedAlg: 'lbry-claim@1.0/<type>',
    });
  }
  if (state.claimOutput) {
    rows.push({
      title: 'stream claim id',
      kind: 'claim-id',
      native: state.claimOutput.claimId,
      storeKey: null,
      note: '20-byte claim id — lives inside the claim output commitment',
    });
  }
  if (state.channel) {
    rows.push(
      {
        title: 'channel transaction',
        kind: 'txid',
        native: state.channel.txid,
        storeKey: state.channel.txid,
        expectedAlg: 'lbry-transaction@1.0/sha-256d',
      },
      {
        title: 'channel claim output',
        kind: 'outpoint',
        native: `${state.channel.txid}:${state.channel.nout}`,
        storeKey: `${state.channel.txid}:${state.channel.nout}`,
        expectedAlg: 'lbry-claim@1.0/<type>',
      },
      {
        title: 'channel claim id',
        kind: 'claim-id',
        native: state.channel.claimId,
        storeKey: null,
        note: '20-byte claim id — lives inside the claim output commitment',
      }
    );
  }
  if (state.sdHash) {
    rows.push({
      title: 'stream descriptor blob',
      kind: 'blob',
      native: state.sdHash,
      storeKey: state.sdHash,
      expectedAlg: 'lbry-blob@1.0/sha-384',
    });
  }
  if (state.descriptor) {
    const blobs = dataBlobs(state.descriptor);
    const spot = blobs.length > 1 ? [blobs[0], blobs[blobs.length - 1]] : blobs;
    for (const blob of spot) {
      rows.push({
        title: `data blob #${blob.blobNum}`,
        kind: 'blob',
        native: blob.blobHash,
        storeKey: blob.blobHash,
        expectedAlg: 'lbry-blob@1.0/sha-384',
      });
    }
  }
  return rows;
}

export function renderIdentityPanel(container, state, hb) {
  container.innerHTML = '';
  const rows = evidenceObjects(state);
  if (rows.length === 0) return false;
  for (const row of rows) {
    container.appendChild(renderRow(row, hb));
  }
  return true;
}

function renderRow(row, hb) {
  const triplet = identityTriplet(row.kind, row.native);
  const card = document.createElement('details');
  card.className = 'identity-row';
  const summary = document.createElement('summary');
  summary.innerHTML = `
    <span class="identity-title"></span>
    <code class="identity-native"></code>`;
  summary.querySelector('.identity-title').textContent = row.title;
  summary.querySelector('.identity-native').textContent = shortId(row.native);
  summary.querySelector('.identity-native').title = row.native;
  card.appendChild(summary);

  const body = document.createElement('div');
  body.className = 'identity-body';
  appendFact(body, `native LBRY id (${row.kind})`, row.native);
  appendFact(body, 'HyperBEAM commitment id', triplet.commitmentId);
  appendFact(body, 'conversion rule', triplet.rule);
  const messageIdValue = appendFact(body, 'message id', '— (not yet observed)');
  appendNote(
    body,
    'the native bytes are never lost: the commitment carries them verbatim ' +
      'in its native-id field and (encoded) in its signature field'
  );
  if (row.note) appendNote(body, row.note);

  if (row.storeKey) {
    const actions = document.createElement('div');
    actions.className = 'identity-actions';
    const url = `${hb.baseUrl}/~cache@1.0/read?read=${encodeURIComponent(row.storeKey)}`;
    const fetchButton = document.createElement('button');
    fetchButton.type = 'button';
    fetchButton.textContent = 'fetch committed form';
    fetchButton.title =
      'request the committed message by its native store key and parse the Signature-Input headers';
    const copyButton = document.createElement('button');
    copyButton.type = 'button';
    copyButton.textContent = 'copy URL';
    copyButton.title = url;
    copyButton.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(url);
        copyButton.textContent = 'copied';
        setTimeout(() => (copyButton.textContent = 'copy URL'), 1200);
      } catch {
        copyButton.textContent = url;
      }
    });
    const result = document.createElement('div');
    result.className = 'committed-result';
    fetchButton.addEventListener('click', async () => {
      fetchButton.disabled = true;
      fetchButton.textContent = 'fetching… (ancestry walks can take a while)';
      result.innerHTML = '';
      try {
        const committed = await hb
          .step('committed-form')
          .fetchCommittedForm(row.storeKey);
        renderCommittedResult(result, committed, url);
        const messageId = messageIdFromHeaders(committed.headers);
        if (messageId) messageIdValue.textContent = messageId;
      } catch (err) {
        appendNote(result, `committed-form fetch failed: ${err.message}`);
      } finally {
        fetchButton.disabled = false;
        fetchButton.textContent = 'fetch committed form';
      }
    });
    actions.append(fetchButton, copyButton);
    body.appendChild(actions);
    body.appendChild(result);
    if (row.expectedAlg) {
      appendNote(body, `expected commitment alg: ${row.expectedAlg}`);
    }
  }
  card.appendChild(body);
  return card;
}

function renderCommittedResult(container, committed, url) {
  container.innerHTML = '';
  appendFact(container, 'status', String(committed.status));
  appendFact(container, 'raw response URL', url);
  if (committed.bodyLength !== null) {
    appendFact(container, 'body', `${committed.bodyLength} bytes (multipart committed form)`);
  }
  if (!committed.ok) {
    appendNote(
      container,
      'the store path did not serve this key — check that the demo node mounts the LBRY stores'
    );
    return;
  }
  renderCommitmentEntries(container, {
    headers: committed.headers,
    commitments: null,
    kind: 'committed',
    path: url,
    error: null,
  });
}

function appendFact(container, label, value) {
  const row = document.createElement('div');
  row.className = 'proof-row';
  const labelEl = document.createElement('span');
  labelEl.className = 'proof-label';
  labelEl.textContent = label;
  const valueEl = document.createElement('span');
  valueEl.className = 'proof-value';
  valueEl.textContent = value;
  row.append(labelEl, valueEl);
  container.appendChild(row);
  return valueEl;
}

function appendNote(container, text) {
  const note = document.createElement('p');
  note.className = 'proof-note';
  note.textContent = text;
  container.appendChild(note);
}

function shortId(value) {
  if (value.length <= 24) return value;
  return `${value.slice(0, 16)}…${value.slice(-6)}`;
}
