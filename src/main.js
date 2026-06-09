import './style.css';
import { HbClient } from './hb.js';
import { runPipeline, verifyAllBlobs } from './pipeline.js';
import { createStepLadder, resetBanner } from './ui/steps.js';
import { playStream, playVerifiedBytes, destroyPlayer } from './ui/player.js';
import { SCENARIOS, tamperHooks } from './tamper.js';

const DEFAULT_NODE = 'http://localhost:8734';

const nodeInput = document.querySelector('#node-url');
const targetInput = document.querySelector('#target');
const tamperSelect = document.querySelector('#tamper');
const verifyButton = document.querySelector('#verify');
const banner = document.querySelector('#banner');
const stepsContainer = document.querySelector('#steps');
const playbackSection = document.querySelector('#playback-section');
const playStreamButton = document.querySelector('#play-stream');
const playVerifiedButton = document.querySelector('#play-verified');
const sweepButton = document.querySelector('#sweep');
const sweepProgress = document.querySelector('#sweep-progress');
const playerContainer = document.querySelector('#player');

nodeInput.value = localStorage.getItem('odysee-on-hb:node') ?? DEFAULT_NODE;
for (const scenario of SCENARIOS) {
  const option = document.createElement('option');
  option.value = scenario.id;
  option.textContent = scenario.label;
  tamperSelect.appendChild(option);
}

let current = null;
let sweepArmed = false;

async function verify() {
  const node = nodeInput.value.trim();
  localStorage.setItem('odysee-on-hb:node', node);
  const input = targetInput.value.trim();
  if (!input) return;

  verifyButton.disabled = true;
  resetBanner(banner);
  destroyPlayer();
  playbackSection.hidden = true;
  playVerifiedButton.disabled = true;
  sweepProgress.textContent = '';
  sweepArmed = false;

  const report = createStepLadder(stepsContainer, banner);
  const hb = new HbClient(node);
  const tamper = tamperHooks(tamperSelect.value);
  try {
    const state = await runPipeline({ input, hb, report, tamper });
    current = { state, hb, tamper };
    if (state.descriptor && state.verdicts.chainFailed == null) {
      const transportNote =
        'streamed bytes are transport-trusted; spot-checked, not re-verified per slice';
      report('playback', 'trusted', 'ready to play', [
        `media URL: ${hb.mediaUrl(state.sdHash)}`,
        `content type: ${state.resolved.contentType ?? 'video/mp4'}`,
        `exact size: ${state.exactSize} bytes (computed client-side)`,
        transportNote,
      ]);
      playbackSection.hidden = false;
    } else {
      report('playback', 'na', 'unavailable — verification did not complete');
    }
  } catch (err) {
    report('playback', 'na', `pipeline error: ${err.message}`);
  } finally {
    verifyButton.disabled = false;
  }
}

verifyButton.addEventListener('click', verify);
targetInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') verify();
});

playStreamButton.addEventListener('click', () => {
  if (!current) return;
  const { state, hb } = current;
  playStream(playerContainer, hb.mediaUrl(state.sdHash), state.resolved.contentType);
});

sweepButton.addEventListener('click', async () => {
  if (!current) return;
  const { state, hb, tamper } = current;
  if (!sweepArmed) {
    sweepArmed = true;
    const mb = (state.exactSize / (1024 * 1024)).toFixed(1);
    sweepProgress.textContent = `this will download and verify ${mb} MB in memory — click again to confirm`;
    return;
  }
  sweepArmed = false;
  sweepButton.disabled = true;
  try {
    await verifyAllBlobs(state, hb, tamper, (done, total) => {
      sweepProgress.textContent = `verified ${done}/${total} blobs`;
    });
    sweepProgress.textContent += ' — all blobs verified, verified playback enabled';
    playVerifiedButton.disabled = false;
  } catch (err) {
    sweepProgress.textContent = `sweep failed: ${err.message}`;
  } finally {
    sweepButton.disabled = false;
  }
});

playVerifiedButton.addEventListener('click', () => {
  if (!current?.state.verifiedBytes) return;
  playVerifiedBytes(
    playerContainer,
    current.state.verifiedBytes,
    current.state.resolved.contentType
  );
});
