import videojs from 'video.js';
import 'video.js/dist/video-js.css';

let player = null;
let objectUrl = null;

export function playStream(container, src, contentType) {
  destroyPlayer();
  const video = document.createElement('video-js');
  video.className = 'video-js vjs-default-skin vjs-big-play-centered';
  container.innerHTML = '';
  container.appendChild(video);
  player = videojs(video, {
    controls: true,
    fluid: true,
    preload: 'auto',
    sources: [{ src, type: contentType || 'video/mp4' }],
  });
  return player;
}

export function playVerifiedBytes(container, bytes, contentType) {
  const blob = new Blob([bytes], { type: contentType || 'video/mp4' });
  const url = URL.createObjectURL(blob);
  const result = playStream(container, url, contentType);
  objectUrl = url;
  return result;
}

export function destroyPlayer() {
  if (player) {
    player.dispose();
    player = null;
  }
  if (objectUrl) {
    URL.revokeObjectURL(objectUrl);
    objectUrl = null;
  }
}
