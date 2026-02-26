import {
  MusikeyConfig, MusikeyScale, MusikeyCredential, MusikeySong,
  MusikeyAnalysis, MusikeyError, DEFAULT_CONFIG, SCALE_NAMES
} from '../core/types';
import { generateSong } from '../core/song';
import { scramble, descramble } from '../core/crypto';
import { analyze } from '../core/analysis';
import { calculateEntropy } from '../core/entropy';
import { MusikeyPlayer } from '../audio/player';
import { highlightNote, updatePiano, renderPiano, resetPiano } from './piano';
import { triggerNote, updateVisualizer, renderVisualizer, pulseSuccess, shakeFailure, randomize, resetVisualizer } from './visualizer';

declare global {
  interface Window {
    musikeyStore: {
      getCredential: (userId: string) => Promise<MusikeyCredential | null>;
      saveCredential: (cred: MusikeyCredential) => Promise<void>;
      listUsers: () => Promise<string[]>;
      deleteCredential: (userId: string) => Promise<void>;
      exportCredential: (userId: string) => Promise<string | null>;
      importCredential: (json: string) => Promise<boolean>;
      showSaveDialog: (defaultName: string) => Promise<string | null>;
      showOpenDialog: () => Promise<string | null>;
      cascadedKDF: (passphrase: string, saltB64: string, iterations: number) => Promise<string>;
    };
  }
}

type AppState = 'idle' | 'enrolling' | 'authenticating' | 'playing' | 'success' | 'failure' | 'locked' | 'cooldown';

let config: MusikeyConfig = { ...DEFAULT_CONFIG };
let state: AppState = 'idle';
let player = new MusikeyPlayer();
let lastSong: MusikeySong | null = null;
let lastAnalysis: MusikeyAnalysis | null = null;
let lastTime = performance.now();
let animId = 0;
let songClearTimeout: ReturnType<typeof setTimeout> | null = null;
let cooldownInterval: ReturnType<typeof setInterval> | null = null;

// DOM elements
let usernameInput: HTMLInputElement;
let passphraseInput: HTMLInputElement;
let scaleSelect: HTMLSelectElement;
let lengthSlider: HTMLInputElement;
let lengthLabel: HTMLSpanElement;
let enrollBtn: HTMLButtonElement;
let authBtn: HTMLButtonElement;
let playBtn: HTMLButtonElement;
let exportBtn: HTMLButtonElement;
let importBtn: HTMLButtonElement;
let deleteBtn: HTMLButtonElement;
let statusEl: HTMLDivElement;
let entropyEl: HTMLSpanElement;
let analysisEl: HTMLDivElement;
let attemptsEl: HTMLSpanElement;
let userListEl: HTMLSelectElement;
let pianoCanvas: HTMLCanvasElement;
let visCanvas: HTMLCanvasElement;
let pianoCtx: CanvasRenderingContext2D;
let visCtx: CanvasRenderingContext2D;
let strengthBar: HTMLDivElement;
let strengthLabel: HTMLSpanElement;

// Passphrase strength checker
interface StrengthResult {
  score: number; // 0-4
  label: string;
  color: string;
  entropy: number;
  ok: boolean;
}

function checkPassphraseStrength(passphrase: string): StrengthResult {
  if (!passphrase) return { score: 0, label: '', color: '#888', entropy: 0, ok: false };

  const len = passphrase.length;
  const hasUpper = /[A-Z]/.test(passphrase);
  const hasLower = /[a-z]/.test(passphrase);
  const hasDigit = /[0-9]/.test(passphrase);
  const hasSymbol = /[^A-Za-z0-9]/.test(passphrase);
  const categories = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;

  // Estimate entropy: log2(charset^length)
  let charsetSize = 0;
  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasDigit) charsetSize += 10;
  if (hasSymbol) charsetSize += 32;
  if (charsetSize === 0) charsetSize = 26;
  const entropy = Math.floor(len * Math.log2(charsetSize));

  // Check for common patterns that reduce effective entropy
  const hasSequential = /(?:012|123|234|345|456|567|678|789|abc|bcd|cde|def)/.test(passphrase.toLowerCase());
  const hasRepeating = /(.)\1{2,}/.test(passphrase);
  const penaltyBits = (hasSequential ? 10 : 0) + (hasRepeating ? 8 : 0);
  const effectiveEntropy = Math.max(0, entropy - penaltyBits);

  let score = 0;
  if (len >= 8) score = 1;
  if (len >= 12 && categories >= 3 && effectiveEntropy >= 50) score = 2;
  if (len >= 16 && categories >= 3 && effectiveEntropy >= 65) score = 3;
  if (len >= 20 && categories >= 4 && effectiveEntropy >= 80) score = 4;

  const labels = ['Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
  const colors = ['#ff6b6b', '#ff6b6b', '#f0a500', '#4ecca3', '#4ecca3'];

  return {
    score,
    label: labels[score],
    color: colors[score],
    entropy: effectiveEntropy,
    ok: score >= 2 && len >= 12 && categories >= 3 && effectiveEntropy >= 50,
  };
}

function updateStrengthMeter(): void {
  const result = checkPassphraseStrength(passphraseInput.value);
  strengthBar.style.width = `${result.score * 25}%`;
  strengthBar.style.background = result.color;
  strengthLabel.textContent = result.label ? `${result.label} (~${result.entropy} bits)` : '';
  strengthLabel.style.color = result.color;
}

// Credential integrity hash
async function computeIntegrityHash(cred: MusikeyCredential): Promise<string> {
  const data = JSON.stringify({
    userId: cred.userId,
    scrambledSong: cred.scrambledSong,
    scale: cred.scale,
    rootNote: cred.rootNote,
    createdTimestamp: cred.createdTimestamp,
    version: cred.version,
  });
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  const bytes = new Uint8Array(hash);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyIntegrity(cred: MusikeyCredential): Promise<boolean> {
  if (!cred.integrityHash) return true; // Legacy credential
  const expected = await computeIntegrityHash(cred);
  return cred.integrityHash === expected;
}

function setStatus(message: string, color: string = '#ececec'): void {
  statusEl.textContent = message;
  statusEl.style.color = color;
}

function setAnalysis(a: MusikeyAnalysis | null): void {
  lastAnalysis = a;
  if (!a) {
    analysisEl.innerHTML = '';
    return;
  }
  analysisEl.innerHTML = `
    <div class="analysis-row"><span>Harmonic</span><div class="bar-bg"><div class="bar-fill" style="width:${a.harmonicScore * 100}%;background:#4ecca3"></div></div><span>${a.harmonicScore.toFixed(2)}</span></div>
    <div class="analysis-row"><span>Melody</span><div class="bar-bg"><div class="bar-fill" style="width:${a.melodyScore * 100}%;background:#e94560"></div></div><span>${a.melodyScore.toFixed(2)}</span></div>
    <div class="analysis-row"><span>Rhythm</span><div class="bar-bg"><div class="bar-fill" style="width:${a.rhythmScore * 100}%;background:#0f3460"></div></div><span>${a.rhythmScore.toFixed(2)}</span></div>
    <div class="analysis-row"><span>Scale</span><div class="bar-bg"><div class="bar-fill" style="width:${a.scaleAdherence * 100}%;background:#e94560"></div></div><span>${a.scaleAdherence.toFixed(2)}</span></div>
    <div class="analysis-overall"><span>Overall: ${a.overallMusicality.toFixed(2)}</span><span class="${a.isValidMusic ? 'valid' : 'invalid'}">${a.isValidMusic ? 'VALID' : 'INVALID'}</span></div>
  `;
}

async function refreshUserList(): Promise<void> {
  const users = await window.musikeyStore.listUsers();
  userListEl.innerHTML = '<option value="">-- Select User --</option>';
  for (const u of users) {
    const opt = document.createElement('option');
    opt.value = u;
    opt.textContent = u;
    userListEl.appendChild(opt);
  }
}

// Schedule clearing sensitive song data from memory
function scheduleSongClear(): void {
  if (songClearTimeout) clearTimeout(songClearTimeout);
  songClearTimeout = setTimeout(() => {
    lastSong = null;
    lastAnalysis = null;
  }, 60000); // 60 seconds
}

// Rate limiting: exponential backoff
function getCooldownRemaining(credential: MusikeyCredential): number {
  if (!credential.lastFailedTimestamp || credential.failedAttempts === 0) return 0;
  const backoffSeconds = Math.pow(2, Math.min(credential.failedAttempts, 5));
  const elapsed = (Date.now() - credential.lastFailedTimestamp) / 1000;
  return Math.max(0, backoffSeconds - elapsed);
}

function startCooldownTimer(seconds: number): void {
  state = 'cooldown';
  setButtonsEnabled(false);
  let remaining = Math.ceil(seconds);

  const tick = () => {
    if (remaining <= 0) {
      if (cooldownInterval) clearInterval(cooldownInterval);
      cooldownInterval = null;
      state = 'idle';
      setButtonsEnabled(true);
      setStatus('Ready', '#ececec');
      return;
    }
    setStatus(`Rate limited — wait ${remaining}s`, '#f0a500');
    remaining--;
  };

  tick();
  cooldownInterval = setInterval(tick, 1000);
}

async function doEnroll(): Promise<void> {
  const username = usernameInput.value.trim();
  const passphrase = passphraseInput.value;
  if (!username || !passphrase) {
    setStatus('Enter username and passphrase', '#ff6b6b');
    return;
  }

  // Passphrase strength check
  const strength = checkPassphraseStrength(passphrase);
  if (!strength.ok) {
    setStatus('Passphrase too weak — need 12+ chars, 3+ categories', '#ff6b6b');
    return;
  }

  state = 'enrolling';
  setStatus('Generating musical composition...', '#e94560');
  setButtonsEnabled(false);
  randomize();

  await new Promise(r => setTimeout(r, 300));

  config.songLength = parseInt(lengthSlider.value);
  config.preferredScale = parseInt(scaleSelect.value) as MusikeyScale;
  const song = generateSong(config);

  const a = analyze(song, config.musicalityThreshold);
  if (!a.isValidMusic) {
    setStatus('Generated song failed musicality check, retrying...', '#ff6b6b');
    state = 'idle';
    setButtonsEnabled(true);
    return;
  }

  setStatus('PBKDF2 → scrypt → double AES-256-GCM...', '#e94560');
  await new Promise(r => setTimeout(r, 100));

  const { scrambled, error } = await scramble(song, passphrase, config.scrambleIterations);
  if (error !== MusikeyError.OK) {
    setStatus('Encryption failed', '#ff6b6b');
    shakeFailure();
    state = 'failure';
    setButtonsEnabled(true);
    return;
  }

  const credential: MusikeyCredential = {
    userId: username,
    scrambledSong: scrambled,
    scale: song.scale,
    rootNote: song.rootNote,
    createdTimestamp: Date.now(),
    lastAuthTimestamp: 0,
    lastFailedTimestamp: 0,
    authAttempts: 0,
    failedAttempts: 0,
    locked: false,
    version: 2,
    integrityHash: '',
  };
  credential.integrityHash = await computeIntegrityHash(credential);

  await window.musikeyStore.saveCredential(credential);
  await refreshUserList();

  lastSong = song;
  setAnalysis(a);
  entropyEl.textContent = String(song.entropyBits);
  attemptsEl.textContent = '0 / ' + config.maxFailedAttempts;

  setStatus(`Enrolled "${username}" — PBKDF2+scrypt cascaded + double AES-GCM`, '#4ecca3');
  pulseSuccess();
  state = 'success';
  setButtonsEnabled(true);

  // Clear passphrase from input
  passphraseInput.value = '';
  updateStrengthMeter();
  scheduleSongClear();

  playCurrentSong();
}

async function doAuthenticate(): Promise<void> {
  const username = usernameInput.value.trim() || userListEl.value;
  const passphrase = passphraseInput.value;
  if (!username || !passphrase) {
    setStatus('Enter username and passphrase', '#ff6b6b');
    return;
  }

  state = 'authenticating';
  setStatus('Retrieving credential...', '#e94560');
  setButtonsEnabled(false);

  const credential = await window.musikeyStore.getCredential(username);
  if (!credential) {
    setStatus(`User "${username}" not found`, '#ff6b6b');
    shakeFailure();
    state = 'idle';
    setButtonsEnabled(true);
    return;
  }

  if (credential.locked) {
    setStatus(`Account "${username}" is locked`, '#ff6b6b');
    state = 'locked';
    setButtonsEnabled(true);
    attemptsEl.textContent = `${credential.failedAttempts} / ${config.maxFailedAttempts} (LOCKED)`;
    passphraseInput.value = '';
    updateStrengthMeter();
    return;
  }

  // Rate limiting check
  const cooldown = getCooldownRemaining(credential);
  if (cooldown > 0) {
    startCooldownTimer(cooldown);
    passphraseInput.value = '';
    updateStrengthMeter();
    return;
  }

  // Integrity check
  const integrityOk = await verifyIntegrity(credential);
  if (!integrityOk) {
    setStatus('Credential integrity check failed — possible tampering', '#ff6b6b');
    shakeFailure();
    state = 'failure';
    setButtonsEnabled(true);
    passphraseInput.value = '';
    updateStrengthMeter();
    return;
  }

  setStatus('Cascaded KDF + double-layer decrypt...', '#e94560');
  randomize();
  await new Promise(r => setTimeout(r, 200));

  credential.authAttempts++;

  const { song, error } = await descramble(credential.scrambledSong, passphrase);

  if (error !== MusikeyError.OK || !song) {
    credential.failedAttempts++;
    credential.lastFailedTimestamp = Date.now();
    if (credential.failedAttempts >= config.maxFailedAttempts) {
      credential.locked = true;
      // Self-destruct: permanently wipe the credential after max failures
      (credential as any)._selfDestruct = true;
      await window.musikeyStore.saveCredential(credential);
      await refreshUserList();
      attemptsEl.textContent = `DESTROYED`;
      setStatus(`Credential "${username}" self-destructed — permanently wiped`, '#ff6b6b');
      shakeFailure();
      state = 'locked';
      setButtonsEnabled(true);
      passphraseInput.value = '';
      updateStrengthMeter();
      return;
    }
    await window.musikeyStore.saveCredential(credential);
    attemptsEl.textContent = `${credential.failedAttempts} / ${config.maxFailedAttempts}`;
    setStatus('Authentication failed — wrong passphrase', '#ff6b6b');
    shakeFailure();
    state = 'failure';
    setButtonsEnabled(true);
    passphraseInput.value = '';
    updateStrengthMeter();

    // Start cooldown
    const nextCooldown = Math.pow(2, Math.min(credential.failedAttempts, 5));
    startCooldownTimer(nextCooldown);
    return;
  }

  // Restore song metadata from credential
  song.scale = credential.scale;
  song.rootNote = credential.rootNote;
  song.entropyBits = calculateEntropy(song);

  const a = analyze(song, config.musicalityThreshold);
  if (!a.isValidMusic) {
    credential.failedAttempts++;
    credential.lastFailedTimestamp = Date.now();
    if (credential.failedAttempts >= config.maxFailedAttempts) {
      credential.locked = true;
      (credential as any)._selfDestruct = true;
      await window.musikeyStore.saveCredential(credential);
      await refreshUserList();
      attemptsEl.textContent = 'DESTROYED';
      setStatus(`Credential "${username}" self-destructed`, '#ff6b6b');
      shakeFailure();
      state = 'locked';
      setButtonsEnabled(true);
      passphraseInput.value = '';
      updateStrengthMeter();
      return;
    }
    await window.musikeyStore.saveCredential(credential);
    attemptsEl.textContent = `${credential.failedAttempts} / ${config.maxFailedAttempts}`;
    setStatus('Musicality verification failed', '#ff6b6b');
    shakeFailure();
    state = 'failure';
    setButtonsEnabled(true);
    passphraseInput.value = '';
    updateStrengthMeter();
    return;
  }

  // Success
  credential.failedAttempts = 0;
  credential.lastAuthTimestamp = Date.now();
  await window.musikeyStore.saveCredential(credential);

  lastSong = song;
  setAnalysis(a);
  entropyEl.textContent = String(song.entropyBits);
  attemptsEl.textContent = `0 / ${config.maxFailedAttempts}`;

  setStatus(`Authenticated "${username}" successfully!`, '#4ecca3');
  pulseSuccess();
  state = 'success';
  setButtonsEnabled(true);

  passphraseInput.value = '';
  updateStrengthMeter();
  scheduleSongClear();

  playCurrentSong();
}

function playCurrentSong(): void {
  if (!lastSong) {
    setStatus('No song to play', '#ff6b6b');
    return;
  }

  if (player.isPlaying) {
    player.stop();
    resetPiano();
    resetVisualizer();
    playBtn.textContent = 'Play';
    state = 'idle';
    return;
  }

  state = 'playing';
  playBtn.textContent = 'Stop';

  player.onNote = (_idx, event) => {
    highlightNote(event.note);
    triggerNote(event.note, event.velocity);
  };

  player.onComplete = () => {
    playBtn.textContent = 'Play';
    state = 'idle';
  };

  player.play(lastSong);
}

async function doExport(): Promise<void> {
  const username = usernameInput.value.trim() || userListEl.value;
  if (!username) {
    setStatus('Select a user to export', '#ff6b6b');
    return;
  }
  const json = await window.musikeyStore.exportCredential(username);
  if (!json) {
    setStatus('No credential found', '#ff6b6b');
    return;
  }
  const filePath = await window.musikeyStore.showSaveDialog(`${username}.musikey`);
  if (!filePath) return;
  setStatus(`Credential exported for "${username}"`, '#4ecca3');
}

async function doImport(): Promise<void> {
  const json = await window.musikeyStore.showOpenDialog();
  if (!json) return;
  const ok = await window.musikeyStore.importCredential(json);
  if (ok) {
    await refreshUserList();
    setStatus('Credential imported successfully', '#4ecca3');
  } else {
    setStatus('Invalid credential file', '#ff6b6b');
  }
}

async function doDelete(): Promise<void> {
  const username = usernameInput.value.trim() || userListEl.value;
  if (!username) {
    setStatus('Select a user to delete', '#ff6b6b');
    return;
  }
  await window.musikeyStore.deleteCredential(username);
  await refreshUserList();
  setStatus(`Deleted "${username}"`, '#4ecca3');
  attemptsEl.textContent = '-';
  setAnalysis(null);
  entropyEl.textContent = '-';
}

function setButtonsEnabled(enabled: boolean): void {
  enrollBtn.disabled = !enabled;
  authBtn.disabled = !enabled;
  exportBtn.disabled = !enabled;
  importBtn.disabled = !enabled;
  deleteBtn.disabled = !enabled;
}

function animate(): void {
  const now = performance.now();
  const delta = now - lastTime;
  lastTime = now;

  updatePiano(delta);
  updateVisualizer(delta);

  pianoCtx.clearRect(0, 0, pianoCanvas.width, pianoCanvas.height);
  renderPiano(pianoCtx, pianoCanvas.width, pianoCanvas.height);

  visCtx.clearRect(0, 0, visCanvas.width, visCanvas.height);
  renderVisualizer(visCtx, visCanvas.width, visCanvas.height);

  animId = requestAnimationFrame(animate);
}

function onUserSelect(): void {
  const userId = userListEl.value;
  if (userId) {
    usernameInput.value = userId;
  }
}

export function initApp(): void {
  usernameInput = document.getElementById('username') as HTMLInputElement;
  passphraseInput = document.getElementById('passphrase') as HTMLInputElement;
  scaleSelect = document.getElementById('scale') as HTMLSelectElement;
  lengthSlider = document.getElementById('songLength') as HTMLInputElement;
  lengthLabel = document.getElementById('lengthLabel') as HTMLSpanElement;
  enrollBtn = document.getElementById('enrollBtn') as HTMLButtonElement;
  authBtn = document.getElementById('authBtn') as HTMLButtonElement;
  playBtn = document.getElementById('playBtn') as HTMLButtonElement;
  exportBtn = document.getElementById('exportBtn') as HTMLButtonElement;
  importBtn = document.getElementById('importBtn') as HTMLButtonElement;
  deleteBtn = document.getElementById('deleteBtn') as HTMLButtonElement;
  statusEl = document.getElementById('status') as HTMLDivElement;
  entropyEl = document.getElementById('entropy') as HTMLSpanElement;
  analysisEl = document.getElementById('analysis') as HTMLDivElement;
  attemptsEl = document.getElementById('attempts') as HTMLSpanElement;
  userListEl = document.getElementById('userList') as HTMLSelectElement;
  pianoCanvas = document.getElementById('piano') as HTMLCanvasElement;
  visCanvas = document.getElementById('visualizer') as HTMLCanvasElement;
  strengthBar = document.getElementById('strengthBar') as HTMLDivElement;
  strengthLabel = document.getElementById('strengthLabel') as HTMLSpanElement;

  pianoCtx = pianoCanvas.getContext('2d')!;
  visCtx = visCanvas.getContext('2d')!;

  // Populate scale dropdown
  for (const [val, name] of Object.entries(SCALE_NAMES)) {
    const opt = document.createElement('option');
    opt.value = val;
    opt.textContent = name;
    if (parseInt(val) === DEFAULT_CONFIG.preferredScale) opt.selected = true;
    scaleSelect.appendChild(opt);
  }

  lengthSlider.addEventListener('input', () => {
    lengthLabel.textContent = lengthSlider.value;
  });

  passphraseInput.addEventListener('input', updateStrengthMeter);

  enrollBtn.addEventListener('click', doEnroll);
  authBtn.addEventListener('click', doAuthenticate);
  playBtn.addEventListener('click', playCurrentSong);
  exportBtn.addEventListener('click', doExport);
  importBtn.addEventListener('click', doImport);
  deleteBtn.addEventListener('click', doDelete);
  userListEl.addEventListener('change', onUserSelect);

  refreshUserList();
  animate();
}
