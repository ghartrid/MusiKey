import {
  MusikeyConfig, MusikeyScale, MusikeyCredential, MusikeySong,
  MusikeyAnalysis, MusikeyError, DEFAULT_CONFIG, SCALE_NAMES, AuthLevel
} from '../core/types';
import { generateSong } from '../core/song';
import { scramble, descramble, reencrypt } from '../core/crypto';
import { analyze } from '../core/analysis';
import { calculateEntropy } from '../core/entropy';
import { MusikeyPlayer } from '../audio/player';
import { highlightNote, updatePiano, renderPiano, resetPiano } from './piano';
import { triggerNote, updateVisualizer, renderVisualizer, pulseSuccess, shakeFailure, randomize, resetVisualizer } from './visualizer';
import { computeSongFingerprint, renderFingerprint } from './fingerprint';
import { generateChallenge, verifyChallenge, MusicChallenge } from '../core/challenge';
import { generateTOTP, verifyTOTP, getTimeRemaining, TOTP_PERIOD } from '../core/totp';
import { createCommitment, verifyCommitment } from '../core/zkp';
import { createSyncBundle, importSyncBundle } from '../core/sync';
import { register as webauthnRegister, authenticate as webauthnAuthenticate, verifyAssertion, generateChallenge as webauthnChallenge, reencryptPrivateKey } from '../core/fido2';
import { createAuditEntry, appendAuditEntry, getAuditSummary, verifyAuditChain } from '../core/audit';
import type { MusikeyWebAuthnCredential, AuditLogEntry } from '../core/webauthn-types';
import { registerWithService, signProtocolChallenge, verifyProtocolAssertion, generateProtocolChallenge, parseProtocolUri } from '../core/protokey';
import type { ServiceRegistration, ProtocolChallenge } from '../core/protokey-types';

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
      writeFile: (filePath: string, data: string) => Promise<boolean>;
      cascadedKDF: (passphrase: string, saltB64: string, iterations: number) => Promise<string>;
      legacyCascadedKDF: (passphrase: string, saltB64: string, iterations: number) => Promise<string>;
      listByRpId: (rpId: string) => Promise<MusikeyCredential[]>;
      getServices: (userId: string) => Promise<any[]>;
      saveService: (userId: string, service: any) => Promise<boolean>;
      removeService: (userId: string, serviceId: string) => Promise<boolean>;
      onProtocolChallenge: (callback: (data: any) => void) => void;
      onProtocolRegister: (callback: (data: any) => void) => void;
      sendProtocolChallengeResponse: (data: any) => void;
      sendProtocolRegisterResponse: (data: any) => void;
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
let fingerprintCanvas: HTMLCanvasElement;
let fingerprintCtx: CanvasRenderingContext2D;
let fingerprintSection: HTMLElement;
let fingerprintLabel: HTMLSpanElement;
let authLevelSelect: HTMLSelectElement;
let mfaSection: HTMLElement;
let mfaChallengeCheck: HTMLInputElement;
let mfaTotpCheck: HTMLInputElement;
let totpDisplay: HTMLElement;
let totpCodeEl: HTMLSpanElement;
let totpTimerBar: HTMLDivElement;
let totpCountdown: HTMLSpanElement;
let authOverlay: HTMLElement;
let authOverlayUser: HTMLElement;
let authOverlayDismiss: HTMLButtonElement;
let authOverlayFpCanvas: HTMLCanvasElement;
let challengeDialog: HTMLElement;
let challengeQuestion: HTMLElement;
let challengeOptions: HTMLElement;
let totpDialog: HTMLElement;
let totpInput: HTMLInputElement;
let totpSubmit: HTMLButtonElement;
let fingerprintDialog: HTMLElement;
let fpDialogCanvas: HTMLCanvasElement;
let fpConfirm: HTMLButtonElement;
let fpDeny: HTMLButtonElement;
let syncExportBtn: HTMLButtonElement;
let auditBtn: HTMLButtonElement;
let syncImportBtn: HTMLButtonElement;
let syncDialog: HTMLElement;
let syncDialogTitle: HTMLElement;
let syncDialogMsg: HTMLElement;
let syncPassphraseInput: HTMLInputElement;
let syncSubmitBtn: HTMLButtonElement;
let totpInterval: ReturnType<typeof setInterval> | null = null;
let lastSongHash: string | null = null; // base64 hash for TOTP
// Services UI
let servicesSection: HTMLElement;
let serviceList: HTMLElement;
let serviceBadge: HTMLElement;
let addServiceBtn: HTMLButtonElement;
let manualChallengeBtn: HTMLButtonElement;
let serviceRegDialog: HTMLElement;
let serviceChallengeDialog: HTMLElement;
let pendingProtocolRequestId: string | null = null;

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

// Compute and display song fingerprint
async function showFingerprint(song: MusikeySong, canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D): Promise<void> {
  // Serialize events to get song data for hashing
  const buffer = new ArrayBuffer(song.eventCount * 6);
  const view = new DataView(buffer);
  for (let i = 0; i < song.eventCount; i++) {
    const offset = i * 6;
    view.setUint8(offset, song.events[i].note);
    view.setUint8(offset + 1, song.events[i].velocity);
    view.setUint16(offset + 2, song.events[i].duration, true);
    view.setUint16(offset + 4, song.events[i].timestamp, true);
  }
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  lastSongHash = btoa(String.fromCharCode(...new Uint8Array(hash)));
  const grid = await computeSongFingerprint(hash);
  renderFingerprint(ctx, grid, canvas.width, canvas.height);
  fingerprintSection.style.display = '';
  // Show first 8 hex chars as label
  const hexLabel = Array.from(new Uint8Array(hash).slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('');
  fingerprintLabel.textContent = hexLabel;
}

// Auth success overlay
function showAuthOverlay(username: string, song: MusikeySong): void {
  authOverlayUser.textContent = username;
  authOverlay.style.display = '';

  // Show fingerprint in overlay
  const fpCtx = authOverlayFpCanvas.getContext('2d');
  if (fpCtx) {
    showFingerprint(song, authOverlayFpCanvas, fpCtx);
  }

  // Disable dismiss for 3 seconds
  authOverlayDismiss.disabled = true;
  setTimeout(() => {
    authOverlayDismiss.disabled = false;
  }, 3000);
}

function hideAuthOverlay(): void {
  authOverlay.style.display = 'none';
}

// Challenge-response MFA
function showChallengeDialog(challenge: MusicChallenge): Promise<boolean> {
  return new Promise((resolve) => {
    challengeQuestion.textContent = challenge.question;
    challengeOptions.innerHTML = '';
    for (const opt of challenge.options) {
      const btn = document.createElement('button');
      btn.className = 'challenge-option-btn';
      btn.textContent = opt;
      btn.addEventListener('click', () => {
        challengeDialog.style.display = 'none';
        resolve(verifyChallenge(challenge, opt));
      });
      challengeOptions.appendChild(btn);
    }
    challengeDialog.style.display = '';
  });
}

// TOTP input dialog
function showTotpDialog(): Promise<boolean> {
  return new Promise((resolve) => {
    totpInput.value = '';
    totpDialog.style.display = '';
    totpInput.focus();

    const handler = async () => {
      const code = totpInput.value.trim();
      if (code.length !== 6) return;
      totpSubmit.removeEventListener('click', handler);
      totpDialog.style.display = 'none';
      if (!lastSongHash) { resolve(false); return; }
      const ok = await verifyTOTP(lastSongHash, code);
      resolve(ok);
    };
    totpSubmit.addEventListener('click', handler);
  });
}

// Fingerprint confirmation dialog
function showFingerprintConfirmDialog(song: MusikeySong): Promise<boolean> {
  return new Promise(async (resolve) => {
    const ctx = fpDialogCanvas.getContext('2d');
    if (ctx) {
      await showFingerprint(song, fpDialogCanvas, ctx);
    }
    fingerprintDialog.style.display = '';

    const onConfirm = () => {
      fingerprintDialog.style.display = 'none';
      fpConfirm.removeEventListener('click', onConfirm);
      fpDeny.removeEventListener('click', onDeny);
      resolve(true);
    };
    const onDeny = () => {
      fingerprintDialog.style.display = 'none';
      fpConfirm.removeEventListener('click', onConfirm);
      fpDeny.removeEventListener('click', onDeny);
      resolve(false);
    };
    fpConfirm.addEventListener('click', onConfirm);
    fpDeny.addEventListener('click', onDeny);
  });
}

// Sync passphrase dialog
function showSyncDialog(title: string, message: string): Promise<string | null> {
  return new Promise((resolve) => {
    syncDialogTitle.textContent = title;
    syncDialogMsg.textContent = message;
    syncPassphraseInput.value = '';
    syncDialog.style.display = '';
    syncPassphraseInput.focus();

    const handler = () => {
      const val = syncPassphraseInput.value.trim();
      syncSubmitBtn.removeEventListener('click', handler);
      syncDialog.style.display = 'none';
      resolve(val || null);
    };
    syncSubmitBtn.addEventListener('click', handler);
  });
}

// Get current auth level from dropdown
function getAuthLevel(): AuthLevel {
  return parseInt(authLevelSelect.value) as AuthLevel;
}

// Start TOTP rolling display
function startTotpDisplay(): void {
  if (totpInterval) clearInterval(totpInterval);
  if (!lastSongHash) return;

  totpDisplay.style.display = '';
  const update = async () => {
    if (!lastSongHash) return;
    const code = await generateTOTP(lastSongHash);
    totpCodeEl.textContent = code;
    const remaining = getTimeRemaining();
    totpCountdown.textContent = `${remaining}s`;
    totpTimerBar.style.width = `${(remaining / TOTP_PERIOD) * 100}%`;
  };
  update();
  totpInterval = setInterval(update, 1000);
}

function stopTotpDisplay(): void {
  if (totpInterval) { clearInterval(totpInterval); totpInterval = null; }
  totpDisplay.style.display = 'none';
}

// Run MFA checks after basic auth succeeds
async function runMfaChecks(credential: MusikeyCredential, song: MusikeySong): Promise<boolean> {
  const mfa = credential.mfa;
  if (!mfa) return true;

  // Challenge-response
  if (mfa.challengeResponse) {
    const challenge = generateChallenge(song);
    if (challenge) {
      // Play fragment
      const fragSong: MusikeySong = {
        events: challenge.fragment,
        eventCount: challenge.fragment.length,
        totalDuration: 0,
        scale: song.scale,
        rootNote: song.rootNote,
        tempo: song.tempo,
        entropyBits: 0,
      };
      const fragPlayer = new MusikeyPlayer();
      fragPlayer.play(fragSong);
      const ok = await showChallengeDialog(challenge);
      fragPlayer.stop();
      if (!ok) {
        setStatus('Challenge-response failed', '#ff6b6b');
        return false;
      }
    }
  }

  // TOTP
  if (mfa.totp) {
    // Compute song hash for TOTP
    await showFingerprint(song, fingerprintCanvas, fingerprintCtx);
    const ok = await showTotpDialog();
    if (!ok) {
      setStatus('TOTP verification failed', '#ff6b6b');
      return false;
    }
  }

  return true;
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

  setStatus('PBKDF2 → Argon2id → double AES-256-GCM...', '#e94560');
  await new Promise(r => setTimeout(r, 100));

  const { scrambled, error } = await scramble(song, passphrase, config.scrambleIterations);
  if (error !== MusikeyError.OK) {
    setStatus('Encryption failed', '#ff6b6b');
    shakeFailure();
    state = 'failure';
    setButtonsEnabled(true);
    return;
  }

  // Build MFA config from checkboxes
  const mfaConfig: any = {};
  if (mfaChallengeCheck.checked) mfaConfig.challengeResponse = true;
  if (mfaTotpCheck.checked) mfaConfig.totp = true;
  const hasMfa = Object.keys(mfaConfig).length > 0;

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
    version: 3,
    integrityHash: '',
    keyVersion: 1,
    authLevel: getAuthLevel(),
    mfa: hasMfa ? mfaConfig : undefined,
  };

  // ZKP commitment
  const songBuf = new ArrayBuffer(song.eventCount * 6);
  const songView = new DataView(songBuf);
  for (let i = 0; i < song.eventCount; i++) {
    const off = i * 6;
    songView.setUint8(off, song.events[i].note);
    songView.setUint8(off + 1, song.events[i].velocity);
    songView.setUint16(off + 2, song.events[i].duration, true);
    songView.setUint16(off + 4, song.events[i].timestamp, true);
  }
  const songHashBuf = await crypto.subtle.digest('SHA-256', songBuf);
  credential.zkpCommitment = await createCommitment(songHashBuf);

  // WebAuthn registration: generate ECDSA P-256 key pair
  setStatus('Generating ECDSA P-256 key pair...', '#e94560');
  try {
    const challenge = webauthnChallenge();
    const { webauthnCredential } = await webauthnRegister(
      {
        rp: { id: 'musikey.local', name: 'MusiKey' },
        user: { id: username, name: username, displayName: username },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        attestation: 'direct',
      },
      passphrase,
      config.scrambleIterations
    );
    credential.webauthn = webauthnCredential;
    credential.mfa = { ...credential.mfa, webauthnSignature: true };
  } catch {
    // WebAuthn registration failed — continue without it
  }

  // Audit log: registration event
  const auditEntry = await createAuditEntry(
    'registration',
    credential.webauthn?.rpId || 'musikey.local',
    credential.webauthn?.credentialId || username,
    username,
    0,
    'Initial enrollment'
  );
  appendAuditEntry(credential, auditEntry);

  credential.integrityHash = await computeIntegrityHash(credential);

  await window.musikeyStore.saveCredential(credential);
  await refreshUserList();

  lastSong = song;
  setAnalysis(a);
  entropyEl.textContent = String(song.entropyBits);
  attemptsEl.textContent = '0 / ' + config.maxFailedAttempts;

  // Show fingerprint
  await showFingerprint(song, fingerprintCanvas, fingerprintCtx);

  // Start TOTP display if enabled
  if (mfaTotpCheck.checked && lastSongHash) {
    startTotpDisplay();
    mfaSection.style.display = '';
  }

  setStatus(`Enrolled "${username}" — PBKDF2+Argon2id cascaded + double AES-GCM`, '#4ecca3');
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

  // Progressive auth: Level 1 (BASIC) skips musicality check
  const authLevel = credential.authLevel || AuthLevel.STANDARD;
  const a = analyze(song, config.musicalityThreshold);
  if (authLevel >= AuthLevel.STANDARD && !a.isValidMusic) {
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

  // Success — key rotation: re-encrypt with fresh salt + Argon2id
  credential.failedAttempts = 0;
  credential.lastAuthTimestamp = Date.now();

  const needsMigration = !credential.scrambledSong.kdfType || credential.scrambledSong.kdfType === 'pbkdf2-scrypt';
  if (needsMigration || true) { // Always rotate keys for forward secrecy
    const { scrambled: rotated, error: reErr } = await reencrypt(song, passphrase, config.scrambleIterations);
    if (reErr === MusikeyError.OK) {
      credential.scrambledSong = rotated;
      credential.keyVersion = (credential.keyVersion || 0) + 1;
      if (needsMigration) {
        credential.version = 3;
      }
      credential.integrityHash = await computeIntegrityHash(credential);
    }
  }

  lastSong = song;
  setAnalysis(a);
  entropyEl.textContent = String(song.entropyBits);
  attemptsEl.textContent = `0 / ${config.maxFailedAttempts}`;

  // Show fingerprint
  await showFingerprint(song, fingerprintCanvas, fingerprintCtx);

  // Progressive auth: Level 3 (HIGH) requires fingerprint visual confirmation
  if (authLevel >= AuthLevel.HIGH) {
    const fpOk = await showFingerprintConfirmDialog(song);
    if (!fpOk) {
      setStatus('Fingerprint confirmation rejected', '#ff6b6b');
      shakeFailure();
      state = 'failure';
      setButtonsEnabled(true);
      passphraseInput.value = '';
      updateStrengthMeter();
      return;
    }
  }

  // MFA checks (challenge-response, TOTP)
  const mfaOk = await runMfaChecks(credential, song);
  if (!mfaOk) {
    shakeFailure();
    state = 'failure';
    setButtonsEnabled(true);
    passphraseInput.value = '';
    updateStrengthMeter();
    return;
  }

  // ZKP verification
  if (credential.zkpCommitment) {
    const songBuf = new ArrayBuffer(song.eventCount * 6);
    const sv = new DataView(songBuf);
    for (let i = 0; i < song.eventCount; i++) {
      const off = i * 6;
      sv.setUint8(off, song.events[i].note);
      sv.setUint8(off + 1, song.events[i].velocity);
      sv.setUint16(off + 2, song.events[i].duration, true);
      sv.setUint16(off + 4, song.events[i].timestamp, true);
    }
    const hashBuf = await crypto.subtle.digest('SHA-256', songBuf);
    const zkpOk = await verifyCommitment(hashBuf, credential.zkpCommitment);
    if (!zkpOk) {
      setStatus('ZKP commitment verification failed', '#ff6b6b');
      shakeFailure();
      state = 'failure';
      setButtonsEnabled(true);
      passphraseInput.value = '';
      updateStrengthMeter();
      return;
    }
  }

  // WebAuthn assertion: ECDSA signature verification
  let cloneWarning = false;
  if (credential.webauthn) {
    try {
      const challenge = webauthnChallenge();
      const { response: assertionResp, newSignCount } = await webauthnAuthenticate(
        { rpId: credential.webauthn.rpId, challenge },
        credential.webauthn,
        passphrase,
        config.scrambleIterations
      );

      const verifyResult = await verifyAssertion(
        assertionResp,
        credential.webauthn.publicKeyJwk,
        challenge,
        credential.webauthn.rpId,
        credential.webauthn.signCount
      );

      if (!verifyResult.verified) {
        setStatus('WebAuthn signature verification failed', '#ff6b6b');
        shakeFailure();
        state = 'failure';
        setButtonsEnabled(true);
        passphraseInput.value = '';
        updateStrengthMeter();
        // Audit: auth failure
        const failEntry = await createAuditEntry(
          'auth_failure', credential.webauthn.rpId, credential.webauthn.credentialId,
          username, credential.webauthn.signCount, 'ECDSA signature verification failed',
          credential.auditLog
        );
        appendAuditEntry(credential, failEntry);
        credential.integrityHash = await computeIntegrityHash(credential);
        await window.musikeyStore.saveCredential(credential);
        return;
      }

      cloneWarning = verifyResult.cloneWarning;
      credential.webauthn.signCount = verifyResult.newSignCount;

      // Re-encrypt private key with fresh salt (forward secrecy)
      try {
        credential.webauthn = await reencryptPrivateKey(
          credential.webauthn, passphrase, config.scrambleIterations
        );
      } catch {
        // Private key re-encryption failed — keep existing encryption
      }

      if (cloneWarning) {
        const cloneEntry = await createAuditEntry(
          'counter_mismatch', credential.webauthn.rpId, credential.webauthn.credentialId,
          username, verifyResult.newSignCount, 'Possible credential clone detected',
          credential.auditLog
        );
        appendAuditEntry(credential, cloneEntry);
      }
    } catch {
      // WebAuthn assertion failed — treat as auth failure
      setStatus('WebAuthn assertion failed', '#ff6b6b');
      shakeFailure();
      state = 'failure';
      setButtonsEnabled(true);
      passphraseInput.value = '';
      updateStrengthMeter();
      return;
    }
  }

  // Audit log: successful authentication
  const authEntry = await createAuditEntry(
    'authentication',
    credential.webauthn?.rpId || 'musikey.local',
    credential.webauthn?.credentialId || username,
    username,
    credential.webauthn?.signCount,
    `Key rotation v${credential.keyVersion}`,
    credential.auditLog
  );
  appendAuditEntry(credential, authEntry);

  // Key rotation audit entry
  const rotateEntry = await createAuditEntry(
    'key_rotation',
    credential.webauthn?.rpId || 'musikey.local',
    credential.webauthn?.credentialId || username,
    username,
    credential.webauthn?.signCount,
    `Rotated to keyVersion ${credential.keyVersion}`,
    credential.auditLog
  );
  appendAuditEntry(credential, rotateEntry);

  credential.integrityHash = await computeIntegrityHash(credential);
  await window.musikeyStore.saveCredential(credential);

  const migrated = needsMigration ? ' (migrated to Argon2id)' : '';
  const cloneMsg = cloneWarning ? ' [CLONE WARNING]' : '';
  setStatus(`Authenticated "${username}" successfully!${migrated}${cloneMsg}`, cloneWarning ? '#ff6b6b' : '#4ecca3');
  pulseSuccess();
  state = 'success';
  setButtonsEnabled(true);

  passphraseInput.value = '';
  updateStrengthMeter();
  scheduleSongClear();

  // Show auth overlay with song playback
  showAuthOverlay(username, song);
  playCurrentSong();

  // Show TOTP display if enabled
  if (credential.mfa?.totp && lastSongHash) {
    mfaSection.style.display = '';
    startTotpDisplay();
  }
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

async function showAuditDialog(): Promise<void> {
  const username = usernameInput.value.trim() || userListEl.value;
  if (!username) {
    setStatus('Select a user to view audit log', '#ff6b6b');
    return;
  }
  const credential = await window.musikeyStore.getCredential(username);
  if (!credential || !credential.auditLog || credential.auditLog.length === 0) {
    setStatus('No audit log for this user', '#ff6b6b');
    return;
  }

  const summary = await getAuditSummary(credential.auditLog);
  const entries = credential.auditLog.slice(-20).reverse();

  const dialog = document.getElementById('auditDialog') as HTMLElement;
  const content = document.getElementById('auditContent') as HTMLElement;

  let html = `<div style="font-size:11px;color:#888;margin-bottom:8px;">
    Chain: <span style="color:${summary.chainValid ? '#4ecca3' : '#ff6b6b'}">${summary.chainValid ? 'VALID' : 'BROKEN'}</span> |
    Auths: ${summary.totalAuths} | Failures: ${summary.totalFailures} |
    Sign count: ${credential.webauthn?.signCount ?? 'N/A'} |
    Clone warnings: ${summary.cloneWarnings}
  </div>`;

  for (const entry of entries) {
    const date = new Date(entry.timestamp).toLocaleString();
    const color = entry.action === 'authentication' ? '#4ecca3' :
                  entry.action === 'auth_failure' ? '#ff6b6b' :
                  entry.action === 'counter_mismatch' ? '#ff6b6b' :
                  entry.action === 'registration' ? '#e94560' : '#888';
    html += `<div style="margin-bottom:4px;font-size:11px;">
      <span style="color:${color};font-weight:600;">${entry.action}</span>
      <span style="color:#666;margin-left:6px;">${date}</span>
      ${entry.signCount !== undefined ? `<span style="color:#666;margin-left:6px;">sig#${entry.signCount}</span>` : ''}
      ${entry.detail ? `<div style="color:#555;font-size:10px;margin-left:8px;">${entry.detail}</div>` : ''}
    </div>`;
  }

  content.innerHTML = html;
  dialog.style.display = 'flex';

  return new Promise(resolve => {
    const closeBtn = document.getElementById('auditClose') as HTMLButtonElement;
    const handler = () => {
      dialog.style.display = 'none';
      closeBtn.removeEventListener('click', handler);
      resolve();
    };
    closeBtn.addEventListener('click', handler);
  });
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
  await window.musikeyStore.writeFile(filePath, json);
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

async function doSyncExport(): Promise<void> {
  const users = await window.musikeyStore.listUsers();
  if (users.length === 0) {
    setStatus('No credentials to export', '#ff6b6b');
    return;
  }

  const passphrase = await showSyncDialog('Sync Export', 'Enter a passphrase to encrypt the sync bundle:');
  if (!passphrase) return;

  setStatus('Creating encrypted sync bundle...', '#e94560');
  const credentials: any[] = [];
  for (const u of users) {
    const cred = await window.musikeyStore.exportCredential(u);
    if (cred) credentials.push(JSON.parse(cred));
  }

  const bundle = await createSyncBundle(credentials, passphrase);
  const filePath = await window.musikeyStore.showSaveDialog('musikey-sync.json');
  if (!filePath) return;

  await window.musikeyStore.writeFile(filePath, bundle);
  setStatus(`Sync bundle exported (${credentials.length} credentials)`, '#4ecca3');
}

async function doSyncImport(): Promise<void> {
  const json = await window.musikeyStore.showOpenDialog();
  if (!json) return;

  const passphrase = await showSyncDialog('Sync Import', 'Enter the sync bundle passphrase:');
  if (!passphrase) return;

  setStatus('Decrypting sync bundle...', '#e94560');
  const { credentials, error } = await importSyncBundle(json, passphrase);
  if (error || !credentials) {
    setStatus(error || 'Import failed', '#ff6b6b');
    return;
  }

  let imported = 0;
  for (const cred of credentials) {
    const ok = await window.musikeyStore.importCredential(JSON.stringify(cred));
    if (ok) imported++;
  }

  await refreshUserList();
  setStatus(`Sync import: ${imported}/${credentials.length} credentials restored`, '#4ecca3');
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
  syncExportBtn.disabled = !enabled;
  syncImportBtn.disabled = !enabled;
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
    loadServices(userId);
  } else {
    renderServiceList([]);
  }
}

// --- Services Management ---

async function loadServices(userId: string): Promise<void> {
  if (!userId) {
    servicesSection.style.display = 'none';
    return;
  }
  const services = await window.musikeyStore.getServices(userId);
  renderServiceList(services);
  servicesSection.style.display = '';
}

function renderServiceList(services: any[]): void {
  serviceList.innerHTML = '';
  serviceBadge.textContent = String(services.length);

  if (services.length === 0) {
    serviceList.innerHTML = '<div style="color:#666;font-size:12px;padding:4px;">No services registered</div>';
    return;
  }

  for (const svc of services) {
    const card = document.createElement('div');
    card.className = 'service-card';

    const info = document.createElement('div');
    info.className = 'service-card-info';

    const name = document.createElement('div');
    name.className = 'service-card-name';
    name.textContent = svc.serviceName;

    const rpid = document.createElement('div');
    rpid.className = 'service-card-rpid';
    rpid.textContent = svc.rpId;

    const stats = document.createElement('div');
    stats.className = 'service-card-stats';
    const lastAuth = svc.lastAuthAt ? new Date(svc.lastAuthAt).toLocaleDateString() : 'Never';
    stats.textContent = `Signs: ${svc.signCount} | Last: ${lastAuth}`;

    info.appendChild(name);
    info.appendChild(rpid);
    info.appendChild(stats);

    const actions = document.createElement('div');
    actions.className = 'service-card-actions';

    const testBtn = document.createElement('button');
    testBtn.className = 'service-card-test';
    testBtn.textContent = 'Test';
    testBtn.addEventListener('click', () => doTestServiceAuth(svc));

    const removeBtn = document.createElement('button');
    removeBtn.className = 'service-card-remove';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', () => doRemoveService(svc.serviceId, svc.serviceName));

    actions.appendChild(testBtn);
    actions.appendChild(removeBtn);

    card.appendChild(info);
    card.appendChild(actions);
    serviceList.appendChild(card);
  }
}

async function doTestServiceAuth(service: any): Promise<void> {
  const userId = usernameInput.value.trim() || userListEl.value;
  const passphrase = passphraseInput.value;

  if (!userId || !passphrase) {
    statusEl.textContent = 'Enter passphrase to test authentication';
    return;
  }

  statusEl.textContent = `Testing ${service.serviceName}...`;

  try {
    const startTime = performance.now();

    // 1. Generate challenge locally (simulates what a server would do)
    const challenge = generateProtocolChallenge(service.rpId);

    // 2. Sign the challenge (decrypts private key, signs payload)
    const { assertion, newSignCount } = await signProtocolChallenge(
      challenge, service, passphrase, config.scrambleIterations
    );

    // 3. Verify the signed assertion against the stored public key (simulates server verification)
    const result = await verifyProtocolAssertion(
      assertion,
      service.publicKeyJwk,
      challenge.challenge,
      service.rpId,
      service.signCount,
      challenge.nonce,
      challenge.timestamp
    );

    const elapsed = Math.round(performance.now() - startTime);

    // Update service signCount and lastAuthAt
    service.signCount = newSignCount;
    service.lastAuthAt = Date.now();
    await window.musikeyStore.saveService(userId, service);

    // Audit log
    const credential = await window.musikeyStore.getCredential(userId);
    if (credential) {
      const entry = await createAuditEntry('service_auth', service.rpId, service.credentialId, userId, newSignCount, `Test auth: ${service.serviceName} — ${result.verified ? 'PASS' : 'FAIL'}`, credential.auditLog);
      appendAuditEntry(credential, entry);
      credential.integrityHash = await computeIntegrityHash(credential);
      await window.musikeyStore.saveCredential(credential);
    }

    // Show result in challenge dialog
    serviceChallengeDialog.style.display = 'flex';
    const manualUri = document.getElementById('manualChallengeUri') as HTMLTextAreaElement;
    const details = document.getElementById('challengeDetails') as HTMLElement;
    const responseOutput = document.getElementById('challengeResponseOutput') as HTMLElement;
    const approveBtn = document.getElementById('challengeApproveBtn') as HTMLButtonElement;
    const denyBtn = document.getElementById('challengeDenyBtn') as HTMLButtonElement;
    const msg = document.getElementById('challengeApprovalMsg') as HTMLElement;

    manualUri.style.display = 'none';
    approveBtn.style.display = 'none';
    msg.textContent = result.verified ? 'Self-Test Passed' : 'Self-Test Failed';

    details.innerHTML = '';
    const lines: [string, string][] = [
      ['Service', service.serviceName],
      ['Domain', service.rpId],
      ['Signature', result.verified ? 'Valid ECDSA P-256' : (result.error || 'Invalid')],
      ['Sign Count', String(newSignCount)],
      ['Clone Check', result.cloneWarning ? 'WARNING' : 'OK'],
      ['Round-trip', `${elapsed}ms`],
    ];
    for (const [label, value] of lines) {
      const row = document.createElement('div');
      row.innerHTML = `<span class="detail-label">${label}:</span> ${value}`;
      details.appendChild(row);
    }

    // Show the full assertion JSON
    responseOutput.style.display = '';
    const responseText = document.getElementById('challengeResponseText') as HTMLTextAreaElement;
    responseText.value = JSON.stringify({ challenge, assertion, verification: result }, null, 2);

    denyBtn.textContent = 'Close';
    denyBtn.onclick = () => {
      serviceChallengeDialog.style.display = 'none';
      approveBtn.style.display = '';
      denyBtn.textContent = 'Deny';
    };

    statusEl.textContent = result.verified
      ? `Test PASSED — ${service.serviceName} (${elapsed}ms)`
      : `Test FAILED — ${result.error}`;

    await loadServices(userId);
  } catch (err: any) {
    statusEl.textContent = `Test failed: ${err.message}`;
  }
}

async function doRemoveService(serviceId: string, serviceName: string): Promise<void> {
  const userId = usernameInput.value.trim() || userListEl.value;
  if (!userId) return;

  const ok = confirm(`Remove service "${serviceName}"? This deletes the keypair.`);
  if (!ok) return;

  await window.musikeyStore.removeService(userId, serviceId);

  // Audit log
  const credential = await window.musikeyStore.getCredential(userId);
  if (credential) {
    const entry = await createAuditEntry('service_remove', serviceName, serviceId, userId, undefined, `Removed service: ${serviceName}`, credential.auditLog);
    appendAuditEntry(credential, entry);
    credential.integrityHash = await computeIntegrityHash(credential);
    await window.musikeyStore.saveCredential(credential);
  }

  statusEl.textContent = `Service "${serviceName}" removed`;
  await loadServices(userId);
}

async function doAddService(): Promise<void> {
  serviceRegDialog.style.display = 'flex';

  // Clear fields
  (document.getElementById('serviceRegUri') as HTMLTextAreaElement).value = '';
  (document.getElementById('serviceRegName') as HTMLInputElement).value = '';
  (document.getElementById('serviceRegRpId') as HTMLInputElement).value = '';
  (document.getElementById('serviceRegUserId') as HTMLInputElement).value = '';
  (document.getElementById('serviceRegEndpoint') as HTMLInputElement).value = '';
}

async function submitServiceRegistration(): Promise<void> {
  const userId = usernameInput.value.trim() || userListEl.value;
  const passphrase = passphraseInput.value;

  if (!userId || !passphrase) {
    statusEl.textContent = 'Select user and enter passphrase to register a service';
    serviceRegDialog.style.display = 'none';
    return;
  }

  const uriInput = (document.getElementById('serviceRegUri') as HTMLTextAreaElement).value.trim();
  let rpId: string;
  let serviceName: string;
  let serviceUserId: string;
  let endpoint: string | undefined;

  if (uriInput) {
    // Parse URI or JSON
    const parsed = parseProtocolUri(uriInput);
    if (!parsed || parsed.type !== 'register') {
      statusEl.textContent = 'Invalid registration URI';
      return;
    }
    rpId = parsed.rpId;
    serviceName = parsed.serviceName || rpId;
    serviceUserId = parsed.userId || userId;
    endpoint = parsed.endpoint;
  } else {
    // Manual fields
    rpId = (document.getElementById('serviceRegRpId') as HTMLInputElement).value.trim();
    serviceName = (document.getElementById('serviceRegName') as HTMLInputElement).value.trim();
    serviceUserId = (document.getElementById('serviceRegUserId') as HTMLInputElement).value.trim() || userId;
    endpoint = (document.getElementById('serviceRegEndpoint') as HTMLInputElement).value.trim() || undefined;

    if (!rpId || !serviceName) {
      statusEl.textContent = 'Service name and domain are required';
      return;
    }
  }

  serviceRegDialog.style.display = 'none';
  statusEl.textContent = 'Registering with service...';

  try {
    const { registration, response } = await registerWithService(
      rpId, serviceName, serviceUserId, passphrase, config.scrambleIterations, endpoint
    );

    await window.musikeyStore.saveService(userId, registration);

    // Audit log
    const credential = await window.musikeyStore.getCredential(userId);
    if (credential) {
      const entry = await createAuditEntry('service_register', rpId, registration.credentialId, userId, 0, `Registered: ${serviceName}`, credential.auditLog);
      appendAuditEntry(credential, entry);
      credential.integrityHash = await computeIntegrityHash(credential);
      await window.musikeyStore.saveCredential(credential);
    }

    statusEl.textContent = `Registered with ${serviceName}`;
    await loadServices(userId);
  } catch (err: any) {
    statusEl.textContent = `Registration failed: ${err.message}`;
  }
}

async function showManualChallengeDialog(): Promise<void> {
  serviceChallengeDialog.style.display = 'flex';

  const manualUri = document.getElementById('manualChallengeUri') as HTMLTextAreaElement;
  const details = document.getElementById('challengeDetails') as HTMLElement;
  const responseOutput = document.getElementById('challengeResponseOutput') as HTMLElement;
  const approveBtn = document.getElementById('challengeApproveBtn') as HTMLButtonElement;
  const denyBtn = document.getElementById('challengeDenyBtn') as HTMLButtonElement;
  const msg = document.getElementById('challengeApprovalMsg') as HTMLElement;

  manualUri.style.display = '';
  manualUri.value = '';
  details.innerHTML = '<div style="color:#666;">Paste a challenge URI or JSON above</div>';
  responseOutput.style.display = 'none';
  msg.textContent = 'Paste a challenge to sign:';

  approveBtn.onclick = async () => {
    const input = manualUri.value.trim();
    if (!input) return;

    const parsed = parseProtocolUri(input);
    if (!parsed || parsed.type !== 'auth') {
      statusEl.textContent = 'Invalid challenge URI';
      return;
    }

    const challenge: ProtocolChallenge = {
      protocol: 'musikey-v1',
      type: 'challenge',
      rpId: parsed.rpId,
      challenge: parsed.challenge || '',
      nonce: parsed.nonce || '',
      timestamp: Math.floor(Date.now() / 1000),
      callback: parsed.callback,
    };

    await handleChallengeApproval(challenge, null);
  };

  denyBtn.onclick = () => {
    serviceChallengeDialog.style.display = 'none';
  };
}

async function handleChallengeApproval(challenge: ProtocolChallenge, requestId: string | null): Promise<void> {
  const userId = usernameInput.value.trim() || userListEl.value;
  const passphrase = passphraseInput.value;

  if (!userId || !passphrase) {
    statusEl.textContent = 'Enter passphrase to sign challenge';
    if (requestId) {
      window.musikeyStore.sendProtocolChallengeResponse({ requestId, error: 'No passphrase' });
    }
    return;
  }

  // Find matching service
  const services = await window.musikeyStore.getServices(userId);
  const service = services.find((s: any) => s.rpId === challenge.rpId);

  if (!service) {
    statusEl.textContent = `No service registered for ${challenge.rpId}`;
    if (requestId) {
      window.musikeyStore.sendProtocolChallengeResponse({ requestId, error: 'No matching service' });
    }
    return;
  }

  statusEl.textContent = 'Signing challenge...';

  try {
    const { assertion, newSignCount } = await signProtocolChallenge(
      challenge, service, passphrase, config.scrambleIterations
    );

    // Update service signCount and lastAuthAt
    service.signCount = newSignCount;
    service.lastAuthAt = Date.now();
    await window.musikeyStore.saveService(userId, service);

    // Audit log
    const credential = await window.musikeyStore.getCredential(userId);
    if (credential) {
      const entry = await createAuditEntry('service_auth', challenge.rpId, service.credentialId, userId, newSignCount, `Auth: ${service.serviceName}`, credential.auditLog);
      appendAuditEntry(credential, entry);
      credential.integrityHash = await computeIntegrityHash(credential);
      await window.musikeyStore.saveCredential(credential);
    }

    // Send response to protocol server
    if (requestId) {
      window.musikeyStore.sendProtocolChallengeResponse({ requestId, assertion });
    }

    // Show signed response in dialog
    const responseOutput = document.getElementById('challengeResponseOutput') as HTMLElement;
    const responseText = document.getElementById('challengeResponseText') as HTMLTextAreaElement;
    if (responseOutput && responseText) {
      responseOutput.style.display = '';
      responseText.value = JSON.stringify(assertion, null, 2);
    }

    statusEl.textContent = `Signed for ${service.serviceName} (count: ${newSignCount})`;
    await loadServices(userId);
  } catch (err: any) {
    statusEl.textContent = `Signing failed: ${err.message}`;
    if (requestId) {
      window.musikeyStore.sendProtocolChallengeResponse({ requestId, error: err.message });
    }
  }
}

function setupProtocolListeners(): void {
  // Listen for challenges from the local protocol server
  window.musikeyStore.onProtocolChallenge((data: any) => {
    const { requestId, challenge } = data;
    pendingProtocolRequestId = requestId;

    // Show challenge approval dialog
    serviceChallengeDialog.style.display = 'flex';
    const manualUri = document.getElementById('manualChallengeUri') as HTMLTextAreaElement;
    const details = document.getElementById('challengeDetails') as HTMLElement;
    const responseOutput = document.getElementById('challengeResponseOutput') as HTMLElement;
    const approveBtn = document.getElementById('challengeApproveBtn') as HTMLButtonElement;
    const denyBtn = document.getElementById('challengeDenyBtn') as HTMLButtonElement;
    const msg = document.getElementById('challengeApprovalMsg') as HTMLElement;

    manualUri.style.display = 'none';
    responseOutput.style.display = 'none';
    msg.textContent = `"${challenge.rpId}" requests authentication:`;

    details.innerHTML = '';
    const rpDiv = document.createElement('div');
    rpDiv.innerHTML = '<span class="detail-label">Service:</span> ' + challenge.rpId;
    const chalDiv = document.createElement('div');
    chalDiv.innerHTML = '<span class="detail-label">Challenge:</span> ' + (challenge.challenge || '').substring(0, 32) + '...';
    const timeDiv = document.createElement('div');
    timeDiv.innerHTML = '<span class="detail-label">Time:</span> ' + new Date(challenge.timestamp * 1000).toLocaleTimeString();
    details.appendChild(rpDiv);
    details.appendChild(chalDiv);
    details.appendChild(timeDiv);

    approveBtn.onclick = () => handleChallengeApproval(challenge, requestId);
    denyBtn.onclick = () => {
      serviceChallengeDialog.style.display = 'none';
      window.musikeyStore.sendProtocolChallengeResponse({ requestId, error: 'denied' });
    };
  });

  // Listen for registration requests from protocol server
  window.musikeyStore.onProtocolRegister((data: any) => {
    const { requestId, request } = data;

    // Pre-fill registration dialog
    serviceRegDialog.style.display = 'flex';
    (document.getElementById('serviceRegUri') as HTMLTextAreaElement).value = '';
    (document.getElementById('serviceRegName') as HTMLInputElement).value = request.serviceName || '';
    (document.getElementById('serviceRegRpId') as HTMLInputElement).value = request.rpId || '';
    (document.getElementById('serviceRegUserId') as HTMLInputElement).value = request.userId || '';
    (document.getElementById('serviceRegEndpoint') as HTMLInputElement).value = request.endpoint || '';

    // Override submit to include requestId response
    const origSubmit = (document.getElementById('serviceRegSubmit') as HTMLButtonElement).onclick;
    (document.getElementById('serviceRegSubmit') as HTMLButtonElement).onclick = async () => {
      await submitServiceRegistration();
      const userId = usernameInput.value.trim() || userListEl.value;
      const services = await window.musikeyStore.getServices(userId);
      const latest = services.find((s: any) => s.rpId === request.rpId);
      if (latest) {
        window.musikeyStore.sendProtocolRegisterResponse({
          requestId,
          registration: {
            protocol: 'musikey-v1',
            type: 'registration',
            rpId: latest.rpId,
            userId: latest.userId,
            publicKeyJwk: latest.publicKeyJwk,
            credentialId: latest.credentialId,
          },
        });
      } else {
        window.musikeyStore.sendProtocolRegisterResponse({ requestId, error: 'Registration failed' });
      }
    };

    (document.getElementById('serviceRegCancel') as HTMLButtonElement).onclick = () => {
      serviceRegDialog.style.display = 'none';
      window.musikeyStore.sendProtocolRegisterResponse({ requestId, error: 'denied' });
    };
  });
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

  // New v2 elements
  fingerprintCanvas = document.getElementById('fingerprint') as HTMLCanvasElement;
  fingerprintSection = document.getElementById('fingerprintSection') as HTMLElement;
  fingerprintLabel = document.getElementById('fingerprintLabel') as HTMLSpanElement;
  authLevelSelect = document.getElementById('authLevel') as HTMLSelectElement;
  mfaSection = document.getElementById('mfaSection') as HTMLElement;
  mfaChallengeCheck = document.getElementById('mfaChallengeResponse') as HTMLInputElement;
  mfaTotpCheck = document.getElementById('mfaTotp') as HTMLInputElement;
  totpDisplay = document.getElementById('totpDisplay') as HTMLElement;
  totpCodeEl = document.getElementById('totpCode') as HTMLSpanElement;
  totpTimerBar = document.getElementById('totpTimerBar') as HTMLDivElement;
  totpCountdown = document.getElementById('totpCountdown') as HTMLSpanElement;
  authOverlay = document.getElementById('authOverlay') as HTMLElement;
  authOverlayUser = document.getElementById('authOverlayUser') as HTMLElement;
  authOverlayDismiss = document.getElementById('authOverlayDismiss') as HTMLButtonElement;
  authOverlayFpCanvas = document.getElementById('authOverlayFingerprint') as HTMLCanvasElement;
  challengeDialog = document.getElementById('challengeDialog') as HTMLElement;
  challengeQuestion = document.getElementById('challengeQuestion') as HTMLElement;
  challengeOptions = document.getElementById('challengeOptions') as HTMLElement;
  totpDialog = document.getElementById('totpDialog') as HTMLElement;
  totpInput = document.getElementById('totpInput') as HTMLInputElement;
  totpSubmit = document.getElementById('totpSubmit') as HTMLButtonElement;
  fingerprintDialog = document.getElementById('fingerprintDialog') as HTMLElement;
  fpDialogCanvas = document.getElementById('fingerprintDialogCanvas') as HTMLCanvasElement;
  fpConfirm = document.getElementById('fpConfirm') as HTMLButtonElement;
  fpDeny = document.getElementById('fpDeny') as HTMLButtonElement;
  syncExportBtn = document.getElementById('syncExportBtn') as HTMLButtonElement;
  syncImportBtn = document.getElementById('syncImportBtn') as HTMLButtonElement;
  auditBtn = document.getElementById('auditBtn') as HTMLButtonElement;
  syncDialog = document.getElementById('syncDialog') as HTMLElement;
  syncDialogTitle = document.getElementById('syncDialogTitle') as HTMLElement;
  syncDialogMsg = document.getElementById('syncDialogMsg') as HTMLElement;
  syncPassphraseInput = document.getElementById('syncPassphrase') as HTMLInputElement;
  syncSubmitBtn = document.getElementById('syncSubmit') as HTMLButtonElement;

  // Services UI elements
  servicesSection = document.getElementById('servicesSection') as HTMLElement;
  serviceList = document.getElementById('serviceList') as HTMLElement;
  serviceBadge = document.getElementById('serviceBadge') as HTMLElement;
  addServiceBtn = document.getElementById('addServiceBtn') as HTMLButtonElement;
  manualChallengeBtn = document.getElementById('manualChallengeBtn') as HTMLButtonElement;
  serviceRegDialog = document.getElementById('serviceRegDialog') as HTMLElement;
  serviceChallengeDialog = document.getElementById('serviceChallengeDialog') as HTMLElement;

  pianoCtx = pianoCanvas.getContext('2d')!;
  visCtx = visCanvas.getContext('2d')!;
  fingerprintCtx = fingerprintCanvas.getContext('2d')!;

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
  syncExportBtn.addEventListener('click', doSyncExport);
  syncImportBtn.addEventListener('click', doSyncImport);
  auditBtn.addEventListener('click', showAuditDialog);
  userListEl.addEventListener('change', onUserSelect);
  authOverlayDismiss.addEventListener('click', hideAuthOverlay);

  // MFA toggle — show/hide TOTP display and MFA section
  mfaChallengeCheck.addEventListener('change', () => {
    mfaSection.style.display = (mfaChallengeCheck.checked || mfaTotpCheck.checked) ? '' : '';
  });
  mfaTotpCheck.addEventListener('change', () => {
    if (mfaTotpCheck.checked && lastSongHash) {
      startTotpDisplay();
    } else {
      stopTotpDisplay();
    }
  });

  // Show MFA section always (for enrollment config)
  mfaSection.style.display = '';

  // Services event listeners
  addServiceBtn.addEventListener('click', doAddService);
  manualChallengeBtn.addEventListener('click', showManualChallengeDialog);
  (document.getElementById('serviceRegSubmit') as HTMLButtonElement).addEventListener('click', submitServiceRegistration);
  (document.getElementById('serviceRegCancel') as HTMLButtonElement).addEventListener('click', () => {
    serviceRegDialog.style.display = 'none';
  });
  (document.getElementById('challengeResponseCopy') as HTMLButtonElement).addEventListener('click', () => {
    const text = (document.getElementById('challengeResponseText') as HTMLTextAreaElement).value;
    navigator.clipboard.writeText(text);
    statusEl.textContent = 'Response copied to clipboard';
  });
  (document.getElementById('challengeResponseClose') as HTMLButtonElement).addEventListener('click', () => {
    serviceChallengeDialog.style.display = 'none';
  });

  // Protocol server event listeners
  setupProtocolListeners();

  refreshUserList();
  animate();
}
