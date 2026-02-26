/**
 * MusiKey WASM-compatible module
 *
 * Self-contained MusiKey implementation using Web Crypto API.
 * Works in browsers (via <script> or ESM import) and WASM runtimes
 * that provide Web Crypto. Does NOT require Node.js.
 *
 * For true WASM compilation, use AssemblyScript or wasm-pack with
 * this as the reference implementation. This module serves as:
 * 1. A browser-ready bundle (no bundler needed)
 * 2. A reference for compiling to actual WASM via AssemblyScript
 */

// ─── Types ───────────────────────────────────────────────────────────

export enum Scale {
  CHROMATIC = 0, MAJOR = 1, MINOR = 2, PENTATONIC = 3,
  BLUES = 4, DORIAN = 5, MIXOLYDIAN = 6,
}

export interface MusicEvent {
  note: number; velocity: number; duration: number; timestamp: number;
}

export interface Song {
  events: MusicEvent[];
  eventCount: number;
  totalDuration: number;
  scale: number;
  rootNote: number;
  tempo: number;
  entropyBits: number;
}

export interface Analysis {
  harmonicScore: number;
  melodyScore: number;
  rhythmScore: number;
  scaleAdherence: number;
  overallMusicality: number;
  isValidMusic: boolean;
}

export interface EncryptedSong {
  scrambledData: string;
  dataSize: number;
  salt: string;
  iv: string;
  authTag: string;
  innerIv: string;
  innerAuthTag: string;
  verificationHash: string;
  scrambleIterations: number;
  kdfType: 'pbkdf2-scrypt' | 'pbkdf2';
}

export interface MusiKeyConfig {
  songLength?: number;
  scrambleIterations?: number;
  musicalityThreshold?: number;
  maxFailedAttempts?: number;
  preferredScale?: Scale;
}

export interface AuthResult {
  success: boolean;
  song?: Song;
  analysis?: Analysis;
  error?: string;
  destroyed?: boolean;
}

export interface Credential {
  userId: string;
  scrambledSong: EncryptedSong;
  scale: number;
  rootNote: number;
  createdTimestamp: number;
  lastAuthTimestamp: number;
  lastFailedTimestamp: number;
  authAttempts: number;
  failedAttempts: number;
  locked: boolean;
  version: number;
  integrityHash: string;
}

// ─── Constants ───────────────────────────────────────────────────────

const SCALE_INTERVALS: Record<number, number[]> = {
  [Scale.CHROMATIC]: [0,1,2,3,4,5,6,7,8,9,10,11],
  [Scale.MAJOR]: [0,2,4,5,7,9,11],
  [Scale.MINOR]: [0,2,3,5,7,8,10],
  [Scale.PENTATONIC]: [0,2,4,7,9],
  [Scale.BLUES]: [0,3,5,6,7,10],
  [Scale.DORIAN]: [0,2,3,5,7,9,10],
  [Scale.MIXOLYDIAN]: [0,2,4,5,7,9,10],
};

const HARMONIC_RATIOS: Record<number, number> = {
  0: 1.0, 1: 0.1, 2: 0.3, 3: 0.6, 4: 0.8, 5: 0.9,
  6: 0.2, 7: 0.95, 8: 0.7, 9: 0.5, 10: 0.4, 11: 0.15,
};

// ─── Helpers ─────────────────────────────────────────────────────────

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function getRandomBytes(n: number): Uint8Array {
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error('MusiKey requires crypto.getRandomValues — this environment is not supported.');
  }
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// ─── Song Generation ─────────────────────────────────────────────────

function generateSongAttempt(length: number, scale: Scale): Song {
  const rand = getRandomBytes(1024);
  let idx = 0;
  const nextByte = () => rand[idx++ % 1024];

  const rootNote = nextByte() % 12;
  const tempo = 80 + (nextByte() % 80);
  const intervals = SCALE_INTERVALS[scale];
  const beatDur = Math.floor(60000 / tempo);

  let currentNote = 48 + rootNote;
  let currentTime = 0;
  const events: MusicEvent[] = [];

  for (let i = 0; i < length; i++) {
    let movement = (nextByte() % 5) - 2;
    if (nextByte() % 8 === 0) movement = (nextByte() % 9) - 4;

    if (scale !== Scale.CHROMATIC) {
      let scalePos = 0;
      for (let j = 0; j < intervals.length; j++) {
        if (currentNote % 12 === (rootNote + intervals[j]) % 12) { scalePos = j; break; }
      }
      scalePos = ((scalePos + movement) % intervals.length + intervals.length * 10) % intervals.length;
      let octave = Math.floor(currentNote / 12);
      if (movement > 2) octave++;
      if (movement < -2) octave--;
      octave = Math.max(3, Math.min(6, octave));
      currentNote = octave * 12 + rootNote + intervals[scalePos];
    } else {
      currentNote = (currentNote + movement + 128) % 128;
    }

    const velocity = 60 + (nextByte() % 60);
    const rc = nextByte() % 16;
    const duration = rc < 4 ? Math.floor(beatDur / 4) :
                     rc < 10 ? Math.floor(beatDur / 2) :
                     rc < 14 ? beatDur : beatDur * 2;
    events.push({ note: currentNote, velocity, duration, timestamp: currentTime });
    currentTime += duration;
  }

  const song: Song = { events, eventCount: length, totalDuration: currentTime, scale, rootNote, tempo, entropyBits: 0 };
  song.entropyBits = calculateEntropy(song);
  return song;
}

function calculateEntropy(song: Song): number {
  if (song.eventCount === 0) return 0;
  const nc = new Map<number, number>();
  const dc = new Map<number, number>();
  for (const e of song.events) {
    nc.set(e.note % 128, (nc.get(e.note % 128) || 0) + 1);
    dc.set(e.duration % 8, (dc.get(e.duration % 8) || 0) + 1);
  }
  const n = song.eventCount;
  let ne = 0, de = 0;
  for (const c of nc.values()) { const p = c / n; ne -= p * Math.log2(p); }
  for (const c of dc.values()) { const p = c / n; de -= p * Math.log2(p); }
  return Math.floor((ne + de) * n / 4);
}

function analyzeSong(song: Song, threshold: number): Analysis {
  const result: Analysis = { harmonicScore: 0, melodyScore: 0, rhythmScore: 0, scaleAdherence: 0, overallMusicality: 0, isValidMusic: false };
  if (song.eventCount < 4) return result;

  let harmSum = 0, melSum = 0, scaleHits = 0;
  for (let i = 1; i < song.eventCount; i++) {
    const interval = Math.abs(song.events[i].note - song.events[i - 1].note) % 12;
    harmSum += HARMONIC_RATIOS[interval] || 0;
    const diff = Math.abs(song.events[i].note - song.events[i - 1].note);
    melSum += diff <= 2 ? 1.0 : diff <= 4 ? 0.7 : diff <= 7 ? 0.4 : 0.2;
    const pc = ((song.events[i].note % 12) - song.rootNote + 12) % 12;
    if ((SCALE_INTERVALS[song.scale] || SCALE_INTERVALS[0]).includes(pc)) scaleHits++;
  }

  let rhythmReg = 0;
  for (let pl = 2; pl <= 8; pl++) {
    let m = 0;
    for (let i = pl; i < song.eventCount; i++) if (song.events[i].duration === song.events[i - pl].duration) m++;
    rhythmReg = Math.max(rhythmReg, m / (song.eventCount - pl));
  }

  const n = song.eventCount - 1;
  result.harmonicScore = harmSum / n;
  result.melodyScore = melSum / n;
  result.rhythmScore = rhythmReg;
  result.scaleAdherence = scaleHits / n;
  result.overallMusicality = result.harmonicScore * 0.3 + result.melodyScore * 0.3 + result.rhythmScore * 0.2 + result.scaleAdherence * 0.2;
  result.isValidMusic = result.overallMusicality >= threshold;
  return result;
}

// ─── Serialization ───────────────────────────────────────────────────

function serializeEvents(events: MusicEvent[]): ArrayBuffer {
  const buf = new ArrayBuffer(events.length * 8);
  const view = new DataView(buf);
  for (let i = 0; i < events.length; i++) {
    const o = i * 8;
    view.setUint8(o, events[i].note);
    view.setUint8(o + 1, events[i].velocity);
    view.setUint16(o + 2, events[i].duration, true);
    view.setUint32(o + 4, events[i].timestamp, true);
  }
  return buf;
}

function deserializeEvents(buf: ArrayBuffer): MusicEvent[] {
  const view = new DataView(buf);
  const count = Math.floor(buf.byteLength / 8);
  const events: MusicEvent[] = [];
  for (let i = 0; i < count; i++) {
    const o = i * 8;
    events.push({
      note: view.getUint8(o),
      velocity: view.getUint8(o + 1),
      duration: view.getUint16(o + 2, true),
      timestamp: view.getUint32(o + 4, true),
    });
  }
  return events;
}

// ─── Web Crypto Wrappers ─────────────────────────────────────────────

async function pbkdf2Derive(passphrase: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, keyMaterial, 256);
}

async function sha256(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', data);
}

async function aesEncrypt(key: ArrayBuffer, plaintext: ArrayBuffer): Promise<{ ct: Uint8Array; iv: Uint8Array; tag: Uint8Array }> {
  const iv = getRandomBytes(12);
  const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, aesKey, plaintext);
  const enc = new Uint8Array(encrypted);
  return { ct: enc.slice(0, enc.length - 16), iv, tag: enc.slice(enc.length - 16) };
}

async function aesDecrypt(key: ArrayBuffer, ct: Uint8Array, iv: Uint8Array, tag: Uint8Array): Promise<ArrayBuffer> {
  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct);
  combined.set(tag, ct.length);
  const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, aesKey, combined);
}

// ─── Main Class ──────────────────────────────────────────────────────

export class MusiKeyWasm {
  private songLength: number;
  private scrambleIterations: number;
  private musicalityThreshold: number;
  private maxFailedAttempts: number;
  private preferredScale: Scale;

  constructor(config: MusiKeyConfig = {}) {
    this.songLength = config.songLength ?? 64;
    this.scrambleIterations = config.scrambleIterations ?? 600000;
    this.musicalityThreshold = config.musicalityThreshold ?? 0.7;
    this.maxFailedAttempts = config.maxFailedAttempts ?? 5;
    this.preferredScale = config.preferredScale ?? Scale.PENTATONIC;
  }

  generateSong(scale?: Scale, length?: number): Song {
    const s = scale ?? this.preferredScale;
    const l = Math.max(32, Math.min(256, length ?? this.songLength));
    for (let i = 0; i < 10; i++) {
      const song = generateSongAttempt(l, s);
      if (song.entropyBits >= 40) return song;
    }
    return generateSongAttempt(l, s);
  }

  analyze(song: Song): Analysis {
    return analyzeSong(song, this.musicalityThreshold);
  }

  /** Encrypt with PBKDF2 + double AES-256-GCM (no scrypt in browser — use high PBKDF2 iterations) */
  async encrypt(song: Song, passphrase: string): Promise<EncryptedSong> {
    const salt = getRandomBytes(32);
    const key = await pbkdf2Derive(passphrase, salt, this.scrambleIterations);
    const plaintext = serializeEvents(song.events);
    const verHash = await sha256(plaintext);

    // Inner layer
    const innerKey = await sha256(plaintext);
    const inner = await aesEncrypt(innerKey, plaintext);

    // Outer layer
    const outer = await aesEncrypt(key, inner.ct.buffer as ArrayBuffer);

    // Zero sensitive buffers
    new Uint8Array(plaintext).fill(0);
    new Uint8Array(key).fill(0);
    new Uint8Array(innerKey).fill(0);

    return {
      scrambledData: toBase64(outer.ct.buffer as ArrayBuffer),
      dataSize: outer.ct.length,
      salt: toBase64(salt.buffer as ArrayBuffer),
      iv: toBase64(outer.iv.buffer as ArrayBuffer),
      authTag: toBase64(outer.tag.buffer as ArrayBuffer),
      innerIv: toBase64(inner.iv.buffer as ArrayBuffer),
      innerAuthTag: toBase64(inner.tag.buffer as ArrayBuffer),
      verificationHash: toBase64(verHash),
      scrambleIterations: this.scrambleIterations,
      kdfType: 'pbkdf2' as const,
    };
  }

  async decrypt(encrypted: EncryptedSong, passphrase: string): Promise<Song | null> {
    try {
      const salt = fromBase64(encrypted.salt);
      const key = await pbkdf2Derive(passphrase, salt, encrypted.scrambleIterations);

      // Outer decrypt
      const innerCt = await aesDecrypt(key, fromBase64(encrypted.scrambledData), fromBase64(encrypted.iv), fromBase64(encrypted.authTag));

      // Inner decrypt
      let plaintext: ArrayBuffer;
      if (encrypted.innerIv && encrypted.innerAuthTag) {
        const verHash = fromBase64(encrypted.verificationHash);
        plaintext = await aesDecrypt(verHash.buffer as ArrayBuffer, new Uint8Array(innerCt), fromBase64(encrypted.innerIv), fromBase64(encrypted.innerAuthTag));
      } else {
        plaintext = innerCt;
      }

      // Verify
      const hash = new Uint8Array(await sha256(plaintext));
      const expected = fromBase64(encrypted.verificationHash);
      let diff = 0;
      for (let i = 0; i < hash.length; i++) diff |= hash[i] ^ expected[i];
      if (diff !== 0) return null;

      const events = deserializeEvents(plaintext);
      let totalDuration = 0;
      if (events.length > 0) {
        const last = events[events.length - 1];
        totalDuration = last.timestamp + last.duration;
      }

      // Zero sensitive buffers
      new Uint8Array(key).fill(0);
      new Uint8Array(plaintext).fill(0);

      return { events, eventCount: events.length, totalDuration, scale: 0, rootNote: 0, tempo: 0, entropyBits: calculateEntropy({ events, eventCount: events.length } as Song) };
    } catch {
      return null;
    }
  }

  async enroll(userId: string, passphrase: string): Promise<Credential | null> {
    let song: Song | null = null;
    let analysis: Analysis | null = null;
    for (let i = 0; i < 10; i++) {
      song = this.generateSong();
      analysis = this.analyze(song);
      if (analysis.isValidMusic) break;
      song = null;
    }
    if (!song || !analysis || !analysis.isValidMusic) return null;

    const encrypted = await this.encrypt(song, passphrase);
    return {
      userId,
      scrambledSong: encrypted,
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
  }

  async authenticate(credential: Credential, passphrase: string): Promise<AuthResult> {
    if (credential.locked) return { success: false, error: 'Account locked' };

    if (credential.lastFailedTimestamp && credential.failedAttempts > 0) {
      const backoff = Math.pow(2, Math.min(credential.failedAttempts, 5)) * 1000;
      if (Date.now() - credential.lastFailedTimestamp < backoff) {
        return { success: false, error: 'Rate limited' };
      }
    }

    credential.authAttempts++;
    const song = await this.decrypt(credential.scrambledSong, passphrase);

    if (!song) {
      credential.failedAttempts++;
      credential.lastFailedTimestamp = Date.now();
      if (credential.failedAttempts >= this.maxFailedAttempts) {
        credential.locked = true;
        return { success: false, error: 'Self-destructed', destroyed: true };
      }
      return { success: false, error: 'Wrong passphrase' };
    }

    song.scale = credential.scale;
    song.rootNote = credential.rootNote;
    const analysis = this.analyze(song);

    if (!analysis.isValidMusic) {
      credential.failedAttempts++;
      credential.lastFailedTimestamp = Date.now();
      if (credential.failedAttempts >= this.maxFailedAttempts) {
        credential.locked = true;
        return { success: false, error: 'Self-destructed', destroyed: true };
      }
      return { success: false, error: 'Musicality check failed' };
    }

    credential.failedAttempts = 0;
    credential.lastAuthTimestamp = Date.now();
    return { success: true, song, analysis };
  }
}

// Browser global export
if (typeof globalThis !== 'undefined') {
  (globalThis as any).MusiKeyWasm = MusiKeyWasm;
  (globalThis as any).MusiKeyScale = Scale;
}

export default MusiKeyWasm;
