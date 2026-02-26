import * as crypto from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────

export enum Scale {
  CHROMATIC = 0, MAJOR, MINOR, PENTATONIC, BLUES, DORIAN, MIXOLYDIAN
}

export interface MusicEvent {
  note: number;
  velocity: number;
  duration: number;
  timestamp: number;
}

export interface Song {
  events: MusicEvent[];
  eventCount: number;
  totalDuration: number;
  scale: Scale;
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

export interface Credential {
  userId: string;
  scrambledSong: EncryptedSong;
  scale: Scale;
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

// ─── Scales ──────────────────────────────────────────────────────────

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

function noteInScale(note: number, scale: Scale, root: number): boolean {
  const intervals = SCALE_INTERVALS[scale] || SCALE_INTERVALS[Scale.CHROMATIC];
  const pc = ((note % 12) - root + 12) % 12;
  return intervals.includes(pc);
}

// ─── Song Generation ─────────────────────────────────────────────────

function generateSongAttempt(length: number, scale: Scale): Song {
  const randomBytes = crypto.randomBytes(1024);
  let idx = 0;
  const nextByte = () => randomBytes[idx++ % 1024];

  const rootNote = nextByte() % 12;
  const tempo = 80 + (nextByte() % 80);
  const intervals = SCALE_INTERVALS[scale];
  const beatDuration = Math.floor(60000 / tempo);

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
    const duration = rc < 4 ? Math.floor(beatDuration / 4) :
                     rc < 10 ? Math.floor(beatDuration / 2) :
                     rc < 14 ? beatDuration : beatDuration * 2;

    events.push({ note: currentNote, velocity, duration, timestamp: currentTime });
    currentTime += duration;
  }

  const song: Song = { events, eventCount: length, totalDuration: currentTime, scale, rootNote, tempo, entropyBits: 0 };
  song.entropyBits = calculateEntropy(song);
  return song;
}

// ─── Entropy ─────────────────────────────────────────────────────────

function calculateEntropy(song: Song): number {
  if (song.eventCount === 0) return 0;
  const noteCounts = new Map<number, number>();
  const durCounts = new Map<number, number>();
  for (const e of song.events) {
    noteCounts.set(e.note % 128, (noteCounts.get(e.note % 128) || 0) + 1);
    durCounts.set(e.duration % 8, (durCounts.get(e.duration % 8) || 0) + 1);
  }
  const n = song.eventCount;
  let ne = 0, de = 0;
  for (const c of noteCounts.values()) { const p = c / n; ne -= p * Math.log2(p); }
  for (const c of durCounts.values()) { const p = c / n; de -= p * Math.log2(p); }
  return Math.floor((ne + de) * n / 4);
}

// ─── Analysis ────────────────────────────────────────────────────────

function analyzeSong(song: Song, threshold: number): Analysis {
  const result: Analysis = { harmonicScore: 0, melodyScore: 0, rhythmScore: 0, scaleAdherence: 0, overallMusicality: 0, isValidMusic: false };
  if (song.eventCount < 4) return result;

  let harmSum = 0, melSum = 0, scaleHits = 0;
  for (let i = 1; i < song.eventCount; i++) {
    const interval = Math.abs(song.events[i].note - song.events[i - 1].note) % 12;
    harmSum += HARMONIC_RATIOS[interval] || 0;
    const diff = Math.abs(song.events[i].note - song.events[i - 1].note);
    melSum += diff <= 2 ? 1.0 : diff <= 4 ? 0.7 : diff <= 7 ? 0.4 : 0.2;
    if (noteInScale(song.events[i].note, song.scale, song.rootNote)) scaleHits++;
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

function serializeEvents(events: MusicEvent[]): Buffer {
  const buf = Buffer.alloc(events.length * 8);
  for (let i = 0; i < events.length; i++) {
    const o = i * 8;
    buf.writeUInt8(events[i].note, o);
    buf.writeUInt8(events[i].velocity, o + 1);
    buf.writeUInt16LE(events[i].duration, o + 2);
    buf.writeUInt32LE(events[i].timestamp, o + 4);
  }
  return buf;
}

function deserializeEvents(buf: Buffer): MusicEvent[] {
  const events: MusicEvent[] = [];
  const count = Math.floor(buf.length / 8);
  for (let i = 0; i < count; i++) {
    const o = i * 8;
    events.push({
      note: buf.readUInt8(o),
      velocity: buf.readUInt8(o + 1),
      duration: buf.readUInt16LE(o + 2),
      timestamp: buf.readUInt32LE(o + 4),
    });
  }
  return events;
}

// ─── Crypto ──────────────────────────────────────────────────────────

function cascadedKDF(passphrase: string, salt: Buffer, iterations: number): Buffer {
  const pbkdf2Key = crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');
  const scryptSalt = crypto.createHash('sha256').update(salt).update('scrypt-stage').digest();
  const finalKey = crypto.scryptSync(pbkdf2Key, scryptSalt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  pbkdf2Key.fill(0);
  return finalKey as Buffer;
}

function aesEncrypt(key: Buffer, plaintext: Buffer): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, iv, tag: cipher.getAuthTag() };
}

function aesDecrypt(key: Buffer, ciphertext: Buffer, iv: Buffer, tag: Buffer): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ─── Main Class ──────────────────────────────────────────────────────

export class MusiKey {
  private config: Required<MusiKeyConfig>;

  constructor(config: MusiKeyConfig = {}) {
    this.config = {
      songLength: config.songLength ?? 64,
      scrambleIterations: config.scrambleIterations ?? 600000,
      musicalityThreshold: config.musicalityThreshold ?? 0.7,
      maxFailedAttempts: config.maxFailedAttempts ?? 5,
      preferredScale: config.preferredScale ?? Scale.PENTATONIC,
    };
  }

  /** Generate a new musical composition */
  generateSong(scale?: Scale, length?: number): Song {
    const s = scale ?? this.config.preferredScale;
    const l = Math.max(32, Math.min(256, length ?? this.config.songLength));
    for (let i = 0; i < 10; i++) {
      const song = generateSongAttempt(l, s);
      if (song.entropyBits >= 40) return song;
    }
    return generateSongAttempt(l, s);
  }

  /** Analyze musicality of a song */
  analyze(song: Song): Analysis {
    return analyzeSong(song, this.config.musicalityThreshold);
  }

  /** Encrypt a song with a passphrase (cascaded PBKDF2 + scrypt + double AES-256-GCM) */
  encrypt(song: Song, passphrase: string): EncryptedSong {
    const salt = crypto.randomBytes(32);
    const key = cascadedKDF(passphrase, salt, this.config.scrambleIterations);
    const plaintext = serializeEvents(song.events);
    const verHash = crypto.createHash('sha256').update(plaintext).digest();

    // Inner layer: song content as key
    const innerKey = crypto.createHash('sha256').update(plaintext).digest();
    const inner = aesEncrypt(innerKey, plaintext);

    // Outer layer: passphrase-derived key
    const outer = aesEncrypt(key, inner.ciphertext);

    plaintext.fill(0);
    key.fill(0);
    innerKey.fill(0);

    return {
      scrambledData: outer.ciphertext.toString('base64'),
      dataSize: outer.ciphertext.length,
      salt: salt.toString('base64'),
      iv: outer.iv.toString('base64'),
      authTag: outer.tag.toString('base64'),
      innerIv: inner.iv.toString('base64'),
      innerAuthTag: inner.tag.toString('base64'),
      verificationHash: verHash.toString('base64'),
      scrambleIterations: this.config.scrambleIterations,
      kdfType: 'pbkdf2-scrypt',
    };
  }

  /** Decrypt an encrypted song with a passphrase */
  decrypt(encrypted: EncryptedSong, passphrase: string): Song | null {
    try {
      if (encrypted.kdfType && encrypted.kdfType !== 'pbkdf2-scrypt') {
        return null; // Incompatible KDF — encrypted by a different module (e.g. WASM/browser)
      }
      const salt = Buffer.from(encrypted.salt, 'base64');
      const key = cascadedKDF(passphrase, salt, encrypted.scrambleIterations);

      // Outer decrypt
      const innerCt = aesDecrypt(
        key,
        Buffer.from(encrypted.scrambledData, 'base64'),
        Buffer.from(encrypted.iv, 'base64'),
        Buffer.from(encrypted.authTag, 'base64')
      );
      key.fill(0);

      // Inner decrypt
      let plaintext: Buffer;
      if (encrypted.innerIv && encrypted.innerAuthTag) {
        const verHash = Buffer.from(encrypted.verificationHash, 'base64');
        plaintext = aesDecrypt(
          verHash,
          innerCt,
          Buffer.from(encrypted.innerIv, 'base64'),
          Buffer.from(encrypted.innerAuthTag, 'base64')
        );
      } else {
        plaintext = innerCt;
      }

      // Verify hash
      const hash = crypto.createHash('sha256').update(plaintext).digest();
      const expected = Buffer.from(encrypted.verificationHash, 'base64');
      if (!crypto.timingSafeEqual(hash, expected)) {
        plaintext.fill(0);
        return null;
      }

      const events = deserializeEvents(plaintext);
      plaintext.fill(0);

      let totalDuration = 0;
      if (events.length > 0) {
        const last = events[events.length - 1];
        totalDuration = last.timestamp + last.duration;
      }

      return { events, eventCount: events.length, totalDuration, scale: 0, rootNote: 0, tempo: 0, entropyBits: calculateEntropy({ events, eventCount: events.length } as Song) };
    } catch {
      return null;
    }
  }

  /** Full enrollment: generate + validate + encrypt (retries up to 10x) */
  enroll(userId: string, passphrase: string): Credential | null {
    let song: Song | null = null;
    let analysis: Analysis | null = null;
    for (let i = 0; i < 10; i++) {
      song = this.generateSong();
      analysis = this.analyze(song);
      if (analysis.isValidMusic) break;
      song = null;
    }
    if (!song || !analysis || !analysis.isValidMusic) return null;

    const encrypted = this.encrypt(song, passphrase);

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

  /** Full authentication: decrypt + validate musicality */
  authenticate(credential: Credential, passphrase: string): AuthResult {
    if (credential.locked) return { success: false, error: 'Account locked' };

    // Rate limiting check
    if (credential.lastFailedTimestamp && credential.failedAttempts > 0) {
      const backoff = Math.pow(2, Math.min(credential.failedAttempts, 5)) * 1000;
      if (Date.now() - credential.lastFailedTimestamp < backoff) {
        return { success: false, error: 'Rate limited' };
      }
    }

    credential.authAttempts++;
    const song = this.decrypt(credential.scrambledSong, passphrase);

    if (!song) {
      credential.failedAttempts++;
      credential.lastFailedTimestamp = Date.now();
      if (credential.failedAttempts >= this.config.maxFailedAttempts) {
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
      if (credential.failedAttempts >= this.config.maxFailedAttempts) {
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

export default MusiKey;
