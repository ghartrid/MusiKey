export enum MusikeyScale {
  CHROMATIC = 0,
  MAJOR,
  MINOR,
  PENTATONIC,
  BLUES,
  DORIAN,
  MIXOLYDIAN,
}

export const SCALE_NAMES: Record<MusikeyScale, string> = {
  [MusikeyScale.CHROMATIC]: 'Chromatic',
  [MusikeyScale.MAJOR]: 'Major',
  [MusikeyScale.MINOR]: 'Minor',
  [MusikeyScale.PENTATONIC]: 'Pentatonic',
  [MusikeyScale.BLUES]: 'Blues',
  [MusikeyScale.DORIAN]: 'Dorian',
  [MusikeyScale.MIXOLYDIAN]: 'Mixolydian',
};

export enum MusikeyError {
  OK = 0,
  INVALID_INPUT,
  INSUFFICIENT_ENTROPY,
  SCRAMBLE_FAILED,
  DESCRAMBLE_FAILED,
  NOT_MUSIC,
  AUTH_FAILED,
  LOCKED,
  MEMORY,
  CRYPTO,
}

export interface MusikeyEvent {
  note: number;
  velocity: number;
  duration: number;
  timestamp: number;
}

export interface MusikeySong {
  events: MusikeyEvent[];
  eventCount: number;
  totalDuration: number;
  scale: MusikeyScale;
  rootNote: number;
  tempo: number;
  entropyBits: number;
}

export interface MusikeyAnalysis {
  harmonicScore: number;
  melodyScore: number;
  rhythmScore: number;
  scaleAdherence: number;
  overallMusicality: number;
  isValidMusic: boolean;
}

export interface MusikeyScrambled {
  scrambledData: string;
  dataSize: number;
  salt: string;
  iv: string;
  authTag: string;
  innerIv: string;
  innerAuthTag: string;
  verificationHash: string;
  scrambleIterations: number;
}

export interface MusikeyCredential {
  userId: string;
  scrambledSong: MusikeyScrambled;
  scale: MusikeyScale;
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

export interface MusikeyConfig {
  songLength: number;
  scrambleIterations: number;
  musicalityThreshold: number;
  maxFailedAttempts: number;
  preferredScale: MusikeyScale;
}

export const DEFAULT_CONFIG: MusikeyConfig = {
  songLength: 64,
  scrambleIterations: 600000,
  musicalityThreshold: 0.7,
  maxFailedAttempts: 5,
  preferredScale: MusikeyScale.PENTATONIC,
};
