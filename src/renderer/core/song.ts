import { MusikeySong, MusikeyEvent, MusikeyScale, MusikeyConfig, DEFAULT_CONFIG } from './types';
import { getScaleIntervals } from './scales';
import { calculateEntropy } from './entropy';

export function generateSong(config: MusikeyConfig = DEFAULT_CONFIG): MusikeySong {
  const length = Math.max(32, Math.min(256, config.songLength));

  // Try up to 10 times to generate a song with sufficient entropy
  for (let attempt = 0; attempt < 10; attempt++) {
    const song = generateSongAttempt(config, length);
    if (song.entropyBits >= 40) return song;
  }
  // Last resort: return whatever we get
  return generateSongAttempt(config, length);
}

function generateSongAttempt(config: MusikeyConfig, length: number): MusikeySong {
  const randomBytes = new Uint8Array(1024);
  crypto.getRandomValues(randomBytes);
  let idx = 0;
  const nextByte = () => randomBytes[idx++ % 1024];

  const scale = config.preferredScale;
  const rootNote = nextByte() % 12;
  const tempo = 80 + (nextByte() % 80);
  const scaleIntervals = getScaleIntervals(scale);
  const beatDuration = Math.floor(60000 / tempo);

  let currentNote = 48 + rootNote;
  let currentTime = 0;
  const events: MusikeyEvent[] = [];

  for (let i = 0; i < length; i++) {
    let movement = (nextByte() % 5) - 2;
    if (nextByte() % 8 === 0) {
      movement = (nextByte() % 9) - 4;
    }

    if (scale !== MusikeyScale.CHROMATIC) {
      let scalePos = 0;
      for (let j = 0; j < scaleIntervals.length; j++) {
        if (currentNote % 12 === (rootNote + scaleIntervals[j]) % 12) {
          scalePos = j;
          break;
        }
      }
      scalePos = ((scalePos + movement) % scaleIntervals.length + scaleIntervals.length * 10) % scaleIntervals.length;
      let octave = Math.floor(currentNote / 12);
      if (movement > 2) octave++;
      if (movement < -2) octave--;
      octave = Math.max(3, Math.min(6, octave));
      currentNote = octave * 12 + rootNote + scaleIntervals[scalePos];
    } else {
      currentNote = (currentNote + movement + 128) % 128;
    }

    const velocity = 60 + (nextByte() % 60);
    const rhythmChoice = nextByte() % 16;
    let duration: number;
    if (rhythmChoice < 4) {
      duration = Math.floor(beatDuration / 4);
    } else if (rhythmChoice < 10) {
      duration = Math.floor(beatDuration / 2);
    } else if (rhythmChoice < 14) {
      duration = beatDuration;
    } else {
      duration = beatDuration * 2;
    }

    events.push({ note: currentNote, velocity, duration, timestamp: currentTime });
    currentTime += duration;
  }

  const song: MusikeySong = {
    events,
    eventCount: length,
    totalDuration: currentTime,
    scale,
    rootNote,
    tempo,
    entropyBits: 0,
  };
  song.entropyBits = calculateEntropy(song);
  return song;
}
