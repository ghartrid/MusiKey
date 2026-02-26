import { MusikeySong, MusikeyAnalysis, MusikeyConfig, DEFAULT_CONFIG } from './types';
import { harmonicRatio, noteInScale } from './scales';

export function analyze(song: MusikeySong, threshold: number = DEFAULT_CONFIG.musicalityThreshold): MusikeyAnalysis {
  const result: MusikeyAnalysis = {
    harmonicScore: 0,
    melodyScore: 0,
    rhythmScore: 0,
    scaleAdherence: 0,
    overallMusicality: 0,
    isValidMusic: false,
  };

  if (song.eventCount < 4) return result;

  let harmonicSum = 0;
  let melodicSum = 0;
  let scaleHits = 0;

  for (let i = 1; i < song.eventCount; i++) {
    harmonicSum += harmonicRatio(song.events[i - 1].note, song.events[i].note);

    const interval = Math.abs(song.events[i].note - song.events[i - 1].note);
    if (interval <= 2) melodicSum += 1.0;
    else if (interval <= 4) melodicSum += 0.7;
    else if (interval <= 7) melodicSum += 0.4;
    else melodicSum += 0.2;

    if (noteInScale(song.events[i].note, song.scale, song.rootNote)) {
      scaleHits++;
    }
  }

  // Rhythm regularity: find best pattern match across lengths 2-8
  let rhythmRegularity = 0;
  for (let patternLen = 2; patternLen <= 8; patternLen++) {
    let matches = 0;
    for (let i = patternLen; i < song.eventCount; i++) {
      if (song.events[i].duration === song.events[i - patternLen].duration) {
        matches++;
      }
    }
    const patternScore = matches / (song.eventCount - patternLen);
    if (patternScore > rhythmRegularity) {
      rhythmRegularity = patternScore;
    }
  }

  const n = song.eventCount - 1;
  result.harmonicScore = harmonicSum / n;
  result.melodyScore = melodicSum / n;
  result.rhythmScore = rhythmRegularity;
  result.scaleAdherence = scaleHits / n;

  result.overallMusicality =
    result.harmonicScore * 0.3 +
    result.melodyScore * 0.3 +
    result.rhythmScore * 0.2 +
    result.scaleAdherence * 0.2;

  result.isValidMusic = result.overallMusicality >= threshold;
  return result;
}
