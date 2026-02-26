import { MusikeyScale } from './types';

export const SCALE_INTERVALS: Record<MusikeyScale, number[]> = {
  [MusikeyScale.CHROMATIC]: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
  [MusikeyScale.MAJOR]: [0, 2, 4, 5, 7, 9, 11],
  [MusikeyScale.MINOR]: [0, 2, 3, 5, 7, 8, 10],
  [MusikeyScale.PENTATONIC]: [0, 2, 4, 7, 9],
  [MusikeyScale.BLUES]: [0, 3, 5, 6, 7, 10],
  [MusikeyScale.DORIAN]: [0, 2, 3, 5, 7, 9, 10],
  [MusikeyScale.MIXOLYDIAN]: [0, 2, 4, 5, 7, 9, 10],
};

export function getScaleIntervals(scale: MusikeyScale): number[] {
  return SCALE_INTERVALS[scale];
}

export function noteInScale(note: number, scale: MusikeyScale, root: number): boolean {
  if (scale === MusikeyScale.CHROMATIC) return true;
  const intervals = SCALE_INTERVALS[scale];
  const relative = ((note - root) % 12 + 12) % 12;
  return intervals.includes(relative);
}

export function harmonicRatio(note1: number, note2: number): number {
  const interval = Math.abs(note1 - note2) % 12;
  switch (interval) {
    case 0: return 1.0;
    case 7: return 0.95;
    case 5: return 0.90;
    case 4: return 0.85;
    case 3: return 0.80;
    case 9: return 0.75;
    case 8: return 0.70;
    case 2: return 0.60;
    case 10: return 0.55;
    case 11: return 0.50;
    case 1: return 0.30;
    case 6: return 0.35;
    default: return 0.5;
  }
}
