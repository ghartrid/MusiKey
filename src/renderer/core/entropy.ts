import { MusikeySong } from './types';

export function calculateEntropy(song: MusikeySong): number {
  if (song.eventCount === 0) return 0;

  const noteCounts = new Map<number, number>();
  const durationCounts = new Map<number, number>();
  const n = song.eventCount;

  for (const event of song.events) {
    noteCounts.set(event.note % 128, (noteCounts.get(event.note % 128) || 0) + 1);
    durationCounts.set(event.duration % 8, (durationCounts.get(event.duration % 8) || 0) + 1);
  }

  let noteEntropy = 0;
  for (const count of noteCounts.values()) {
    const p = count / n;
    noteEntropy -= p * Math.log2(p);
  }

  let durationEntropy = 0;
  for (const count of durationCounts.values()) {
    const p = count / n;
    durationEntropy -= p * Math.log2(p);
  }

  return Math.floor((noteEntropy + durationEntropy) * n / 4);
}
