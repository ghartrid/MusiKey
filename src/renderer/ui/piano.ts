const WHITE_KEY_WIDTH = 24;
const BLACK_KEY_WIDTH = 16;
const WHITE_KEY_HEIGHT = 70;
const BLACK_KEY_HEIGHT = 44;
const START_NOTE = 36; // C3 (octave 3)
const END_NOTE = 84;   // C7 — covers octaves 3-6 used by song generator
const NUM_WHITE_KEYS = 28; // C3 to B6 = 28 white keys

interface KeyLayout {
  note: number;
  x: number;
  width: number;
  height: number;
  isBlack: boolean;
}

const KEY_LAYOUT: KeyLayout[] = [];
const NOTE_HIGHLIGHT: Map<number, number> = new Map(); // note -> fade (0-1)

function buildLayout(canvasWidth: number): void {
  KEY_LAYOUT.length = 0;
  const totalWhite = NUM_WHITE_KEYS;
  const keyW = Math.floor(canvasWidth / totalWhite);
  const blackW = Math.floor(keyW * 0.65);

  // White keys first, then black overlaid
  const whiteNotes: number[] = [];
  const blackNotes: number[] = [];

  for (let n = START_NOTE; n < END_NOTE; n++) {
    const pc = n % 12;
    if ([1, 3, 6, 8, 10].includes(pc)) {
      blackNotes.push(n);
    } else {
      whiteNotes.push(n);
    }
  }

  for (let i = 0; i < whiteNotes.length; i++) {
    KEY_LAYOUT.push({
      note: whiteNotes[i],
      x: i * keyW,
      width: keyW - 1,
      height: WHITE_KEY_HEIGHT,
      isBlack: false,
    });
  }

  for (const n of blackNotes) {
    // Find the white key just below
    const pc = n % 12;
    let whiteBelow: number;
    if (pc === 1) whiteBelow = n - 1;
    else if (pc === 3) whiteBelow = n - 1;
    else if (pc === 6) whiteBelow = n - 1;
    else if (pc === 8) whiteBelow = n - 1;
    else whiteBelow = n - 1;

    const wIdx = whiteNotes.indexOf(whiteBelow);
    if (wIdx >= 0) {
      KEY_LAYOUT.push({
        note: n,
        x: (wIdx + 1) * keyW - Math.floor(blackW / 2),
        width: blackW,
        height: BLACK_KEY_HEIGHT,
        isBlack: true,
      });
    }
  }
}

export function highlightNote(note: number): void {
  NOTE_HIGHLIGHT.set(note, 1.0);
}

export function updatePiano(deltaMs: number): void {
  const decay = deltaMs / 500;
  for (const [note, val] of NOTE_HIGHLIGHT.entries()) {
    const newVal = val - decay;
    if (newVal <= 0) {
      NOTE_HIGHLIGHT.delete(note);
    } else {
      NOTE_HIGHLIGHT.set(note, newVal);
    }
  }
}

export function renderPiano(ctx: CanvasRenderingContext2D, width: number, height: number): void {
  if (KEY_LAYOUT.length === 0) buildLayout(width);

  ctx.clearRect(0, 0, width, height);

  // Draw white keys
  for (const key of KEY_LAYOUT) {
    if (key.isBlack) continue;
    const hl = NOTE_HIGHLIGHT.get(key.note) || 0;
    if (hl > 0) {
      const r = Math.round(240 - (240 - 78) * hl);
      const g = Math.round(240 - (240 - 204) * hl);
      const b = Math.round(240 - (240 - 163) * hl);
      ctx.fillStyle = `rgb(${r},${g},${b})`;
    } else {
      ctx.fillStyle = '#f0f0f0';
    }
    ctx.fillRect(key.x, 0, key.width, key.height);
    ctx.strokeStyle = '#888';
    ctx.lineWidth = 1;
    ctx.strokeRect(key.x, 0, key.width, key.height);
  }

  // Draw black keys
  for (const key of KEY_LAYOUT) {
    if (!key.isBlack) continue;
    const hl = NOTE_HIGHLIGHT.get(key.note) || 0;
    if (hl > 0) {
      const r = Math.round(42 + (78 - 42) * hl);
      const g = Math.round(42 + (204 - 42) * hl);
      const b = Math.round(42 + (163 - 42) * hl);
      ctx.fillStyle = `rgb(${r},${g},${b})`;
    } else {
      ctx.fillStyle = '#2a2a2a';
    }
    ctx.fillRect(key.x, 0, key.width, key.height);
    ctx.strokeStyle = '#111';
    ctx.lineWidth = 1;
    ctx.strokeRect(key.x, 0, key.width, key.height);
  }
}

export function resetPiano(): void {
  NOTE_HIGHLIGHT.clear();
}
