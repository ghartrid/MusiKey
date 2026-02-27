// Musical Randomart — visual song fingerprint using drunken bishop algorithm
// Produces an SSH-style ASCII art grid from SHA-256 of serialized song data

const GRID_W = 9;
const GRID_H = 9;
const PALETTE = ['#16213e', '#1a2744', '#1f2d4a', '#243350', '#293956', '#2e3f5c', '#334562', '#384b68', '#3d516e', '#426774', '#477d7a', '#4c9380', '#51a986', '#4ecca3', '#e94560', '#ff6b6b'];

export function generateFingerprint(songData: ArrayBuffer): number[][] {
  const grid: number[][] = Array.from({ length: GRID_H }, () => Array(GRID_W).fill(0));
  const hash = new Uint8Array(songData);

  // Compute SHA-256 synchronously by using pre-computed hash passed in
  let x = Math.floor(GRID_W / 2);
  let y = Math.floor(GRID_H / 2);

  for (let i = 0; i < hash.length; i++) {
    const byte = hash[i];
    for (let j = 0; j < 4; j++) {
      const bits = (byte >> (j * 2)) & 0x03;
      const dx = (bits & 1) ? 1 : -1;
      const dy = (bits & 2) ? 1 : -1;
      x = Math.max(0, Math.min(GRID_W - 1, x + dx));
      y = Math.max(0, Math.min(GRID_H - 1, y + dy));
      grid[y][x]++;
    }
  }

  // Mark start and end positions
  const startX = Math.floor(GRID_W / 2);
  const startY = Math.floor(GRID_H / 2);
  grid[startY][startX] = -1; // Start marker
  grid[y][x] = -2;          // End marker

  return grid;
}

export function renderFingerprint(
  ctx: CanvasRenderingContext2D,
  grid: number[][],
  width: number,
  height: number
): void {
  const cellW = width / GRID_W;
  const cellH = height / GRID_H;

  ctx.clearRect(0, 0, width, height);

  // Background
  ctx.fillStyle = '#0d1117';
  ctx.fillRect(0, 0, width, height);

  // Draw border
  ctx.strokeStyle = '#0f3460';
  ctx.lineWidth = 2;
  ctx.strokeRect(1, 1, width - 2, height - 2);

  for (let y = 0; y < GRID_H; y++) {
    for (let x = 0; x < GRID_W; x++) {
      const val = grid[y][x];
      const cx = x * cellW;
      const cy = y * cellH;

      if (val === -1) {
        // Start position — green circle
        ctx.fillStyle = '#4ecca3';
        ctx.beginPath();
        ctx.arc(cx + cellW / 2, cy + cellH / 2, Math.min(cellW, cellH) / 3, 0, Math.PI * 2);
        ctx.fill();
        // S label
        ctx.fillStyle = '#0d1117';
        ctx.font = `bold ${Math.floor(cellH * 0.5)}px monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('S', cx + cellW / 2, cy + cellH / 2);
      } else if (val === -2) {
        // End position — red diamond
        ctx.fillStyle = '#e94560';
        ctx.beginPath();
        const hw = cellW / 3;
        const hh = cellH / 3;
        ctx.moveTo(cx + cellW / 2, cy + cellH / 2 - hh);
        ctx.lineTo(cx + cellW / 2 + hw, cy + cellH / 2);
        ctx.lineTo(cx + cellW / 2, cy + cellH / 2 + hh);
        ctx.lineTo(cx + cellW / 2 - hw, cy + cellH / 2);
        ctx.closePath();
        ctx.fill();
        // E label
        ctx.fillStyle = '#0d1117';
        ctx.font = `bold ${Math.floor(cellH * 0.4)}px monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('E', cx + cellW / 2, cy + cellH / 2);
      } else {
        // Color based on visit count
        const idx = Math.min(val, PALETTE.length - 3);
        if (val > 0) {
          ctx.fillStyle = PALETTE[idx];
          const inset = 1;
          ctx.fillRect(cx + inset, cy + inset, cellW - inset * 2, cellH - inset * 2);
        }
      }
    }
  }

  // Grid lines
  ctx.strokeStyle = 'rgba(15, 52, 96, 0.3)';
  ctx.lineWidth = 0.5;
  for (let x = 1; x < GRID_W; x++) {
    ctx.beginPath();
    ctx.moveTo(x * cellW, 0);
    ctx.lineTo(x * cellW, height);
    ctx.stroke();
  }
  for (let y = 1; y < GRID_H; y++) {
    ctx.beginPath();
    ctx.moveTo(0, y * cellH);
    ctx.lineTo(width, y * cellH);
    ctx.stroke();
  }
}

// Generate fingerprint from raw hash bytes (already computed SHA-256)
export async function computeSongFingerprint(songHash: ArrayBuffer): Promise<number[][]> {
  return generateFingerprint(songHash);
}
