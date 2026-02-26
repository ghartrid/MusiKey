const NUM_BARS = 32;
const bars: { height: number; target: number; color: string }[] = [];

for (let i = 0; i < NUM_BARS; i++) {
  bars.push({ height: 0.05, target: 0.05, color: '#e94560' });
}

export function setBarTarget(index: number, target: number, color?: string): void {
  if (index >= 0 && index < NUM_BARS) {
    bars[index].target = Math.max(0.05, Math.min(1.0, target));
    if (color) bars[index].color = color;
  }
}

export function triggerNote(note: number, velocity: number): void {
  const bar = Math.floor(((note - 36) / 48) * NUM_BARS);
  const idx = Math.max(0, Math.min(NUM_BARS - 1, bar));
  bars[idx].target = velocity / 127;
  bars[idx].color = '#4ecca3';
  // Also affect neighbors slightly
  if (idx > 0) {
    bars[idx - 1].target = Math.max(bars[idx - 1].target, velocity / 200);
    bars[idx - 1].color = '#0f3460';
  }
  if (idx < NUM_BARS - 1) {
    bars[idx + 1].target = Math.max(bars[idx + 1].target, velocity / 200);
    bars[idx + 1].color = '#0f3460';
  }
}

export function updateVisualizer(deltaMs: number): void {
  const lerp = Math.min(1.0, deltaMs / 120);
  for (const bar of bars) {
    bar.height += (bar.target - bar.height) * lerp;
    // Decay target toward baseline
    bar.target += (0.05 - bar.target) * (deltaMs / 400);
  }
}

export function renderVisualizer(ctx: CanvasRenderingContext2D, width: number, height: number): void {
  ctx.clearRect(0, 0, width, height);

  const barWidth = Math.floor(width / NUM_BARS) - 2;
  const gap = 2;

  for (let i = 0; i < NUM_BARS; i++) {
    const x = i * (barWidth + gap) + 1;
    const barH = bars[i].height * height;
    const y = height - barH;

    // Gradient bar
    const gradient = ctx.createLinearGradient(x, y, x, height);
    gradient.addColorStop(0, bars[i].color);
    gradient.addColorStop(1, '#16213e');
    ctx.fillStyle = gradient;

    ctx.beginPath();
    ctx.roundRect(x, y, barWidth, barH, 2);
    ctx.fill();
  }
}

export function pulseSuccess(): void {
  for (let i = 0; i < NUM_BARS; i++) {
    bars[i].target = 0.3 + Math.sin(i * 0.3) * 0.3;
    bars[i].color = '#4ecca3';
  }
}

export function shakeFailure(): void {
  for (let i = 0; i < NUM_BARS; i++) {
    bars[i].target = 0.1 + Math.random() * 0.15;
    bars[i].color = '#ff6b6b';
  }
}

export function randomize(): void {
  for (let i = 0; i < NUM_BARS; i++) {
    bars[i].target = 0.1 + Math.random() * 0.6;
    bars[i].color = '#e94560';
  }
}

export function resetVisualizer(): void {
  for (const bar of bars) {
    bar.height = 0.05;
    bar.target = 0.05;
    bar.color = '#e94560';
  }
}
