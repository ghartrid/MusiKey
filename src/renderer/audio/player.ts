import { MusikeySong, MusikeyEvent } from '../core/types';

export class MusikeyPlayer {
  private audioCtx: AudioContext | null = null;
  private scheduledNodes: OscillatorNode[] = [];
  private startTime = 0;
  private songDuration = 0;
  private _isPlaying = false;
  private animFrameId = 0;
  public onNote: ((index: number, event: MusikeyEvent) => void) | null = null;
  public onComplete: (() => void) | null = null;

  private currentNoteIndex = 0;
  private song: MusikeySong | null = null;

  get isPlaying(): boolean {
    return this._isPlaying;
  }

  play(song: MusikeySong): void {
    this.stop();
    this.audioCtx = new AudioContext();
    this.song = song;
    this.currentNoteIndex = 0;
    this._isPlaying = true;
    this.startTime = this.audioCtx.currentTime + 0.1;
    this.songDuration = song.totalDuration / 1000;

    for (let i = 0; i < song.eventCount; i++) {
      const event = song.events[i];
      const freq = 440 * Math.pow(2, (event.note - 69) / 12);
      const noteStart = this.startTime + event.timestamp / 1000;
      const noteDuration = Math.max(event.duration / 1000, 0.02);
      const amplitude = (event.velocity / 127) * 0.25;

      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();

      osc.type = 'sine';
      osc.frequency.value = freq;

      const attackEnd = noteStart + noteDuration * 0.1;
      const releaseStart = noteStart + noteDuration * 0.9;

      gain.gain.setValueAtTime(0, noteStart);
      gain.gain.linearRampToValueAtTime(amplitude, attackEnd);
      gain.gain.setValueAtTime(amplitude, releaseStart);
      gain.gain.linearRampToValueAtTime(0, noteStart + noteDuration);

      osc.connect(gain).connect(this.audioCtx.destination);
      osc.start(noteStart);
      osc.stop(noteStart + noteDuration);

      this.scheduledNodes.push(osc);
    }

    this.tick();
  }

  private tick = (): void => {
    if (!this._isPlaying || !this.audioCtx || !this.song) return;

    const elapsed = (this.audioCtx.currentTime - this.startTime) * 1000;

    // Fire note callbacks
    while (this.currentNoteIndex < this.song.eventCount) {
      const event = this.song.events[this.currentNoteIndex];
      if (event.timestamp <= elapsed) {
        this.onNote?.(this.currentNoteIndex, event);
        this.currentNoteIndex++;
      } else {
        break;
      }
    }

    if (elapsed >= this.song.totalDuration + 200) {
      this._isPlaying = false;
      this.onComplete?.();
      return;
    }

    this.animFrameId = requestAnimationFrame(this.tick);
  };

  stop(): void {
    this._isPlaying = false;
    cancelAnimationFrame(this.animFrameId);
    for (const osc of this.scheduledNodes) {
      try { osc.stop(); } catch { /* already stopped */ }
    }
    this.scheduledNodes = [];
    if (this.audioCtx) {
      this.audioCtx.close().catch(() => {});
      this.audioCtx = null;
    }
    this.song = null;
  }

  getElapsedMs(): number {
    if (!this.audioCtx || !this._isPlaying) return 0;
    return (this.audioCtx.currentTime - this.startTime) * 1000;
  }
}
