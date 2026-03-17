import { MusikeyEvent } from './types';

export interface MidiDeviceInfo {
  id: string;
  name: string;
}

interface ActiveNote {
  startTime: number;
  velocity: number;
}

export class MidiManager {
  private access: MIDIAccess | null = null;
  private activeInput: MIDIInput | null = null;
  private recording = false;
  private recordStartTime = 0;
  private events: MusikeyEvent[] = [];
  private activeNotes: Map<number, ActiveNote> = new Map();

  /** Called in real-time for each note-on during recording */
  public onNote: ((note: number, velocity: number) => void) | null = null;

  /** Called when a note-off completes an event during recording */
  public onEventCaptured: ((count: number) => void) | null = null;

  async init(): Promise<boolean> {
    try {
      this.access = await navigator.requestMIDIAccess();
      return true;
    } catch {
      this.access = null;
      return false;
    }
  }

  getInputs(): MidiDeviceInfo[] {
    if (!this.access) return [];
    const devices: MidiDeviceInfo[] = [];
    this.access.inputs.forEach((input) => {
      devices.push({
        id: input.id,
        name: input.name || `MIDI Input ${input.id}`,
      });
    });
    return devices;
  }

  selectInput(id: string): boolean {
    if (!this.access) return false;

    // Disconnect previous
    if (this.activeInput) {
      this.activeInput.onmidimessage = null;
      this.activeInput = null;
    }

    let found: MIDIInput | null = null;
    this.access.inputs.forEach((inp) => {
      if (inp.id === id) found = inp;
    });
    if (!found) return false;

    this.activeInput = found;
    (this.activeInput as MIDIInput).onmidimessage = this.handleMessage;
    return true;
  }

  startRecording(): void {
    this.events = [];
    this.activeNotes.clear();
    this.recordStartTime = performance.now();
    this.recording = true;
  }

  stopRecording(): MusikeyEvent[] {
    this.recording = false;

    // Finalize any notes still held down
    const now = performance.now();
    for (const [note, active] of this.activeNotes.entries()) {
      const duration = Math.round(now - active.startTime);
      const timestamp = Math.round(active.startTime - this.recordStartTime);
      this.events.push({
        note,
        velocity: active.velocity,
        duration: Math.max(duration, 10),
        timestamp,
      });
    }
    this.activeNotes.clear();

    // Sort events by timestamp — finalized held notes may have earlier timestamps
    // than events that completed during recording
    this.events.sort((a, b) => a.timestamp - b.timestamp);

    return [...this.events];
  }

  get isRecording(): boolean {
    return this.recording;
  }

  get noteCount(): number {
    return this.events.length + this.activeNotes.size;
  }

  get isInitialized(): boolean {
    return this.access !== null;
  }

  get hasInput(): boolean {
    return this.activeInput !== null;
  }

  dispose(): void {
    if (this.activeInput) {
      this.activeInput.onmidimessage = null;
      this.activeInput = null;
    }
    this.access = null;
    this.recording = false;
    this.events = [];
    this.activeNotes.clear();
  }

  private handleMessage = (msg: MIDIMessageEvent): void => {
    if (!this.recording) return;

    const data = msg.data;
    if (!data || data.length < 3) return;

    const status = data[0] & 0xf0;
    const note = data[1];
    const velocity = data[2];

    if (status === 0x90 && velocity > 0) {
      // Note On
      this.activeNotes.set(note, {
        startTime: performance.now(),
        velocity,
      });
      this.onNote?.(note, velocity);
    } else if (status === 0x80 || (status === 0x90 && velocity === 0)) {
      // Note Off
      const active = this.activeNotes.get(note);
      if (active) {
        const now = performance.now();
        const duration = Math.round(now - active.startTime);
        const timestamp = Math.round(active.startTime - this.recordStartTime);
        this.events.push({
          note,
          velocity: active.velocity,
          duration: Math.max(duration, 10),
          timestamp,
        });
        this.activeNotes.delete(note);
        this.onEventCaptured?.(this.events.length);
      }
    }
  };
}
