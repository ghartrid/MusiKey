import { MusikeySong, MusikeyScrambled, MusikeyEvent, MusikeyError } from './types';

function zeroBuffer(buf: Uint8Array): void {
  buf.fill(0);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function serializeEvents(events: MusikeyEvent[], count: number): ArrayBuffer {
  const buffer = new ArrayBuffer(count * 6);
  const view = new DataView(buffer);
  for (let i = 0; i < count; i++) {
    const offset = i * 6;
    view.setUint8(offset, events[i].note);
    view.setUint8(offset + 1, events[i].velocity);
    view.setUint16(offset + 2, events[i].duration, true);
    view.setUint16(offset + 4, events[i].timestamp, true);
  }
  return buffer;
}

function deserializeEvents(buffer: ArrayBuffer): MusikeyEvent[] {
  const view = new DataView(buffer);
  const count = Math.floor(buffer.byteLength / 6);
  const events: MusikeyEvent[] = [];
  for (let i = 0; i < count; i++) {
    const offset = i * 6;
    events.push({
      note: view.getUint8(offset),
      velocity: view.getUint8(offset + 1),
      duration: view.getUint16(offset + 2, true),
      timestamp: view.getUint16(offset + 4, true),
    });
  }
  return events;
}

// Cascaded KDF: PBKDF2 (600k) → scrypt (N=2^17, 128MB memory-hard) → AES-256 key
// Runs in main process via IPC for access to Node.js crypto.scryptSync
async function deriveCascadedKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const saltB64 = arrayBufferToBase64(salt.buffer as ArrayBuffer);
  const keyB64 = await window.musikeyStore.cascadedKDF(passphrase, saltB64, iterations);
  const keyBytes = base64ToArrayBuffer(keyB64);
  return crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function deriveKeyFromBytes(keyBytes: ArrayBuffer): Promise<CryptoKey> {
  const hash = await crypto.subtle.digest('SHA-256', keyBytes);
  return crypto.subtle.importKey(
    'raw', hash, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function sha256(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', data);
}

// Inner encryption: uses song content as key material
async function innerEncrypt(plaintext: ArrayBuffer): Promise<{ ciphertext: Uint8Array; iv: Uint8Array; authTag: Uint8Array }> {
  const innerKey = await deriveKeyFromBytes(plaintext);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, innerKey, plaintext
  );

  const encBytes = new Uint8Array(encrypted);
  const ciphertext = encBytes.slice(0, encBytes.length - 16);
  const authTag = encBytes.slice(encBytes.length - 16);

  return { ciphertext, iv, authTag };
}

export async function scramble(
  song: MusikeySong,
  passphrase: string,
  iterations: number = 600000
): Promise<{ scrambled: MusikeyScrambled; error: MusikeyError }> {
  try {
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    // Cascaded KDF: PBKDF2 → scrypt → AES key
    const key = await deriveCascadedKey(passphrase, salt, iterations);
    const plaintext = serializeEvents(song.events, song.eventCount);
    const verificationHash = await sha256(plaintext);

    // Inner encryption layer: song content encrypts itself
    const inner = await innerEncrypt(plaintext);

    // Outer encryption layer: cascaded-KDF-derived key encrypts the inner ciphertext
    const innerPayload = new Uint8Array(inner.ciphertext.length);
    innerPayload.set(inner.ciphertext);

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key, innerPayload.buffer
    );

    const encBytes = new Uint8Array(encrypted);
    const ciphertext = encBytes.slice(0, encBytes.length - 16);
    const authTag = encBytes.slice(encBytes.length - 16);

    // Zero sensitive buffers
    zeroBuffer(new Uint8Array(plaintext));
    zeroBuffer(innerPayload);

    return {
      scrambled: {
        scrambledData: arrayBufferToBase64(ciphertext.buffer),
        dataSize: ciphertext.length,
        salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
        iv: arrayBufferToBase64(iv.buffer),
        authTag: arrayBufferToBase64(authTag.buffer),
        innerIv: arrayBufferToBase64(inner.iv.buffer as ArrayBuffer),
        innerAuthTag: arrayBufferToBase64(inner.authTag.buffer as ArrayBuffer),
        verificationHash: arrayBufferToBase64(verificationHash),
        scrambleIterations: iterations,
      },
      error: MusikeyError.OK,
    };
  } catch {
    return { scrambled: {} as MusikeyScrambled, error: MusikeyError.SCRAMBLE_FAILED };
  }
}

export async function descramble(
  scrambled: MusikeyScrambled,
  passphrase: string
): Promise<{ song: MusikeySong | null; error: MusikeyError }> {
  try {
    const salt = new Uint8Array(base64ToArrayBuffer(scrambled.salt));
    const iv = new Uint8Array(base64ToArrayBuffer(scrambled.iv));
    const ciphertext = new Uint8Array(base64ToArrayBuffer(scrambled.scrambledData));
    const authTag = new Uint8Array(base64ToArrayBuffer(scrambled.authTag));

    // Outer decryption: cascaded KDF key
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const key = await deriveCascadedKey(passphrase, salt, scrambled.scrambleIterations);

    const innerCiphertext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key, combined.buffer
    );

    // Inner decryption
    const hasInnerLayer = scrambled.innerIv && scrambled.innerAuthTag;
    let plaintext: ArrayBuffer;

    if (hasInnerLayer) {
      const innerIv = new Uint8Array(base64ToArrayBuffer(scrambled.innerIv));
      const innerTag = new Uint8Array(base64ToArrayBuffer(scrambled.innerAuthTag));
      const innerCt = new Uint8Array(innerCiphertext);

      const verifyHashBytes = new Uint8Array(base64ToArrayBuffer(scrambled.verificationHash));
      const innerKey = await crypto.subtle.importKey(
        'raw', verifyHashBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );

      const innerCombined = new Uint8Array(innerCt.length + innerTag.length);
      innerCombined.set(innerCt);
      innerCombined.set(innerTag, innerCt.length);

      plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: innerIv as BufferSource, tagLength: 128 }, innerKey, innerCombined.buffer as ArrayBuffer
      );
    } else {
      plaintext = innerCiphertext;
    }

    // Verify hash (constant-time)
    const hash = await sha256(plaintext);
    const expectedHash = new Uint8Array(base64ToArrayBuffer(scrambled.verificationHash));
    const actualHash = new Uint8Array(hash);
    let diff = 0;
    for (let i = 0; i < expectedHash.length; i++) {
      diff |= expectedHash[i] ^ actualHash[i];
    }
    if (diff !== 0) {
      return { song: null, error: MusikeyError.DESCRAMBLE_FAILED };
    }

    const events = deserializeEvents(plaintext);
    let totalDuration = 0;
    if (events.length > 0) {
      const last = events[events.length - 1];
      totalDuration = last.timestamp + last.duration;
    }

    // Zero sensitive buffers
    zeroBuffer(new Uint8Array(plaintext));

    return {
      song: {
        events,
        eventCount: events.length,
        totalDuration,
        scale: 0,
        rootNote: 0,
        tempo: 0,
        entropyBits: 0,
      },
      error: MusikeyError.OK,
    };
  } catch {
    return { song: null, error: MusikeyError.DESCRAMBLE_FAILED };
  }
}
