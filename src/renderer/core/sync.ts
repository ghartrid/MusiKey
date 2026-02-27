// Encrypted Credential Sync — portable credential bundles
// Uses independent PBKDF2 (300k) + AES-256-GCM keyed from sync passphrase

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

async function deriveSyncKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']
  );
  const keyBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: 300000, hash: 'SHA-256' },
    baseKey,
    256
  );
  return crypto.subtle.importKey(
    'raw', keyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

export interface SyncBundle {
  version: number;
  salt: string;
  iv: string;
  authTag: string;
  data: string;
  integrityHash: string;
  credentialCount: number;
  createdAt: number;
}

export async function createSyncBundle(
  credentials: any[],
  syncPassphrase: string
): Promise<string> {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const key = await deriveSyncKey(syncPassphrase, salt);

  const plaintext = new TextEncoder().encode(JSON.stringify(credentials));

  // Integrity hash of plaintext
  const hashBuf = await crypto.subtle.digest('SHA-256', plaintext);
  const integrityHash = arrayBufferToBase64(hashBuf);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext
  );

  const encBytes = new Uint8Array(encrypted);
  const ciphertext = encBytes.slice(0, encBytes.length - 16);
  const authTag = encBytes.slice(encBytes.length - 16);

  const bundle: SyncBundle = {
    version: 1,
    salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
    authTag: arrayBufferToBase64(authTag.buffer as ArrayBuffer),
    data: arrayBufferToBase64(ciphertext.buffer as ArrayBuffer),
    integrityHash,
    credentialCount: credentials.length,
    createdAt: Date.now(),
  };

  return JSON.stringify(bundle, null, 2);
}

export async function importSyncBundle(
  bundleJson: string,
  syncPassphrase: string
): Promise<{ credentials: any[] | null; error: string | null }> {
  try {
    const bundle: SyncBundle = JSON.parse(bundleJson);
    if (bundle.version !== 1) {
      return { credentials: null, error: 'Unsupported sync bundle version' };
    }

    const salt = new Uint8Array(base64ToArrayBuffer(bundle.salt));
    const iv = new Uint8Array(base64ToArrayBuffer(bundle.iv));
    const ciphertext = new Uint8Array(base64ToArrayBuffer(bundle.data));
    const authTag = new Uint8Array(base64ToArrayBuffer(bundle.authTag));

    const key = await deriveSyncKey(syncPassphrase, salt);

    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, key, combined.buffer
    );

    // Verify integrity
    const hashBuf = await crypto.subtle.digest('SHA-256', decrypted);
    const actualHash = arrayBufferToBase64(hashBuf);
    if (actualHash !== bundle.integrityHash) {
      return { credentials: null, error: 'Integrity check failed' };
    }

    const json = new TextDecoder().decode(decrypted);
    const credentials = JSON.parse(json);
    return { credentials, error: null };
  } catch {
    return { credentials: null, error: 'Failed to decrypt sync bundle — wrong passphrase?' };
  }
}
