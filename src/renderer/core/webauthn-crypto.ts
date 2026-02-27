// WebAuthn Crypto — ECDSA P-256 key management, authenticator data, minimal CBOR
// Uses Web Crypto API exclusively (renderer process)

import { FLAGS, MUSIKEY_AAGUID } from './webauthn-types';

// --- Base64 / Base64URL utilities ---

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

export function toBase64Url(b64: string): string {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(b64url: string): string {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return b64;
}

function zeroBuffer(buf: Uint8Array): void {
  buf.fill(0);
}

// --- ECDSA P-256 Key Operations ---

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable — needed for encrypted storage
    ['sign', 'verify']
  );
}

export async function exportPublicKeyJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', publicKey);
}

export async function encryptPrivateKey(
  privateKey: CryptoKey,
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<{ encryptedKey: string; iv: string; authTag: string; salt: string }> {
  // Export private key as PKCS8
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  const pkcs8Bytes = new Uint8Array(pkcs8);

  // Derive AES key using same cascaded KDF as song encryption
  const saltB64 = arrayBufferToBase64(salt.buffer as ArrayBuffer);
  const keyB64 = await window.musikeyStore.cascadedKDF(passphrase, saltB64, iterations);
  const keyBytes = base64ToArrayBuffer(keyB64);
  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );

  // Encrypt private key
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, aesKey, pkcs8Bytes.buffer as ArrayBuffer
  );

  const encBytes = new Uint8Array(encrypted);
  const ciphertext = encBytes.slice(0, encBytes.length - 16);
  const authTag = encBytes.slice(encBytes.length - 16);

  // Zero sensitive material
  zeroBuffer(pkcs8Bytes);

  return {
    encryptedKey: arrayBufferToBase64(ciphertext.buffer as ArrayBuffer),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
    authTag: arrayBufferToBase64(authTag.buffer as ArrayBuffer),
    salt: saltB64,
  };
}

export async function decryptPrivateKey(
  encryptedData: { encryptedKey: string; iv: string; authTag: string; salt: string },
  passphrase: string,
  iterations: number
): Promise<CryptoKey> {
  // Derive AES key
  const keyB64 = await window.musikeyStore.cascadedKDF(passphrase, encryptedData.salt, iterations);
  const keyBytes = base64ToArrayBuffer(keyB64);
  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );

  // Reconstruct ciphertext + auth tag
  const ciphertext = new Uint8Array(base64ToArrayBuffer(encryptedData.encryptedKey));
  const authTag = new Uint8Array(base64ToArrayBuffer(encryptedData.authTag));
  const iv = new Uint8Array(base64ToArrayBuffer(encryptedData.iv));

  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);

  const pkcs8 = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, aesKey, combined.buffer as ArrayBuffer
  );

  // Import as non-extractable for defense in depth
  const key = await crypto.subtle.importKey(
    'pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );

  // Zero the raw PKCS8 bytes
  zeroBuffer(new Uint8Array(pkcs8));

  return key;
}

export async function signChallenge(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privateKey, data
  );
}

export async function verifySignature(
  publicKeyJwk: JsonWebKey,
  signature: ArrayBuffer,
  data: ArrayBuffer
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    'jwk', publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
  );
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, data
  );
}

// --- Credential ID Generation ---

export async function generateCredentialId(rpId: string, userId: string): Promise<string> {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const enc = new TextEncoder();
  const data = new Uint8Array([
    ...enc.encode(rpId),
    ...enc.encode(userId),
    ...random,
  ]);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return toBase64Url(arrayBufferToBase64(hash));
}

// --- Authenticator Data Construction ---

export async function buildAuthenticatorData(
  rpId: string,
  flags: number,
  signCount: number,
  attestedCredentialData?: Uint8Array
): Promise<Uint8Array> {
  // rpIdHash: SHA-256(rpId) = 32 bytes
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
  );

  // Base size: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37
  const baseSize = 37;
  const attestedSize = attestedCredentialData ? attestedCredentialData.length : 0;
  const authData = new Uint8Array(baseSize + attestedSize);

  // rpIdHash (32 bytes)
  authData.set(rpIdHash, 0);

  // Flags (1 byte)
  authData[32] = flags;

  // signCount (4 bytes, big-endian)
  const view = new DataView(authData.buffer);
  view.setUint32(33, signCount, false); // big-endian

  // Attested credential data (optional)
  if (attestedCredentialData) {
    authData.set(attestedCredentialData, 37);
  }

  return authData;
}

export async function buildAttestedCredentialData(
  credentialId: Uint8Array,
  publicKeyCose: Uint8Array
): Promise<Uint8Array> {
  // AAGUID: 16 bytes — SHA-256 of MUSIKEY_AAGUID truncated
  const aaguidHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(MUSIKEY_AAGUID))
  );
  const aaguid = aaguidHash.slice(0, 16);

  // credentialIdLength: 2 bytes big-endian
  const result = new Uint8Array(16 + 2 + credentialId.length + publicKeyCose.length);
  result.set(aaguid, 0);

  const lenView = new DataView(result.buffer);
  lenView.setUint16(16, credentialId.length, false); // big-endian

  result.set(credentialId, 18);
  result.set(publicKeyCose, 18 + credentialId.length);

  return result;
}

// --- Minimal CBOR Encoder ---
// Only supports the structures needed for COSE keys and attestation objects.
// Handles: unsigned ints, negative ints, byte strings, text strings, arrays, maps.

function cborEncodeUint(major: number, value: number): Uint8Array {
  const majorBits = major << 5;
  if (value < 24) {
    return new Uint8Array([majorBits | value]);
  } else if (value < 256) {
    return new Uint8Array([majorBits | 24, value]);
  } else if (value < 65536) {
    const buf = new Uint8Array(3);
    buf[0] = majorBits | 25;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = value & 0xff;
    return buf;
  } else {
    const buf = new Uint8Array(5);
    buf[0] = majorBits | 26;
    buf[1] = (value >> 24) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 8) & 0xff;
    buf[4] = value & 0xff;
    return buf;
  }
}

function cborEncodeNegInt(value: number): Uint8Array {
  // CBOR negative int: -1 - n, where n is the encoded uint
  return cborEncodeUint(1, -value - 1);
}

function cborEncodeBytes(data: Uint8Array): Uint8Array {
  const header = cborEncodeUint(2, data.length);
  const result = new Uint8Array(header.length + data.length);
  result.set(header);
  result.set(data, header.length);
  return result;
}

function cborEncodeText(text: string): Uint8Array {
  const encoded = new TextEncoder().encode(text);
  const header = cborEncodeUint(3, encoded.length);
  const result = new Uint8Array(header.length + encoded.length);
  result.set(header);
  result.set(encoded, header.length);
  return result;
}

function cborConcat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

// Encode a COSE EC2 public key (P-256, ECDSA-SHA256)
// Map: { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
export function publicKeyToCose(jwk: JsonWebKey): Uint8Array {
  const x = new Uint8Array(base64ToArrayBuffer(fromBase64Url(jwk.x!)));
  const y = new Uint8Array(base64ToArrayBuffer(fromBase64Url(jwk.y!)));

  return cborConcat(
    cborEncodeUint(5, 5), // map of 5 items
    cborEncodeUint(0, 1), cborEncodeUint(0, 2),       // 1: 2 (kty: EC2)
    cborEncodeUint(0, 3), cborEncodeNegInt(-7),        // 3: -7 (alg: ES256)
    cborEncodeNegInt(-1), cborEncodeUint(0, 1),        // -1: 1 (crv: P-256)
    cborEncodeNegInt(-2), cborEncodeBytes(x),          // -2: x coordinate
    cborEncodeNegInt(-3), cborEncodeBytes(y),          // -3: y coordinate
  );
}

// Encode attestation object: { fmt: "packed", attStmt: { alg: -7, sig: bytes }, authData: bytes }
export function encodeAttestationObject(
  authData: Uint8Array,
  signature: Uint8Array
): Uint8Array {
  return cborConcat(
    cborEncodeUint(5, 3), // map of 3 items
    cborEncodeText('fmt'), cborEncodeText('packed'),
    cborEncodeText('attStmt'), cborConcat(
      cborEncodeUint(5, 1), // map of 1 item (alg is implied by packed self-attestation)
      cborEncodeText('sig'), cborEncodeBytes(signature),
    ),
    cborEncodeText('authData'), cborEncodeBytes(authData),
  );
}

// --- Challenge Generation ---

export function generateChallenge(): ArrayBuffer {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  return challenge.buffer as ArrayBuffer;
}

// --- Utility Exports ---

export { arrayBufferToBase64, base64ToArrayBuffer };
