// MusiKey Protocol — Server-Side Verification Utility
// Verifies ECDSA P-256 challenge-response assertions from MusiKey clients.
// Reusable by any Node.js server adopting the MusiKey protocol.

import * as crypto from 'crypto';

const PROTOKEY_VERSION = 'musikey-v1';

// --- Base64URL utilities ---

function toBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(b64url: string): Buffer {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}

// --- Challenge Generation ---

export interface MusiKeyChallenge {
  protocol: 'musikey-v1';
  type: 'challenge';
  rpId: string;
  challenge: string;   // base64url
  nonce: string;       // hex
  timestamp: number;
  callback?: string;
}

export function generateMusiKeyChallenge(rpId: string, callback?: string): MusiKeyChallenge {
  const challenge = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(16);

  return {
    protocol: PROTOKEY_VERSION,
    type: 'challenge',
    rpId,
    challenge: toBase64Url(challenge),
    nonce: nonce.toString('hex'),
    timestamp: Math.floor(Date.now() / 1000),
    callback,
  };
}

// --- URI Building ---

export function buildMusiKeyUri(
  type: 'register' | 'auth',
  params: Record<string, string>
): string {
  const parts = Object.entries(params)
    .filter(([, v]) => v)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  return `musikey://${type}?${parts}`;
}

// --- Assertion Verification ---

export interface MusiKeyAssertion {
  protocol: 'musikey-v1';
  type: 'assertion';
  rpId: string;
  challenge: string;
  signature: string;    // base64url
  publicKeyId: string;
  signCount: number;
  timestamp: number;
}

export interface MusiKeyVerifyResult {
  verified: boolean;
  newSignCount: number;
  cloneWarning: boolean;
  error?: string;
}

export function verifyMusiKeyAssertion(
  assertion: MusiKeyAssertion,
  publicKeyJwk: { kty?: string; crv?: string; x?: string; y?: string; [key: string]: any },
  challenge: MusiKeyChallenge,
  rpId: string,
  lastSignCount: number
): MusiKeyVerifyResult {
  try {
    // Check protocol version
    if (assertion.protocol !== PROTOKEY_VERSION) {
      return { verified: false, newSignCount: assertion.signCount, cloneWarning: false, error: 'Invalid protocol version' };
    }

    // Check challenge matches
    if (assertion.challenge !== challenge.challenge) {
      return { verified: false, newSignCount: assertion.signCount, cloneWarning: false, error: 'Challenge mismatch' };
    }

    // Check rpId matches
    if (assertion.rpId !== rpId) {
      return { verified: false, newSignCount: assertion.signCount, cloneWarning: false, error: 'rpId mismatch' };
    }

    // Check timestamp within 5-minute window
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - assertion.timestamp) > 300) {
      return { verified: false, newSignCount: assertion.signCount, cloneWarning: false, error: 'Assertion expired' };
    }

    // Clone detection
    const cloneWarning = assertion.signCount <= lastSignCount;

    // Rebuild signing payload: SHA-256(challenge + rpId + nonce + timestamp)
    const payloadStr = `${challenge.challenge}:${challenge.rpId}:${challenge.nonce}:${challenge.timestamp}`;
    const payloadHash = crypto.createHash('sha256').update(payloadStr).digest();

    // Import public key from JWK
    const keyObject = crypto.createPublicKey({
      key: { kty: publicKeyJwk.kty, crv: publicKeyJwk.crv, x: publicKeyJwk.x, y: publicKeyJwk.y },
      format: 'jwk',
    });

    // Decode signature from base64url
    const signatureBuf = fromBase64Url(assertion.signature);

    // Verify ECDSA P-256 signature (ieee-p1363 = raw r||s format from Web Crypto)
    const verified = crypto.verify(
      'SHA256',
      payloadHash,
      { key: keyObject, dsaEncoding: 'ieee-p1363' },
      signatureBuf
    );

    return {
      verified,
      newSignCount: assertion.signCount,
      cloneWarning,
      error: verified ? undefined : 'Signature verification failed',
    };
  } catch (err: any) {
    return { verified: false, newSignCount: assertion.signCount, cloneWarning: false, error: err.message };
  }
}

// --- Registration Verification ---

export interface MusiKeyRegistration {
  protocol: 'musikey-v1';
  type: 'registration';
  rpId: string;
  userId: string;
  publicKeyJwk: { kty?: string; crv?: string; x?: string; y?: string; [key: string]: any };
  credentialId: string;
  attestation: string;  // base64url self-signed attestation
}

export function verifyMusiKeyRegistration(
  registration: MusiKeyRegistration,
  rpId: string
): { verified: boolean; error?: string } {
  try {
    if (registration.protocol !== PROTOKEY_VERSION) {
      return { verified: false, error: 'Invalid protocol version' };
    }

    if (registration.rpId !== rpId) {
      return { verified: false, error: 'rpId mismatch' };
    }

    // Verify self-attestation: sig(rpId + userId + credentialId) with public key
    const attestData = Buffer.from(`${registration.rpId}:${registration.userId}:${registration.credentialId}`);

    const keyObject = crypto.createPublicKey({
      key: {
        kty: registration.publicKeyJwk.kty,
        crv: registration.publicKeyJwk.crv,
        x: registration.publicKeyJwk.x,
        y: registration.publicKeyJwk.y,
      },
      format: 'jwk',
    });

    const attestSig = fromBase64Url(registration.attestation);

    const verified = crypto.verify(
      'SHA256',
      attestData,
      { key: keyObject, dsaEncoding: 'ieee-p1363' },
      attestSig
    );

    return { verified, error: verified ? undefined : 'Attestation signature invalid' };
  } catch (err: any) {
    return { verified: false, error: err.message };
  }
}
