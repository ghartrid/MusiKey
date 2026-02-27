// MusiKey Protocol — ECDSA Challenge-Response Authentication Engine
// Reuses existing WebAuthn crypto primitives for key generation, signing, verification.
// Each service gets its own ECDSA P-256 keypair, encrypted under the user's passphrase.

import {
  PROTOKEY_VERSION,
  ServiceRegistration,
  ProtocolChallenge,
  ProtocolAssertion,
  ProtocolRegistrationResponse,
  ProtocolVerifyResult,
  ParsedProtocolUri,
} from './protokey-types';

import {
  generateKeyPair,
  exportPublicKeyJwk,
  encryptPrivateKey,
  decryptPrivateKey,
  signChallenge as ecdsaSign,
  verifySignature,
  generateCredentialId,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  toBase64Url,
  fromBase64Url,
} from './webauthn-crypto';

// --- Registration ---

export async function registerWithService(
  rpId: string,
  serviceName: string,
  userId: string,
  passphrase: string,
  iterations: number,
  endpoint?: string
): Promise<{ registration: ServiceRegistration; response: ProtocolRegistrationResponse }> {
  // Generate dedicated keypair for this service
  const keyPair = await generateKeyPair();
  const publicKeyJwk = await exportPublicKeyJwk(keyPair.publicKey);

  // Generate credential ID
  const credentialId = await generateCredentialId(rpId, userId);

  // Encrypt private key under cascaded KDF
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  const encrypted = await encryptPrivateKey(keyPair.privateKey, passphrase, salt, iterations);

  // Build self-attestation: sign(rpId + userId + credentialId)
  const attestData = new TextEncoder().encode(`${rpId}:${userId}:${credentialId}`);
  const attestSig = await ecdsaSign(keyPair.privateKey, attestData.buffer as ArrayBuffer);
  const attestation = toBase64Url(arrayBufferToBase64(attestSig));

  // Build service registration record
  const serviceId = await generateCredentialId(rpId, `service-${Date.now()}`);

  const registration: ServiceRegistration = {
    serviceId,
    serviceName,
    rpId,
    userId,
    credentialId,
    publicKeyJwk,
    encryptedPrivateKey: encrypted.encryptedKey,
    privateKeyIv: encrypted.iv,
    privateKeyAuthTag: encrypted.authTag,
    privateKeySalt: encrypted.salt,
    signCount: 0,
    registeredAt: Date.now(),
    lastAuthAt: null,
    endpoint,
  };

  // Build protocol registration response
  const response: ProtocolRegistrationResponse = {
    protocol: PROTOKEY_VERSION,
    type: 'registration',
    rpId,
    userId,
    publicKeyJwk,
    credentialId,
    attestation,
  };

  // If endpoint provided, POST registration
  if (endpoint) {
    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(response),
      });
    } catch {
      // Registration saved locally even if remote POST fails
    }
  }

  return { registration, response };
}

// --- Challenge Signing ---

export async function signProtocolChallenge(
  challenge: ProtocolChallenge,
  service: ServiceRegistration,
  passphrase: string,
  iterations: number
): Promise<{ assertion: ProtocolAssertion; newSignCount: number }> {
  // Verify rpId matches service
  if (challenge.rpId !== service.rpId) {
    throw new Error(`rpId mismatch: challenge=${challenge.rpId}, service=${service.rpId}`);
  }

  // Decrypt private key
  const privateKey = await decryptPrivateKey(
    {
      encryptedKey: service.encryptedPrivateKey,
      iv: service.privateKeyIv,
      authTag: service.privateKeyAuthTag,
      salt: service.privateKeySalt,
    },
    passphrase,
    iterations
  );

  // Increment sign count
  const newSignCount = service.signCount + 1;

  // Build signing payload: SHA-256(challenge + rpId + nonce + timestamp)
  const payloadStr = `${challenge.challenge}:${challenge.rpId}:${challenge.nonce}:${challenge.timestamp}`;
  const payloadBytes = new TextEncoder().encode(payloadStr);
  const payloadHash = await crypto.subtle.digest('SHA-256', payloadBytes);

  // Sign with ECDSA P-256
  const signature = await ecdsaSign(privateKey, payloadHash);
  const signatureB64 = toBase64Url(arrayBufferToBase64(signature));

  const assertion: ProtocolAssertion = {
    protocol: PROTOKEY_VERSION,
    type: 'assertion',
    rpId: challenge.rpId,
    challenge: challenge.challenge,
    signature: signatureB64,
    publicKeyId: service.credentialId,
    signCount: newSignCount,
    timestamp: Math.floor(Date.now() / 1000),
  };

  // If callback URL provided, POST assertion
  if (challenge.callback) {
    try {
      await fetch(challenge.callback, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertion),
      });
    } catch {
      // Assertion available locally even if callback fails
    }
  }

  return { assertion, newSignCount };
}

// --- Assertion Verification (client-side / for testing) ---

export async function verifyProtocolAssertion(
  assertion: ProtocolAssertion,
  publicKeyJwk: JsonWebKey,
  expectedChallenge: string,
  rpId: string,
  expectedSignCount: number,
  nonce: string,
  challengeTimestamp: number
): Promise<ProtocolVerifyResult> {
  // Check protocol version
  if (assertion.protocol !== PROTOKEY_VERSION) {
    return { verified: false, newSignCount: assertion.signCount, cloneWarning: false, error: 'Invalid protocol version' };
  }

  // Check challenge matches
  if (assertion.challenge !== expectedChallenge) {
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

  // Clone detection: signCount must be strictly greater than expected
  const cloneWarning = assertion.signCount <= expectedSignCount;

  // Rebuild signing payload
  const payloadStr = `${expectedChallenge}:${rpId}:${nonce}:${challengeTimestamp}`;
  const payloadBytes = new TextEncoder().encode(payloadStr);
  const payloadHash = await crypto.subtle.digest('SHA-256', payloadBytes);

  // Decode signature from base64url
  const sigB64 = fromBase64Url(assertion.signature);
  const sigBytes = base64ToArrayBuffer(sigB64);

  // Verify ECDSA signature
  const verified = await verifySignature(publicKeyJwk, sigBytes, payloadHash);

  return {
    verified,
    newSignCount: assertion.signCount,
    cloneWarning,
    error: verified ? undefined : 'Signature verification failed',
  };
}

// --- URI Parsing ---

export function parseProtocolUri(uri: string): ParsedProtocolUri | null {
  try {
    // Support musikey://register?... and musikey://auth?...
    // Also support plain query strings and JSON
    let url: URL;

    if (uri.startsWith('musikey://')) {
      // Convert musikey:// to https:// for URL parsing
      // musikey://register?... → https://register?... so hostname = 'register' or 'auth'
      url = new URL(uri.replace('musikey://', 'https://'));
    } else if (uri.startsWith('{')) {
      // JSON format
      const json = JSON.parse(uri);
      if (json.type === 'challenge') {
        return {
          type: 'auth',
          rpId: json.rpId,
          challenge: json.challenge,
          nonce: json.nonce,
          callback: json.callback,
        };
      } else if (json.type === 'register') {
        return {
          type: 'register',
          rpId: json.rpId,
          serviceName: json.serviceName,
          userId: json.userId,
          challenge: json.challenge,
          endpoint: json.endpoint,
        };
      }
      return null;
    } else {
      return null;
    }

    const type = url.hostname as 'register' | 'auth';
    if (type !== 'register' && type !== 'auth') return null;

    const params = url.searchParams;
    return {
      type,
      rpId: params.get('rpId') || params.get('service') || '',
      serviceName: params.get('service') || params.get('serviceName') || undefined,
      userId: params.get('userId') || undefined,
      challenge: params.get('challenge') || undefined,
      nonce: params.get('nonce') || undefined,
      endpoint: params.get('endpoint') || undefined,
      callback: params.get('callback') || undefined,
    };
  } catch {
    return null;
  }
}

export function buildProtocolUri(
  type: 'register' | 'auth',
  params: Record<string, string>
): string {
  const url = new URL(`musikey://${type}`);
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value);
  }
  return url.toString();
}

// --- Challenge Generation ---

export function generateProtocolChallenge(rpId: string, callback?: string): ProtocolChallenge {
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);

  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);

  return {
    protocol: PROTOKEY_VERSION,
    type: 'challenge',
    rpId,
    challenge: toBase64Url(arrayBufferToBase64(challengeBytes.buffer as ArrayBuffer)),
    nonce: Array.from(nonceBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
    timestamp: Math.floor(Date.now() / 1000),
    callback,
  };
}
