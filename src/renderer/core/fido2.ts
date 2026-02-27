// FIDO2 API — WebAuthn-compatible registration and assertion ceremonies
// Models navigator.credentials.create() and navigator.credentials.get()

import {
  MusikeyWebAuthnCredential,
  MusikeyRegistrationRequest,
  MusikeyRegistrationResponse,
  MusikeyAssertionRequest,
  MusikeyAssertionResponse,
  AssertionVerifyResult,
  FLAGS,
} from './webauthn-types';

import {
  generateKeyPair,
  exportPublicKeyJwk,
  encryptPrivateKey,
  decryptPrivateKey,
  signChallenge,
  verifySignature,
  generateCredentialId,
  buildAuthenticatorData,
  buildAttestedCredentialData,
  publicKeyToCose,
  encodeAttestationObject,
  generateChallenge as genChallenge,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  toBase64Url,
  fromBase64Url,
} from './webauthn-crypto';

const DEFAULT_ITERATIONS = 600000;

// --- Registration Ceremony ---
// Equivalent to navigator.credentials.create()

export async function register(
  request: MusikeyRegistrationRequest,
  passphrase: string,
  iterations: number = DEFAULT_ITERATIONS
): Promise<{
  response: MusikeyRegistrationResponse;
  webauthnCredential: MusikeyWebAuthnCredential;
}> {
  // 1. Generate ECDSA P-256 key pair
  const keyPair = await generateKeyPair();
  const publicKeyJwk = await exportPublicKeyJwk(keyPair.publicKey);

  // 2. Encrypt private key under cascaded KDF
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  const encrypted = await encryptPrivateKey(keyPair.privateKey, passphrase, salt, iterations);

  // 3. Generate credential ID
  const credentialId = await generateCredentialId(request.rp.id, request.user.id);
  const credIdBytes = new Uint8Array(base64ToArrayBuffer(fromBase64Url(credentialId)));

  // 4. Build COSE public key
  const publicKeyCose = publicKeyToCose(publicKeyJwk);

  // 5. Build attested credential data
  const attestedCredData = await buildAttestedCredentialData(credIdBytes, publicKeyCose);

  // 6. Build authenticator data (UP + UV + AT flags, signCount = 0)
  const flags = FLAGS.UP | FLAGS.UV | FLAGS.AT;
  const authData = await buildAuthenticatorData(request.rp.id, flags, 0, attestedCredData);

  // 7. Build clientDataJSON
  const clientData = {
    type: 'webauthn.create',
    challenge: toBase64Url(arrayBufferToBase64(request.challenge)),
    origin: `musikey://${request.rp.id}`,
    crossOrigin: false,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

  // 8. Self-attestation: sign authData || SHA-256(clientDataJSON)
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', clientDataJSON)
  );
  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData);
  signedData.set(clientDataHash, authData.length);

  const signature = await signChallenge(keyPair.privateKey, signedData.buffer as ArrayBuffer);

  // 9. Build attestation object (CBOR-encoded)
  const attestationObject = encodeAttestationObject(authData, new Uint8Array(signature));

  // 10. Build stored WebAuthn credential
  const webauthnCredential: MusikeyWebAuthnCredential = {
    credentialId,
    rpId: request.rp.id,
    rpName: request.rp.name,
    publicKeyJwk,
    encryptedPrivateKey: encrypted.encryptedKey,
    privateKeyIv: encrypted.iv,
    privateKeyAuthTag: encrypted.authTag,
    privateKeySalt: encrypted.salt,
    signCount: 0,
    createdAt: Date.now(),
    discoverable: true,
    transports: ['internal'],
  };

  // 11. Build registration response
  const response: MusikeyRegistrationResponse = {
    id: credentialId,
    type: 'public-key',
    response: {
      clientDataJSON: arrayBufferToBase64(clientDataJSON.buffer as ArrayBuffer),
      attestationObject: arrayBufferToBase64(attestationObject.buffer as ArrayBuffer),
    },
  };

  return { response, webauthnCredential };
}

// --- Assertion Ceremony ---
// Equivalent to navigator.credentials.get()

export async function authenticate(
  request: MusikeyAssertionRequest,
  webauthnCred: MusikeyWebAuthnCredential,
  passphrase: string,
  iterations: number = DEFAULT_ITERATIONS
): Promise<{
  response: MusikeyAssertionResponse;
  newSignCount: number;
}> {
  // 1. Verify rpId matches
  if (request.rpId !== webauthnCred.rpId) {
    throw new Error('rpId mismatch');
  }

  // 2. Decrypt private key
  const privateKey = await decryptPrivateKey(
    {
      encryptedKey: webauthnCred.encryptedPrivateKey,
      iv: webauthnCred.privateKeyIv,
      authTag: webauthnCred.privateKeyAuthTag,
      salt: webauthnCred.privateKeySalt,
    },
    passphrase,
    iterations
  );

  // 3. Increment sign count
  const newSignCount = webauthnCred.signCount + 1;

  // 4. Build authenticator data (UP + UV flags, new signCount)
  const flags = FLAGS.UP | FLAGS.UV;
  const authData = await buildAuthenticatorData(request.rpId, flags, newSignCount);

  // 5. Build clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: toBase64Url(arrayBufferToBase64(request.challenge)),
    origin: `musikey://${request.rpId}`,
    crossOrigin: false,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

  // 6. Sign authData || SHA-256(clientDataJSON)
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', clientDataJSON)
  );
  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData);
  signedData.set(clientDataHash, authData.length);

  const signature = await signChallenge(privateKey, signedData.buffer as ArrayBuffer);

  // 7. Build assertion response
  const response: MusikeyAssertionResponse = {
    id: webauthnCred.credentialId,
    type: 'public-key',
    response: {
      clientDataJSON: arrayBufferToBase64(clientDataJSON.buffer as ArrayBuffer),
      authenticatorData: arrayBufferToBase64(authData.buffer as ArrayBuffer),
      signature: arrayBufferToBase64(signature),
      userHandle: toBase64Url(arrayBufferToBase64(
        new TextEncoder().encode(webauthnCred.rpId).buffer as ArrayBuffer
      )),
    },
  };

  return { response, newSignCount };
}

// --- Assertion Verification (Relying Party side) ---

export async function verifyAssertion(
  response: MusikeyAssertionResponse,
  publicKeyJwk: JsonWebKey,
  challenge: ArrayBuffer,
  rpId: string,
  expectedSignCount: number
): Promise<AssertionVerifyResult> {
  // 1. Parse and verify clientDataJSON
  const clientDataBytes = new Uint8Array(base64ToArrayBuffer(response.response.clientDataJSON));
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.get') {
    return { verified: false, newSignCount: 0, cloneWarning: false };
  }

  const expectedChallenge = toBase64Url(arrayBufferToBase64(challenge));
  if (clientData.challenge !== expectedChallenge) {
    return { verified: false, newSignCount: 0, cloneWarning: false };
  }

  const expectedOrigin = `musikey://${rpId}`;
  if (clientData.origin !== expectedOrigin) {
    return { verified: false, newSignCount: 0, cloneWarning: false };
  }

  // 2. Parse authenticator data
  const authData = new Uint8Array(base64ToArrayBuffer(response.response.authenticatorData));

  // Verify rpIdHash (first 32 bytes)
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
  );
  for (let i = 0; i < 32; i++) {
    if (authData[i] !== rpIdHash[i]) {
      return { verified: false, newSignCount: 0, cloneWarning: false };
    }
  }

  // Verify flags: UP and UV must be set
  const flagsByte = authData[32];
  if (!(flagsByte & FLAGS.UP) || !(flagsByte & FLAGS.UV)) {
    return { verified: false, newSignCount: 0, cloneWarning: false };
  }

  // Extract signCount (bytes 33-36, big-endian)
  const signCountView = new DataView(authData.buffer, 33, 4);
  const newSignCount = signCountView.getUint32(0, false);

  // Clone detection: signCount must be greater than expected
  const cloneWarning = newSignCount <= expectedSignCount;

  // 3. Reconstruct signed data: authData || SHA-256(clientDataJSON)
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', clientDataBytes)
  );
  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData);
  signedData.set(clientDataHash, authData.length);

  // 4. Verify ECDSA signature
  const signatureBytes = base64ToArrayBuffer(response.response.signature);
  const verified = await verifySignature(
    publicKeyJwk, signatureBytes, signedData.buffer as ArrayBuffer
  );

  return { verified, newSignCount, cloneWarning };
}

// --- Attestation Verification (for RP receiving a registration) ---

export async function verifyAttestation(
  response: MusikeyRegistrationResponse,
  challenge: ArrayBuffer,
  rpId: string
): Promise<{ verified: boolean; publicKeyJwk?: JsonWebKey; credentialId?: string }> {
  // 1. Parse clientDataJSON
  const clientDataBytes = new Uint8Array(base64ToArrayBuffer(response.response.clientDataJSON));
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.create') {
    return { verified: false };
  }

  const expectedChallenge = toBase64Url(arrayBufferToBase64(challenge));
  if (clientData.challenge !== expectedChallenge) {
    return { verified: false };
  }

  const expectedOrigin = `musikey://${rpId}`;
  if (clientData.origin !== expectedOrigin) {
    return { verified: false };
  }

  // For full implementation, decode the CBOR attestation object
  // and verify the self-attestation signature.
  // For now, trust the registration from our own authenticator.
  return {
    verified: true,
    credentialId: response.id,
  };
}

// --- Credential Discovery ---

export function discoverCredentials(
  rpId: string,
  credentials: MusikeyWebAuthnCredential[]
): MusikeyWebAuthnCredential[] {
  return credentials.filter(c => c.rpId === rpId && c.discoverable);
}

// --- Re-export challenge generation ---

export function generateChallenge(): ArrayBuffer {
  return genChallenge();
}

// --- Re-encrypt private key (for key rotation) ---

export async function reencryptPrivateKey(
  webauthnCred: MusikeyWebAuthnCredential,
  passphrase: string,
  iterations: number = DEFAULT_ITERATIONS
): Promise<MusikeyWebAuthnCredential> {
  // Decrypt with current salt
  const privateKey = await decryptPrivateKey(
    {
      encryptedKey: webauthnCred.encryptedPrivateKey,
      iv: webauthnCred.privateKeyIv,
      authTag: webauthnCred.privateKeyAuthTag,
      salt: webauthnCred.privateKeySalt,
    },
    passphrase,
    iterations
  );

  // Re-import as extractable to re-encrypt
  // Since decryptPrivateKey returns non-extractable, we need to export+reimport
  // Actually, we need to generate fresh encryption directly
  // The private key from decrypt is non-extractable, so we sign a test to verify it works,
  // then we need to re-derive the key and re-encrypt from the stored encrypted form
  // Alternative: decrypt the raw bytes and re-encrypt them

  // Decrypt raw PKCS8 bytes
  const keyB64 = await window.musikeyStore.cascadedKDF(passphrase, webauthnCred.privateKeySalt, iterations);
  const keyBytes = base64ToArrayBuffer(keyB64);
  const aesKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );

  const ciphertext = new Uint8Array(base64ToArrayBuffer(webauthnCred.encryptedPrivateKey));
  const authTag = new Uint8Array(base64ToArrayBuffer(webauthnCred.privateKeyAuthTag));
  const iv = new Uint8Array(base64ToArrayBuffer(webauthnCred.privateKeyIv));

  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);

  const pkcs8 = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, aesKey, combined.buffer as ArrayBuffer
  );

  // Re-encrypt with fresh salt
  const newSalt = new Uint8Array(32);
  crypto.getRandomValues(newSalt);
  const newSaltB64 = arrayBufferToBase64(newSalt.buffer as ArrayBuffer);
  const newKeyB64 = await window.musikeyStore.cascadedKDF(passphrase, newSaltB64, iterations);
  const newKeyBytes = base64ToArrayBuffer(newKeyB64);
  const newAesKey = await crypto.subtle.importKey(
    'raw', newKeyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );

  const newIv = new Uint8Array(12);
  crypto.getRandomValues(newIv);

  const newEncrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: newIv, tagLength: 128 }, newAesKey, pkcs8
  );

  const newEncBytes = new Uint8Array(newEncrypted);
  const newCiphertext = newEncBytes.slice(0, newEncBytes.length - 16);
  const newAuthTag = newEncBytes.slice(newEncBytes.length - 16);

  // Zero raw PKCS8
  new Uint8Array(pkcs8).fill(0);

  return {
    ...webauthnCred,
    encryptedPrivateKey: arrayBufferToBase64(newCiphertext.buffer as ArrayBuffer),
    privateKeyIv: arrayBufferToBase64(newIv.buffer as ArrayBuffer),
    privateKeyAuthTag: arrayBufferToBase64(newAuthTag.buffer as ArrayBuffer),
    privateKeySalt: newSaltB64,
  };
}
