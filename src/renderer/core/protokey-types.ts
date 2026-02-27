// MusiKey Protocol — ECDSA Challenge-Response Authentication Protocol Types
// Unlike TOTP (shared secret, 6-digit code), MusiKey Protocol uses asymmetric
// ECDSA P-256 signatures bound to service origin. Non-replayable, non-phishable.

export const PROTOKEY_VERSION = 'musikey-v1';

// --- Service Registration (stored per credential) ---

export interface ServiceRegistration {
  serviceId: string;              // unique ID for this registration (base64url)
  serviceName: string;            // human-readable service name
  rpId: string;                   // relying party domain (e.g. "example.com")
  userId: string;                 // user identifier at the service
  credentialId: string;           // base64url credential ID
  publicKeyJwk: JsonWebKey;       // ECDSA P-256 public key
  encryptedPrivateKey: string;    // private key encrypted under cascaded KDF (base64)
  privateKeyIv: string;           // IV for encryption (base64)
  privateKeyAuthTag: string;      // auth tag (base64)
  privateKeySalt: string;         // KDF salt (base64)
  signCount: number;              // monotonic signature counter
  registeredAt: number;           // registration timestamp
  lastAuthAt: number | null;      // last authentication timestamp
  endpoint?: string;              // optional service endpoint URL
}

// --- Protocol Messages ---

export interface ProtocolChallenge {
  protocol: 'musikey-v1';
  type: 'challenge';
  rpId: string;
  challenge: string;              // base64url 32-byte challenge
  nonce: string;                  // hex 16-byte nonce
  timestamp: number;
  callback?: string;              // URL to POST assertion to
}

export interface ProtocolAssertion {
  protocol: 'musikey-v1';
  type: 'assertion';
  rpId: string;
  challenge: string;              // echoed from challenge
  signature: string;              // base64url ECDSA P-256 signature
  publicKeyId: string;            // credentialId
  signCount: number;
  timestamp: number;
}

export interface ProtocolRegistrationRequest {
  protocol: 'musikey-v1';
  type: 'register';
  rpId: string;
  serviceName: string;
  userId: string;
  challenge?: string;             // optional registration challenge
  endpoint?: string;              // where to POST public key
}

export interface ProtocolRegistrationResponse {
  protocol: 'musikey-v1';
  type: 'registration';
  rpId: string;
  userId: string;
  publicKeyJwk: JsonWebKey;
  credentialId: string;
  attestation: string;            // base64url self-signed attestation
}

// --- Verification ---

export interface ProtocolVerifyResult {
  verified: boolean;
  newSignCount: number;
  cloneWarning: boolean;
  error?: string;
}

// --- URI Parsing ---

export type ProtocolUriType = 'register' | 'auth';

export interface ParsedProtocolUri {
  type: ProtocolUriType;
  rpId: string;
  serviceName?: string;
  userId?: string;
  challenge?: string;
  nonce?: string;
  endpoint?: string;
  callback?: string;
}
