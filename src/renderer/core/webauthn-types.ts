// WebAuthn Types — FIDO2-compatible type definitions for MusiKey

export interface RelyingParty {
  id: string;      // domain-style identifier, e.g. "musikey.local"
  name: string;    // human-readable name
}

export interface PublicKeyCredentialParams {
  type: 'public-key';
  alg: -7;  // ECDSA P-256 with SHA-256 (COSE algorithm identifier)
}

// Stored per credential — the asymmetric key material
export interface MusikeyWebAuthnCredential {
  credentialId: string;          // base64url credential ID
  rpId: string;                  // relying party this credential is scoped to
  rpName: string;                // human-readable RP name
  publicKeyJwk: JsonWebKey;      // exported ECDSA P-256 public key
  encryptedPrivateKey: string;   // private key encrypted under cascaded KDF (base64)
  privateKeyIv: string;          // IV for private key encryption (base64)
  privateKeyAuthTag: string;     // auth tag for private key encryption (base64)
  privateKeySalt: string;        // salt used for KDF (base64)
  signCount: number;             // monotonic signature counter
  createdAt: number;             // registration timestamp
  discoverable: boolean;         // resident key support
  transports: string[];          // ["internal"] for software authenticator
}

// Attestation object returned during registration
export interface AttestationObject {
  fmt: 'packed';
  attStmt: {
    alg: -7;
    sig: string;   // base64 self-attestation signature
  };
  authData: string; // base64 authenticator data
}

// Authenticator data fields (binary structure breakdown)
export interface AuthenticatorDataFields {
  rpIdHash: ArrayBuffer;      // SHA-256(rpId) — 32 bytes
  flags: number;              // 1 byte: UP(0) | UV(2) | AT(6) | ED(7)
  signCount: number;          // 4 bytes big-endian
  attestedCredentialData?: {
    aaguid: ArrayBuffer;            // 16 bytes — MusiKey authenticator ID
    credentialIdLength: number;     // 2 bytes big-endian
    credentialId: ArrayBuffer;
    credentialPublicKey: ArrayBuffer; // COSE-encoded public key
  };
}

// Flag bit positions
export const FLAGS = {
  UP: 0x01,  // User Present
  UV: 0x04,  // User Verified
  AT: 0x40,  // Attested Credential Data present
  ED: 0x80,  // Extension Data present
} as const;

// MusiKey AAGUID — fixed 16-byte authenticator identifier
// SHA-256("musikey-authenticator-v1") truncated to 16 bytes
export const MUSIKEY_AAGUID = 'musikey-authn-v1';

// Registration (navigator.credentials.create equivalent)
export interface MusikeyRegistrationRequest {
  rp: RelyingParty;
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  challenge: ArrayBuffer;
  pubKeyCredParams: PublicKeyCredentialParams[];
  attestation?: 'none' | 'direct';
}

export interface MusikeyRegistrationResponse {
  id: string;          // credential ID (base64url)
  type: 'public-key';
  response: {
    clientDataJSON: string;      // base64
    attestationObject: string;   // base64 (CBOR-encoded)
  };
}

// Assertion (navigator.credentials.get equivalent)
export interface MusikeyAssertionRequest {
  rpId: string;
  challenge: ArrayBuffer;
  allowCredentials?: { id: string; type: 'public-key' }[];
}

export interface MusikeyAssertionResponse {
  id: string;          // credential ID
  type: 'public-key';
  response: {
    clientDataJSON: string;       // base64
    authenticatorData: string;    // base64
    signature: string;            // base64 (DER-encoded ECDSA)
    userHandle?: string;          // base64 user ID (discoverable credentials)
  };
}

// Assertion verification result
export interface AssertionVerifyResult {
  verified: boolean;
  newSignCount: number;
  cloneWarning: boolean;
}

// Audit log — cryptographically chained
export type AuditAction =
  | 'registration'
  | 'authentication'
  | 'auth_failure'
  | 'key_rotation'
  | 'export'
  | 'counter_mismatch'
  | 'self_destruct'
  | 'service_register'
  | 'service_auth'
  | 'service_remove';

export interface AuditLogEntry {
  timestamp: number;
  action: AuditAction;
  rpId: string;
  credentialId: string;
  userId: string;
  signCount?: number;
  detail?: string;
  prevHash: string;     // SHA-256 of previous entry (or 'genesis')
  entryHash: string;    // SHA-256 of this entry's content
}

export interface AuditChainResult {
  valid: boolean;
  brokenAt?: number;
}

export interface AuditSummary {
  totalAuths: number;
  totalFailures: number;
  lastAuthTime: number | null;
  registrationCount: number;
  cloneWarnings: number;
  chainValid: boolean;
}
