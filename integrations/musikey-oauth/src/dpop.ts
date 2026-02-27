// DPoP (Demonstration of Proof-of-Possession) — RFC 9449
// Binds OAuth2 tokens to a client's key pair so stolen tokens are useless

import * as crypto from 'crypto';

// --- Base64URL utilities ---

function toBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(b64url: string): Buffer {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}

// --- JWK Thumbprint (RFC 7638) ---

export function computeJwkThumbprint(jwk: { kty?: string; crv?: string; x?: string; y?: string }): string {
  // For EC keys: JSON with lexicographically sorted members { crv, kty, x, y }
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return toBase64Url(crypto.createHash('sha256').update(canonical).digest());
}

// --- DPoP Proof Verification ---

export interface DPoPVerifyResult {
  valid: boolean;
  jwkThumbprint: string;
  error?: string;
}

export function verifyDPoPProof(
  proof: string,
  method: string,
  uri: string,
  expectedJwkThumbprint?: string,
  accessToken?: string
): DPoPVerifyResult {
  try {
    // Parse compact JWS: header.payload.signature
    const parts = proof.split('.');
    if (parts.length !== 3) {
      return { valid: false, jwkThumbprint: '', error: 'Invalid JWS format' };
    }

    const header = JSON.parse(fromBase64Url(parts[0]).toString('utf8'));
    const payload = JSON.parse(fromBase64Url(parts[1]).toString('utf8'));

    // Verify header
    if (header.typ !== 'dpop+jwt') {
      return { valid: false, jwkThumbprint: '', error: 'Invalid typ' };
    }
    if (header.alg !== 'ES256') {
      return { valid: false, jwkThumbprint: '', error: 'Unsupported algorithm' };
    }
    if (!header.jwk || header.jwk.kty !== 'EC' || header.jwk.crv !== 'P-256') {
      return { valid: false, jwkThumbprint: '', error: 'Invalid JWK in header' };
    }

    // Verify payload claims
    if (payload.htm !== method) {
      return { valid: false, jwkThumbprint: '', error: 'htm mismatch' };
    }
    if (payload.htu !== uri) {
      return { valid: false, jwkThumbprint: '', error: 'htu mismatch' };
    }

    // Check iat within 5 minutes
    const now = Math.floor(Date.now() / 1000);
    if (!payload.iat || Math.abs(now - payload.iat) > 300) {
      return { valid: false, jwkThumbprint: '', error: 'iat out of range' };
    }

    // Verify access token hash if provided
    if (accessToken && payload.ath) {
      const expectedAth = toBase64Url(
        crypto.createHash('sha256').update(accessToken).digest()
      );
      if (payload.ath !== expectedAth) {
        return { valid: false, jwkThumbprint: '', error: 'ath mismatch' };
      }
    }

    // Compute JWK thumbprint
    const thumbprint = computeJwkThumbprint(header.jwk);

    // Check expected thumbprint if provided
    if (expectedJwkThumbprint && thumbprint !== expectedJwkThumbprint) {
      return { valid: false, jwkThumbprint: thumbprint, error: 'Thumbprint mismatch' };
    }

    // Verify ECDSA signature
    const keyObject = crypto.createPublicKey({
      key: { kty: header.jwk.kty, crv: header.jwk.crv, x: header.jwk.x, y: header.jwk.y },
      format: 'jwk',
    });

    const signatureInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    const signatureBuf = fromBase64Url(parts[2]);

    const verified = crypto.verify(
      'SHA256',
      signatureInput,
      { key: keyObject, dsaEncoding: 'ieee-p1363' },
      signatureBuf
    );

    if (!verified) {
      return { valid: false, jwkThumbprint: thumbprint, error: 'Signature verification failed' };
    }

    return { valid: true, jwkThumbprint: thumbprint };
  } catch (err) {
    return { valid: false, jwkThumbprint: '', error: 'DPoP proof parsing failed' };
  }
}

// --- DPoP Proof Creation (for testing / client-side) ---

export function createDPoPProof(
  privateKeyPem: string,
  publicKeyJwk: { kty: string; crv: string; x: string; y: string },
  method: string,
  uri: string,
  accessToken?: string
): string {
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: publicKeyJwk,
  };

  const payload: any = {
    jti: crypto.randomBytes(16).toString('hex'),
    htm: method,
    htu: uri,
    iat: Math.floor(Date.now() / 1000),
  };

  if (accessToken) {
    payload.ath = toBase64Url(
      crypto.createHash('sha256').update(accessToken).digest()
    );
  }

  const headerB64 = toBase64Url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = toBase64Url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(
    'SHA256',
    Buffer.from(signingInput),
    { key: privateKey, dsaEncoding: 'ieee-p1363' }
  );

  return `${signingInput}.${toBase64Url(signature)}`;
}
