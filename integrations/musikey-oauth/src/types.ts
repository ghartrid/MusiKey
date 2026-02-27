export interface OAuthClient {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  name: string;
}

export interface AuthorizationCode {
  code: string;
  clientId: string;
  redirectUri: string;
  userId: string;
  scope: string;
  expiresAt: number;
}

export interface AccessToken {
  token: string;
  clientId: string;
  userId: string;
  scope: string;
  expiresAt: number;
  jwkThumbprint?: string; // DPoP binding
}

export interface WebAuthnChallenge {
  challenge: string;  // base64
  rpId: string;
  timeout: number;
}

export interface WebAuthnRegistration {
  userId: string;
  publicKeyJwk: { kty?: string; crv?: string; x?: string; y?: string; [key: string]: any };
  credentialId: string;
  signCount: number;
}

export interface UserInfo {
  sub: string;       // userId
  name: string;
  auth_time: number;
  auth_method: string;
}
