import * as nodeCrypto from 'crypto';
import { AuthorizationCode, AccessToken, OAuthClient } from './types';

// In-memory stores
const codes = new Map<string, AuthorizationCode>();
const tokens = new Map<string, AccessToken>();
const clients = new Map<string, OAuthClient>();

const CODE_TTL = 10 * 60 * 1000;  // 10 minutes
const TOKEN_TTL = 60 * 60 * 1000; // 1 hour

export function registerClient(client: OAuthClient): void {
  clients.set(client.clientId, client);
}

export function getClient(clientId: string): OAuthClient | undefined {
  return clients.get(clientId);
}

export function validateClient(clientId: string, clientSecret: string): boolean {
  const client = clients.get(clientId);
  if (!client) return false;
  return client.clientSecret === clientSecret;
}

export function generateCode(clientId: string, redirectUri: string, userId: string, scope: string): string {
  const code = nodeCrypto.randomBytes(32).toString('hex');
  codes.set(code, {
    code,
    clientId,
    redirectUri,
    userId,
    scope,
    expiresAt: Date.now() + CODE_TTL,
  });
  return code;
}

export function exchangeCode(code: string, clientId: string, redirectUri: string): AccessToken | null {
  const authCode = codes.get(code);
  if (!authCode) return null;

  // Delete code immediately (one-time use)
  codes.delete(code);

  if (authCode.expiresAt < Date.now()) return null;
  if (authCode.clientId !== clientId) return null;
  if (authCode.redirectUri !== redirectUri) return null;

  const token = nodeCrypto.randomBytes(32).toString('hex');
  const accessToken: AccessToken = {
    token,
    clientId,
    userId: authCode.userId,
    scope: authCode.scope,
    expiresAt: Date.now() + TOKEN_TTL,
  };
  tokens.set(token, accessToken);
  return accessToken;
}

export function validateToken(token: string): AccessToken | null {
  const at = tokens.get(token);
  if (!at) return null;
  if (at.expiresAt < Date.now()) {
    tokens.delete(token);
    return null;
  }
  return at;
}

// Cleanup expired entries
export function cleanup(): void {
  const now = Date.now();
  for (const [k, v] of codes) {
    if (v.expiresAt < now) codes.delete(k);
  }
  for (const [k, v] of tokens) {
    if (v.expiresAt < now) tokens.delete(k);
  }
}
