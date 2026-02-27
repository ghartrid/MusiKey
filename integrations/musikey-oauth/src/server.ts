// MusiKey OAuth2 Provider — Authorization Code Flow with WebAuthn
// Uses ECDSA P-256 public key verification for authentication

import * as http from 'http';
import * as url from 'url';
import * as crypto from 'crypto';
import * as querystring from 'querystring';
import { registerClient, getClient, validateClient, generateCode, exchangeCode, validateToken, cleanup } from './tokens';
import { UserInfo, WebAuthnRegistration } from './types';
import { verifyDPoPProof } from './dpop';

const PORT = 3200;
const userSessions = new Map<string, UserInfo>();
const webauthnKeys = new Map<string, WebAuthnRegistration>(); // userId → public key

// Register a demo client
registerClient({
  clientId: 'musikey-demo-client',
  clientSecret: 'musikey-demo-secret',
  redirectUris: ['http://localhost:3201/callback'],
  name: 'MusiKey Demo App',
});

function sendJson(res: http.ServerResponse, status: number, data: any): void {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function sendError(res: http.ServerResponse, status: number, error: string, description: string): void {
  sendJson(res, status, { error, error_description: description });
}

function parseBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 65536) { reject(new Error('Body too large')); return; }
      body += chunk.toString();
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url || '', true);
  const path = parsed.pathname;
  const method = req.method?.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    });
    res.end();
    return;
  }

  try {
    // GET /authorize — Authorization endpoint
    if (path === '/authorize' && method === 'GET') {
      const { client_id, redirect_uri, response_type, scope, state } = parsed.query as Record<string, string>;

      if (response_type !== 'code') {
        return sendError(res, 400, 'unsupported_response_type', 'Only authorization_code flow is supported');
      }

      const client = getClient(client_id);
      if (!client) {
        return sendError(res, 400, 'invalid_client', 'Unknown client_id');
      }

      if (!client.redirectUris.includes(redirect_uri)) {
        return sendError(res, 400, 'invalid_request', 'Invalid redirect_uri');
      }

      // In a real implementation, this would show a MusiKey auth UI.
      // For the skeleton, we return a simple HTML form.
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html><head><title>MusiKey Authorization</title></head>
<body style="background:#1a1a2e;color:#ececec;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;">
  <div style="text-align:center;max-width:400px;">
    <h1 style="color:#e94560;">&#9835; MusiKey</h1>
    <p><strong>${client.name}</strong> wants to access your MusiKey identity.</p>
    <p>Scope: ${scope || 'openid'}</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="scope" value="${scope || 'openid'}">
      <input type="hidden" name="state" value="${state || ''}">
      <div style="margin:16px 0;">
        <input name="username" placeholder="MusiKey Username" style="padding:8px;width:200px;"><br><br>
        <input name="passphrase" type="password" placeholder="Passphrase" style="padding:8px;width:200px;">
      </div>
      <button type="submit" style="padding:10px 30px;background:#e94560;color:white;border:none;border-radius:8px;cursor:pointer;">Authorize</button>
    </form>
  </div>
</body></html>`);
      return;
    }

    // POST /authorize — Process authorization
    if (path === '/authorize' && method === 'POST') {
      const body = await parseBody(req);
      const params = querystring.parse(body);
      const { client_id, redirect_uri, scope, state, username, passphrase } = params as Record<string, string>;

      const client = getClient(client_id);
      if (!client) {
        return sendError(res, 400, 'invalid_client', 'Unknown client_id');
      }

      // In a real implementation, authenticate via MusiKey core.
      // For skeleton, accept any non-empty username+passphrase.
      if (!username || !passphrase) {
        return sendError(res, 401, 'access_denied', 'Authentication required');
      }

      // Store user session
      userSessions.set(username, {
        sub: username,
        name: username,
        auth_time: Math.floor(Date.now() / 1000),
        auth_method: 'musikey',
      });

      const code = generateCode(client_id, redirect_uri, username, scope || 'openid');
      const redirectUrl = `${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`;

      res.writeHead(302, { Location: redirectUrl });
      res.end();
      return;
    }

    // POST /token — Token endpoint
    if (path === '/token' && method === 'POST') {
      const body = await parseBody(req);
      const params = querystring.parse(body);
      const { grant_type, code, redirect_uri, client_id, client_secret } = params as Record<string, string>;

      if (grant_type !== 'authorization_code') {
        return sendError(res, 400, 'unsupported_grant_type', 'Only authorization_code is supported');
      }

      if (!validateClient(client_id, client_secret)) {
        return sendError(res, 401, 'invalid_client', 'Client authentication failed');
      }

      const accessToken = exchangeCode(code, client_id, redirect_uri);
      if (!accessToken) {
        return sendError(res, 400, 'invalid_grant', 'Invalid or expired authorization code');
      }

      // DPoP binding: if DPoP header present, bind token to client key
      const dpopHeader = req.headers['dpop'] as string | undefined;
      let tokenType = 'Bearer';
      if (dpopHeader) {
        const tokenUri = `http://localhost:${PORT}/token`;
        const dpopResult = verifyDPoPProof(dpopHeader, 'POST', tokenUri);
        if (dpopResult.valid) {
          accessToken.jwkThumbprint = dpopResult.jwkThumbprint;
          tokenType = 'DPoP';
        }
      }

      return sendJson(res, 200, {
        access_token: accessToken.token,
        token_type: tokenType,
        expires_in: 3600,
        scope: accessToken.scope,
      });
    }

    // GET /userinfo — UserInfo endpoint
    if (path === '/userinfo' && method === 'GET') {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return sendError(res, 401, 'invalid_token', 'Authorization header required');
      }

      // Support both Bearer and DPoP token types
      let token: string;
      if (authHeader.startsWith('DPoP ')) {
        token = authHeader.substring(5);
      } else if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      } else {
        return sendError(res, 401, 'invalid_token', 'Bearer or DPoP token required');
      }

      const accessToken = validateToken(token);
      if (!accessToken) {
        return sendError(res, 401, 'invalid_token', 'Token expired or invalid');
      }

      // If token is DPoP-bound, verify the DPoP proof
      if (accessToken.jwkThumbprint) {
        const dpopHeader = req.headers['dpop'] as string | undefined;
        if (!dpopHeader) {
          return sendError(res, 401, 'invalid_token', 'DPoP proof required for DPoP-bound token');
        }
        const userinfoUri = `http://localhost:${PORT}/userinfo`;
        const dpopResult = verifyDPoPProof(dpopHeader, 'GET', userinfoUri, accessToken.jwkThumbprint, token);
        if (!dpopResult.valid) {
          return sendError(res, 401, 'invalid_dpop_proof', dpopResult.error || 'DPoP proof verification failed');
        }
      }

      const user = userSessions.get(accessToken.userId);
      if (!user) {
        return sendError(res, 404, 'not_found', 'User not found');
      }

      return sendJson(res, 200, user);
    }

    // POST /webauthn/register — Register a public key for a user
    if (path === '/webauthn/register' && method === 'POST') {
      const body = await parseBody(req);
      const { userId, publicKeyJwk, credentialId } = JSON.parse(body);

      if (!userId || !publicKeyJwk || !credentialId) {
        return sendError(res, 400, 'invalid_request', 'Missing userId, publicKeyJwk, or credentialId');
      }

      webauthnKeys.set(userId, {
        userId,
        publicKeyJwk,
        credentialId,
        signCount: 0,
      });

      return sendJson(res, 201, {
        status: 'registered',
        userId,
        credentialId,
      });
    }

    // POST /webauthn/challenge — Generate a WebAuthn challenge
    if (path === '/webauthn/challenge' && method === 'POST') {
      const body = await parseBody(req);
      const { rpId } = JSON.parse(body);

      const challenge = crypto.randomBytes(32).toString('base64');
      return sendJson(res, 200, {
        challenge,
        rpId: rpId || 'musikey.local',
        timeout: 60000,
      });
    }

    // POST /webauthn/assertion — Verify a WebAuthn assertion
    if (path === '/webauthn/assertion' && method === 'POST') {
      const body = await parseBody(req);
      const { userId, signature, authenticatorData, clientDataJSON, challenge } = JSON.parse(body);

      const reg = webauthnKeys.get(userId);
      if (!reg) {
        return sendError(res, 404, 'not_found', 'No WebAuthn registration for this user');
      }

      try {
        // Reconstruct signed data: authData || SHA-256(clientDataJSON)
        const authDataBuf = Buffer.from(authenticatorData, 'base64');
        const clientDataBuf = Buffer.from(clientDataJSON, 'base64');
        const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
        const signedData = Buffer.concat([authDataBuf, clientDataHash]);

        // Import public key and verify ECDSA signature
        const keyObject = crypto.createPublicKey({
          key: {
            kty: reg.publicKeyJwk.kty,
            crv: reg.publicKeyJwk.crv,
            x: reg.publicKeyJwk.x,
            y: reg.publicKeyJwk.y,
          },
          format: 'jwk',
        });

        const signatureBuf = Buffer.from(signature, 'base64');
        const verified = crypto.verify(
          'SHA256',
          signedData,
          { key: keyObject, dsaEncoding: 'ieee-p1363' },
          signatureBuf
        );

        if (!verified) {
          return sendError(res, 401, 'invalid_assertion', 'Signature verification failed');
        }

        // Extract signCount from authenticator data (bytes 33-36, big-endian)
        const signCount = authDataBuf.readUInt32BE(33);
        if (signCount <= reg.signCount) {
          return sendJson(res, 200, {
            verified: true,
            cloneWarning: true,
            signCount,
            userId,
          });
        }

        reg.signCount = signCount;

        // Store user session
        userSessions.set(userId, {
          sub: userId,
          name: userId,
          auth_time: Math.floor(Date.now() / 1000),
          auth_method: 'musikey-webauthn',
        });

        return sendJson(res, 200, {
          verified: true,
          cloneWarning: false,
          signCount,
          userId,
        });
      } catch (err) {
        return sendError(res, 400, 'invalid_assertion', 'Failed to verify assertion');
      }
    }

    // GET /health
    if (path === '/health') {
      return sendJson(res, 200, { status: 'ok', provider: 'musikey-oauth', version: '2.0.0' });
    }

    sendError(res, 404, 'not_found', 'Endpoint not found');
  } catch (err) {
    sendError(res, 500, 'server_error', 'Internal server error');
  }
});

// Cleanup expired tokens every 5 minutes
setInterval(cleanup, 5 * 60 * 1000);

server.listen(PORT, () => {
  console.log(`MusiKey OAuth2 Provider running on http://localhost:${PORT}`);
  console.log(`Authorization: GET http://localhost:${PORT}/authorize`);
  console.log(`Token:         POST http://localhost:${PORT}/token`);
  console.log(`UserInfo:      GET http://localhost:${PORT}/userinfo`);
});
