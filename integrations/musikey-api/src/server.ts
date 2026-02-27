import * as http from 'http';
import * as url from 'url';
import { MusiKey, Scale } from 'musikey-core';
import {
  generateMusiKeyChallenge,
  verifyMusiKeyAssertion,
  verifyMusiKeyRegistration,
  buildMusiKeyUri,
  MusiKeyChallenge,
} from './verify';

const mk = new MusiKey({ preferredScale: Scale.PENTATONIC, songLength: 64 });
const credentials = new Map<string, any>();
// MusiKey Protocol stores
const musikeyKeys = new Map<string, { publicKeyJwk: any; credentialId: string; signCount: number }>();
const pendingChallenges = new Map<string, { challenge: MusiKeyChallenge; expiresAt: number }>();
const PORT = parseInt(process.env.PORT || '3100', 10);
const RPID = process.env.RPID || 'musikey-api.local';

function json(res: http.ServerResponse, status: number, data: any): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const MAX_BODY_SIZE = 64 * 1024; // 64 KB

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_SIZE) { req.destroy(); reject(new Error('Request body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const parsed = url.parse(req.url || '/', true);
  const method = req.method || 'GET';
  const path = parsed.pathname || '/';

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    // POST /enroll { userId, passphrase }
    if (method === 'POST' && path === '/enroll') {
      const body = JSON.parse(await readBody(req));
      if (!body.userId || !body.passphrase) {
        return json(res, 400, { error: 'userId and passphrase required' });
      }
      if (credentials.has(body.userId)) {
        return json(res, 409, { error: 'User already enrolled' });
      }
      const cred = mk.enroll(body.userId, body.passphrase);
      if (!cred) return json(res, 500, { error: 'Enrollment failed' });
      credentials.set(body.userId, cred);
      return json(res, 201, {
        userId: cred.userId,
        scale: cred.scale,
        rootNote: cred.rootNote,
        created: cred.createdTimestamp,
      });
    }

    // POST /authenticate { userId, passphrase }
    if (method === 'POST' && path === '/authenticate') {
      const body = JSON.parse(await readBody(req));
      if (!body.userId || !body.passphrase) {
        return json(res, 400, { error: 'userId and passphrase required' });
      }
      const cred = credentials.get(body.userId);
      if (!cred) return json(res, 404, { error: 'User not found' });

      const result = mk.authenticate(cred, body.passphrase);
      if (result.destroyed) {
        credentials.delete(body.userId);
      }
      return json(res, result.success ? 200 : 401, {
        success: result.success,
        error: result.error,
        destroyed: result.destroyed,
        musicality: result.analysis?.overallMusicality,
        entropy: result.song?.entropyBits,
      });
    }

    // GET /users
    if (method === 'GET' && path === '/users') {
      return json(res, 200, { users: Array.from(credentials.keys()) });
    }

    // DELETE /users/:id
    if (method === 'DELETE' && path.startsWith('/users/')) {
      const userId = decodeURIComponent(path.slice(7));
      if (!credentials.has(userId)) return json(res, 404, { error: 'User not found' });
      credentials.delete(userId);
      return json(res, 200, { deleted: userId });
    }

    // GET /health
    if (method === 'GET' && path === '/health') {
      return json(res, 200, { status: 'ok', users: credentials.size });
    }

    // POST /generate - generate a song without enrolling
    if (method === 'POST' && path === '/generate') {
      const body = JSON.parse(await readBody(req));
      const song = mk.generateSong(body.scale, body.length);
      const analysis = mk.analyze(song);
      return json(res, 200, {
        eventCount: song.eventCount,
        totalDuration: song.totalDuration,
        entropy: song.entropyBits,
        scale: song.scale,
        rootNote: song.rootNote,
        tempo: song.tempo,
        musicality: analysis.overallMusicality,
        isValid: analysis.isValidMusic,
      });
    }

    // --- MusiKey Protocol Endpoints ---

    // POST /musikey/register — Accept public key registration
    if (method === 'POST' && path === '/musikey/register') {
      const body = JSON.parse(await readBody(req));
      if (!body.publicKeyJwk || !body.credentialId || !body.userId) {
        return json(res, 400, { error: 'publicKeyJwk, credentialId, and userId required' });
      }

      // Verify self-attestation if provided
      if (body.attestation) {
        const result = verifyMusiKeyRegistration(body, RPID);
        if (!result.verified) {
          return json(res, 400, { error: result.error || 'Attestation verification failed' });
        }
      }

      musikeyKeys.set(body.userId, {
        publicKeyJwk: body.publicKeyJwk,
        credentialId: body.credentialId,
        signCount: 0,
      });

      return json(res, 201, {
        userId: body.userId,
        credentialId: body.credentialId,
        registered: true,
      });
    }

    // POST /musikey/challenge — Generate authentication challenge
    if (method === 'POST' && path === '/musikey/challenge') {
      const body = JSON.parse(await readBody(req));
      if (!body.userId) {
        return json(res, 400, { error: 'userId required' });
      }

      const stored = musikeyKeys.get(body.userId);
      if (!stored) {
        return json(res, 404, { error: 'User not registered' });
      }

      const challenge = generateMusiKeyChallenge(RPID, body.callback);
      pendingChallenges.set(challenge.challenge, {
        challenge,
        expiresAt: Date.now() + 300000, // 5 minutes
      });

      // Also provide the musikey:// URI for convenience
      const uri = buildMusiKeyUri('auth', {
        rpId: RPID,
        challenge: challenge.challenge,
        nonce: challenge.nonce,
        callback: body.callback || '',
      });

      return json(res, 200, { challenge, uri });
    }

    // POST /musikey/verify — Verify signed assertion
    if (method === 'POST' && path === '/musikey/verify') {
      const body = JSON.parse(await readBody(req));
      if (!body.assertion) {
        return json(res, 400, { error: 'assertion required' });
      }

      const assertion = body.assertion;
      if (!assertion.challenge) {
        return json(res, 400, { error: 'assertion.challenge required' });
      }

      // Find pending challenge
      const pending = pendingChallenges.get(assertion.challenge);
      if (!pending) {
        return json(res, 400, { error: 'Challenge not found or expired' });
      }

      // Check expiry
      if (Date.now() > pending.expiresAt) {
        pendingChallenges.delete(assertion.challenge);
        return json(res, 400, { error: 'Challenge expired' });
      }

      // Find stored public key by credentialId
      let storedKey: { publicKeyJwk: any; credentialId: string; signCount: number } | undefined;
      let storedUserId: string | undefined;
      for (const [userId, key] of musikeyKeys) {
        if (key.credentialId === assertion.publicKeyId) {
          storedKey = key;
          storedUserId = userId;
          break;
        }
      }

      if (!storedKey || !storedUserId) {
        return json(res, 404, { error: 'Credential not found' });
      }

      const result = verifyMusiKeyAssertion(
        assertion,
        storedKey.publicKeyJwk,
        pending.challenge,
        RPID,
        storedKey.signCount
      );

      // Clean up challenge (one-time use)
      pendingChallenges.delete(assertion.challenge);

      if (result.verified) {
        // Update stored signCount
        storedKey.signCount = result.newSignCount;
      }

      return json(res, result.verified ? 200 : 401, {
        verified: result.verified,
        userId: storedUserId,
        signCount: result.newSignCount,
        cloneWarning: result.cloneWarning,
        error: result.error,
      });
    }

    // GET /musikey/discover — List supported auth methods
    if (method === 'GET' && path === '/musikey/discover') {
      return json(res, 200, {
        protocol: 'musikey-v1',
        rpId: RPID,
        methods: ['musikey-protocol', 'passphrase'],
        registeredUsers: musikeyKeys.size,
      });
    }

    json(res, 404, { error: 'Not found' });
  } catch (err: any) {
    json(res, 500, { error: err.message || 'Internal error' });
  }
}

// Periodic cleanup of expired challenges
setInterval(() => {
  const now = Date.now();
  for (const [key, pending] of pendingChallenges) {
    if (now > pending.expiresAt) pendingChallenges.delete(key);
  }
}, 60000);

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
  console.log(`MusiKey API running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log('  POST /enroll              { userId, passphrase }');
  console.log('  POST /authenticate        { userId, passphrase }');
  console.log('  POST /generate            { scale?, length? }');
  console.log('  GET  /users');
  console.log('  DELETE /users/:id');
  console.log('  GET  /health');
  console.log('  POST /musikey/register    { publicKeyJwk, credentialId, userId }');
  console.log('  POST /musikey/challenge   { userId }');
  console.log('  POST /musikey/verify      { assertion }');
  console.log('  GET  /musikey/discover');
});
