// MusiKey Protocol Server — Local HTTP server for browser ↔ MusiKey communication
// Bound to 127.0.0.1 only (never exposed externally)
// Services POST challenges here; MusiKey signs them after user approval

import * as http from 'http';

const PORT = 9817;
const MAX_BODY_SIZE = 16 * 1024; // 16 KB

let server: http.Server | null = null;
let mainWindow: any = null;
let ipcListenersRegistered = false;

// Pending requests waiting for renderer approval
const pendingRequests = new Map<string, {
  resolve: (value: any) => void;
  timeout: ReturnType<typeof setTimeout>;
}>();

// Only allow CORS from localhost origins (same machine, different ports)
function getAllowedOrigin(req: http.IncomingMessage): string | null {
  const origin = req.headers.origin;
  if (!origin) return null;
  try {
    const url = new URL(origin);
    if (url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '::1') {
      return origin;
    }
  } catch {}
  return null;
}

function json(res: http.ServerResponse, status: number, data: any, req?: http.IncomingMessage): void {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (req) {
    const allowed = getAllowedOrigin(req);
    if (allowed) headers['Access-Control-Allow-Origin'] = allowed;
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_SIZE) { req.destroy(); reject(new Error('Body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function generateRequestId(): string {
  const bytes = require('crypto').randomBytes(16);
  return bytes.toString('hex');
}

async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const method = req.method || 'GET';
  const urlPath = (req.url || '/').split('?')[0];

  // CORS preflight
  if (method === 'OPTIONS') {
    const headers: Record<string, string> = {
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    };
    const allowed = getAllowedOrigin(req);
    if (allowed) headers['Access-Control-Allow-Origin'] = allowed;
    res.writeHead(204, headers);
    res.end();
    return;
  }

  try {
    // GET /status — health check
    if (method === 'GET' && urlPath === '/status') {
      return json(res, 200, { protocol: 'musikey-v1', ready: true, port: PORT }, req);
    }

    // POST /challenge — receive challenge from service
    if (method === 'POST' && urlPath === '/challenge') {
      if (!mainWindow) {
        return json(res, 503, { error: 'MusiKey not ready' }, req);
      }

      const body = JSON.parse(await readBody(req));
      if (!body.rpId || !body.challenge) {
        return json(res, 400, { error: 'rpId and challenge required' }, req);
      }

      const requestId = generateRequestId();

      // Forward challenge to renderer for user approval
      const result = await new Promise<any>((resolve) => {
        const timeout = setTimeout(() => {
          pendingRequests.delete(requestId);
          resolve({ error: 'timeout' });
        }, 60000); // 60-second timeout for user approval

        pendingRequests.set(requestId, { resolve, timeout });
        mainWindow!.webContents.send('protocol:challenge-received', {
          requestId,
          challenge: {
            protocol: 'musikey-v1',
            type: 'challenge',
            rpId: body.rpId,
            challenge: body.challenge,
            nonce: body.nonce || '',
            timestamp: body.timestamp || Math.floor(Date.now() / 1000),
          },
        });
      });

      if (result.error === 'timeout') {
        return json(res, 408, { error: 'User did not respond in time' }, req);
      }
      if (result.error === 'denied') {
        return json(res, 403, { error: 'User denied the request' }, req);
      }
      if (result.assertion) {
        return json(res, 200, result.assertion, req);
      }
      return json(res, 500, { error: result.error || 'Unknown error' }, req);
    }

    // POST /register — receive registration request from service
    if (method === 'POST' && urlPath === '/register') {
      if (!mainWindow) {
        return json(res, 503, { error: 'MusiKey not ready' }, req);
      }

      const body = JSON.parse(await readBody(req));
      if (!body.rpId || !body.serviceName) {
        return json(res, 400, { error: 'rpId and serviceName required' }, req);
      }

      const requestId = generateRequestId();

      const result = await new Promise<any>((resolve) => {
        const timeout = setTimeout(() => {
          pendingRequests.delete(requestId);
          resolve({ error: 'timeout' });
        }, 120000); // 2-minute timeout for registration

        pendingRequests.set(requestId, { resolve, timeout });
        mainWindow!.webContents.send('protocol:register-request', {
          requestId,
          request: {
            protocol: 'musikey-v1',
            type: 'register',
            rpId: body.rpId,
            serviceName: body.serviceName,
            userId: body.userId || '',
            endpoint: body.endpoint,
          },
        });
      });

      if (result.error === 'timeout') {
        return json(res, 408, { error: 'User did not respond in time' }, req);
      }
      if (result.error === 'denied') {
        return json(res, 403, { error: 'User denied the request' }, req);
      }
      if (result.registration) {
        return json(res, 201, result.registration, req);
      }
      return json(res, 500, { error: result.error || 'Unknown error' }, req);
    }

    json(res, 404, { error: 'Not found' }, req);
  } catch (err: any) {
    json(res, 500, { error: err.message || 'Internal error' }, req);
  }
}

export function startProtocolServer(win: any): void {
  mainWindow = win;

  // Guard against duplicate IPC listener registration (e.g., macOS activate re-creates window)
  if (!ipcListenersRegistered) {
    ipcListenersRegistered = true;
    const { ipcMain: ipc } = require('electron');

    // Handle renderer responses to protocol requests
    ipc.on('protocol:challenge-response', (_event: any, data: { requestId: string; assertion?: any; error?: string }) => {
      const pending = pendingRequests.get(data.requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingRequests.delete(data.requestId);
        if (data.assertion) {
          pending.resolve({ assertion: data.assertion });
        } else {
          pending.resolve({ error: data.error || 'denied' });
        }
      }
    });

    ipc.on('protocol:register-response', (_event: any, data: { requestId: string; registration?: any; error?: string }) => {
      const pending = pendingRequests.get(data.requestId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingRequests.delete(data.requestId);
        if (data.registration) {
          pending.resolve({ registration: data.registration });
        } else {
          pending.resolve({ error: data.error || 'denied' });
        }
      }
    });
  }

  if (server) return; // Already running
  server = http.createServer(handleRequest);
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`MusiKey Protocol Server listening on http://127.0.0.1:${PORT}`);
  });

  // If port is busy, fail silently (another MusiKey instance may be running)
  server.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`Port ${PORT} in use — protocol server disabled`);
      server = null;
    }
  });
}

export function stopProtocolServer(): void {
  if (server) {
    // Clear all pending requests
    for (const [id, pending] of pendingRequests) {
      clearTimeout(pending.timeout);
      pending.resolve({ error: 'shutdown' });
    }
    pendingRequests.clear();
    server.close();
    server = null;
  }
  mainWindow = null;
}
