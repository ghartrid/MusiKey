// MusiKey Protocol Server — Local HTTP server for browser ↔ MusiKey communication
// Bound to 127.0.0.1 only (never exposed externally)
// Services POST challenges here; MusiKey signs them after user approval

import * as http from 'http';
import { BrowserWindow, ipcMain } from 'electron';

const PORT = 9817;
const MAX_BODY_SIZE = 16 * 1024; // 16 KB

let server: http.Server | null = null;
let mainWindow: BrowserWindow | null = null;

// Pending requests waiting for renderer approval
const pendingRequests = new Map<string, {
  resolve: (value: any) => void;
  timeout: ReturnType<typeof setTimeout>;
}>();

function json(res: http.ServerResponse, status: number, data: any): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
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
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    });
    res.end();
    return;
  }

  try {
    // GET /status — health check
    if (method === 'GET' && urlPath === '/status') {
      return json(res, 200, { protocol: 'musikey-v1', ready: true, port: PORT });
    }

    // POST /challenge — receive challenge from service
    if (method === 'POST' && urlPath === '/challenge') {
      if (!mainWindow) {
        return json(res, 503, { error: 'MusiKey not ready' });
      }

      const body = JSON.parse(await readBody(req));
      if (!body.rpId || !body.challenge) {
        return json(res, 400, { error: 'rpId and challenge required' });
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
        return json(res, 408, { error: 'User did not respond in time' });
      }
      if (result.error === 'denied') {
        return json(res, 403, { error: 'User denied the request' });
      }
      if (result.assertion) {
        return json(res, 200, result.assertion);
      }
      return json(res, 500, { error: result.error || 'Unknown error' });
    }

    // POST /register — receive registration request from service
    if (method === 'POST' && urlPath === '/register') {
      if (!mainWindow) {
        return json(res, 503, { error: 'MusiKey not ready' });
      }

      const body = JSON.parse(await readBody(req));
      if (!body.rpId || !body.serviceName) {
        return json(res, 400, { error: 'rpId and serviceName required' });
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
        return json(res, 408, { error: 'User did not respond in time' });
      }
      if (result.error === 'denied') {
        return json(res, 403, { error: 'User denied the request' });
      }
      if (result.registration) {
        return json(res, 201, result.registration);
      }
      return json(res, 500, { error: result.error || 'Unknown error' });
    }

    json(res, 404, { error: 'Not found' });
  } catch (err: any) {
    json(res, 500, { error: err.message || 'Internal error' });
  }
}

// Handle renderer responses to protocol requests
ipcMain.on('protocol:challenge-response', (_event: any, data: { requestId: string; assertion?: any; error?: string }) => {
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

ipcMain.on('protocol:register-response', (_event: any, data: { requestId: string; registration?: any; error?: string }) => {
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

export function startProtocolServer(win: BrowserWindow): void {
  mainWindow = win;

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
