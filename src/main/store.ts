import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as nodeCrypto from 'crypto';
import { app } from 'electron';

let storePath: string;
let saltPath: string;
let keyPartPath: string;
let machineKey: Buffer | null = null;

function getStorePath(): string {
  if (!storePath) {
    storePath = path.join(app.getPath('userData'), 'credentials.enc');
  }
  return storePath;
}

function getSaltPath(): string {
  if (!saltPath) {
    saltPath = path.join(app.getPath('userData'), 'store-salt');
  }
  return saltPath;
}

function getKeyPartPath(): string {
  if (!keyPartPath) {
    keyPartPath = path.join(app.getPath('userData'), 'store-keypart');
  }
  return keyPartPath;
}

// Collect deep machine fingerprint: hostname, username, path, CPU model, OS release, MAC addresses
function getMachineFingerprint(): string {
  const parts = [
    os.hostname(),
    os.userInfo().username,
    app.getPath('userData'),
    os.cpus()[0]?.model || 'unknown-cpu',
    os.release(),
    os.platform(),
    os.arch(),
  ];

  // Add all non-internal MAC addresses for hardware binding
  const nets = os.networkInterfaces();
  const macs: string[] = [];
  for (const name in nets) {
    for (const iface of nets[name] || []) {
      if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
        macs.push(iface.mac);
      }
    }
  }
  macs.sort();
  parts.push(macs.join(','));

  return parts.join('::');
}

// Key splitting: final key = HMAC(scrypt(fingerprint, salt), keyPart)
// keyPart is a random 32-byte value stored separately — both files needed
function getMachineKey(): Buffer {
  if (machineKey) return machineKey;

  const fingerprint = getMachineFingerprint();
  const dir = path.dirname(getSaltPath());
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Salt
  let salt: Buffer;
  try {
    salt = fs.readFileSync(getSaltPath());
  } catch {
    salt = nodeCrypto.randomBytes(32);
    fs.writeFileSync(getSaltPath(), salt);
  }

  // Key part (second factor for key splitting)
  let keyPart: Buffer;
  try {
    keyPart = fs.readFileSync(getKeyPartPath());
  } catch {
    keyPart = nodeCrypto.randomBytes(32);
    fs.writeFileSync(getKeyPartPath(), keyPart);
  }

  // Derive base key from fingerprint via scrypt (memory-hard)
  const baseKey = nodeCrypto.scryptSync(fingerprint, salt, 32, {
    N: 65536, // 2^16
    r: 8,
    p: 1,
    maxmem: 128 * 1024 * 1024,
  });

  // Split: combine base key with random key part via HMAC
  machineKey = nodeCrypto.createHmac('sha256', baseKey).update(keyPart).digest() as Buffer;

  // Zero intermediates
  baseKey.fill(0);

  return machineKey;
}

function encryptStore(plaintext: string): Buffer {
  const key = getMachineKey();
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: [iv 12 bytes][tag 16 bytes][ciphertext]
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptStore(data: Buffer): string {
  const key = getMachineKey();
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

// HMAC for tamper-resistant lockout fields
function computeHmac(credential: any): string {
  const key = getMachineKey();
  const data = `${credential.userId}:${credential.failedAttempts}:${credential.locked}:${credential.authAttempts}:${credential.version || 0}`;
  return nodeCrypto.createHmac('sha256', key).update(data).digest('hex');
}

interface CredentialStore {
  version: number;
  credentials: Record<string, any>;
}

function readStore(): CredentialStore {
  try {
    const raw = fs.readFileSync(getStorePath());
    const json = decryptStore(raw);
    return JSON.parse(json);
  } catch {
    // Try reading legacy unencrypted store
    try {
      const legacyPath = path.join(app.getPath('userData'), 'credentials.json');
      const data = fs.readFileSync(legacyPath, 'utf-8');
      const store = JSON.parse(data);
      writeStore(store);
      fs.unlinkSync(legacyPath);
      return store;
    } catch {
      return { version: 3, credentials: {} };
    }
  }
}

function writeStore(store: CredentialStore): void {
  const dir = path.dirname(getStorePath());
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  store.version = 3;
  const encrypted = encryptStore(JSON.stringify(store));
  fs.writeFileSync(getStorePath(), encrypted);
}

// Secure wipe: overwrite credential data with random bytes before deleting
function secureWipeCredential(store: CredentialStore, userId: string): void {
  const cred = store.credentials[userId];
  if (cred && cred.scrambledSong) {
    const randomData = nodeCrypto.randomBytes(256).toString('base64');
    cred.scrambledSong.scrambledData = randomData;
    cred.scrambledSong.salt = randomData.substring(0, 24);
    cred.scrambledSong.iv = randomData.substring(0, 16);
    cred.scrambledSong.authTag = randomData.substring(0, 24);
    cred.scrambledSong.verificationHash = randomData.substring(0, 44);
    cred.userId = 'DESTROYED';
    cred.integrityHash = 'DESTROYED';
  }
  delete store.credentials[userId];
}

export function getCredential(userId: string): any | null {
  const store = readStore();
  const cred = store.credentials[userId] || null;
  if (!cred) return null;

  // Verify HMAC — if tampered, force lock
  if (cred._hmac) {
    const expected = computeHmac(cred);
    if (cred._hmac !== expected) {
      cred.locked = true;
      cred.failedAttempts = 999;
      cred._hmac = computeHmac(cred);
      store.credentials[userId] = cred;
      writeStore(store);
    }
  }

  return cred;
}

export function saveCredential(credential: any): void {
  const store = readStore();

  // Self-destruct: if max failures reached and locked, wipe the credential entirely
  if (credential.failedAttempts >= 5 && credential.locked && credential._selfDestruct) {
    secureWipeCredential(store, credential.userId);
    writeStore(store);
    return;
  }

  credential._hmac = computeHmac(credential);
  store.credentials[credential.userId] = credential;
  writeStore(store);
}

export function listUsers(): string[] {
  const store = readStore();
  return Object.keys(store.credentials);
}

export function deleteCredential(userId: string): void {
  const store = readStore();
  secureWipeCredential(store, userId);
  writeStore(store);
}

export function listCredentialsByRpId(rpId: string): any[] {
  const store = readStore();
  return Object.values(store.credentials)
    .filter((cred: any) => cred.webauthn?.rpId === rpId);
}

export function exportCredential(userId: string): string | null {
  const cred = getCredential(userId);
  if (!cred) return null;
  const exportCred = { ...cred };
  delete exportCred._hmac;
  delete exportCred._selfDestruct;
  return JSON.stringify(exportCred, null, 2);
}

export function importCredential(jsonString: string): boolean {
  try {
    const cred = JSON.parse(jsonString);
    if (!cred.userId) return false;
    cred.failedAttempts = 0;
    cred.locked = false;
    delete cred._selfDestruct;
    saveCredential(cred);
    return true;
  } catch {
    return false;
  }
}

// --- MusiKey Protocol Service Operations ---

export function getServicesByUserId(userId: string): any[] {
  const cred = getCredential(userId);
  if (!cred) return [];
  return cred.services || [];
}

export function saveServiceRegistration(userId: string, service: any): boolean {
  const store = readStore();
  const cred = store.credentials[userId];
  if (!cred) return false;
  if (!cred.services) cred.services = [];
  // Replace existing service with same serviceId, or append
  const idx = cred.services.findIndex((s: any) => s.serviceId === service.serviceId);
  if (idx >= 0) {
    cred.services[idx] = service;
  } else {
    cred.services.push(service);
  }
  cred._hmac = computeHmac(cred);
  store.credentials[userId] = cred;
  writeStore(store);
  return true;
}

export function removeServiceRegistration(userId: string, serviceId: string): boolean {
  const store = readStore();
  const cred = store.credentials[userId];
  if (!cred || !cred.services) return false;
  const before = cred.services.length;
  cred.services = cred.services.filter((s: any) => s.serviceId !== serviceId);
  if (cred.services.length === before) return false;
  cred._hmac = computeHmac(cred);
  store.credentials[userId] = cred;
  writeStore(store);
  return true;
}
