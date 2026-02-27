const { app, BrowserWindow, ipcMain, dialog, screen } = require('electron');
import * as path from 'path';
import * as fs from 'fs';
import * as nodeCrypto from 'crypto';
import * as argon2 from 'argon2';
import * as store from './store';
import { startProtocolServer, stopProtocolServer } from './protocol-server';

let mainWindow: any = null;

// Derive a deterministic pepper from machine fingerprint — never stored on disk
function derivePepper(): Buffer {
  const parts = [
    require('os').hostname(),
    require('os').userInfo().username,
    require('os').cpus()[0]?.model || 'unknown-cpu',
    require('os').platform(),
    require('os').arch(),
    require('os').release(),
  ];
  // Add MAC addresses
  const nets = require('os').networkInterfaces();
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

  const fingerprint = parts.join('::musikey-pepper::');
  return nodeCrypto.createHash('sha256').update(fingerprint).digest();
}

// Mix pepper into passphrase: HMAC-SHA256(pepper, passphrase) → peppered input for KDF
function pepperPassphrase(passphrase: string): Buffer {
  const pepper = derivePepper();
  return nodeCrypto.createHmac('sha256', pepper).update(passphrase).digest();
}

function createWindow(): void {
  const { height: screenHeight } = screen.getPrimaryDisplay().workAreaSize;
  const winHeight = Math.min(1050, screenHeight - 40);

  mainWindow = new BrowserWindow({
    width: 700,
    height: winHeight,
    minWidth: 600,
    minHeight: 600,
    title: 'MusiKey',
    backgroundColor: '#1a1a2e',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  mainWindow.setMenuBarVisibility(false);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();
  if (mainWindow) startProtocolServer(mainWindow);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
      if (mainWindow) startProtocolServer(mainWindow);
    }
  });
});

app.on('window-all-closed', () => {
  stopProtocolServer();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers
ipcMain.handle('store:getCredential', (_e: any, userId: string) => store.getCredential(userId));
ipcMain.handle('store:saveCredential', (_e: any, cred: any) => store.saveCredential(cred));
ipcMain.handle('store:listUsers', () => store.listUsers());
ipcMain.handle('store:deleteCredential', (_e: any, userId: string) => store.deleteCredential(userId));
ipcMain.handle('store:listByRpId', (_e: any, rpId: string) => store.listCredentialsByRpId(rpId));
ipcMain.handle('store:exportCredential', (_e: any, userId: string) => store.exportCredential(userId));
ipcMain.handle('store:importCredential', (_e: any, json: string) => store.importCredential(json));
ipcMain.handle('store:getServices', (_e: any, userId: string) => store.getServicesByUserId(userId));
ipcMain.handle('store:saveService', (_e: any, userId: string, service: any) => store.saveServiceRegistration(userId, service));
ipcMain.handle('store:removeService', (_e: any, userId: string, serviceId: string) => store.removeServiceRegistration(userId, serviceId));

// Cascaded KDF: PBKDF2 (600k) → Argon2id (128MB, t=3) → 32-byte key
// Argon2id is memory-hard + GPU/ASIC resistant (winner of Password Hashing Competition)
ipcMain.handle('crypto:cascadedKDF', async (_e: any, passphrase: string, saltB64: string, pbkdf2Iterations: number) => {
  const salt = Buffer.from(saltB64, 'base64');
  const peppered = pepperPassphrase(passphrase);

  // Stage 1: PBKDF2-SHA256 (CPU-hard, 600k iterations) with peppered passphrase
  const pbkdf2Key = nodeCrypto.pbkdf2Sync(peppered, salt, pbkdf2Iterations, 32, 'sha256');
  peppered.fill(0);

  // Stage 2: Argon2id (memory-hard, 128MB, 3 iterations, 1 thread)
  const argon2Salt = nodeCrypto.createHash('sha256').update(salt).update('argon2-stage').digest();
  const finalKey = await argon2.hash(pbkdf2Key, {
    type: argon2.argon2id,
    memoryCost: 131072, // 128MB
    timeCost: 3,
    parallelism: 1,
    hashLength: 32,
    salt: argon2Salt,
    raw: true,
  });

  // Zero intermediate key
  pbkdf2Key.fill(0);

  return Buffer.from(finalKey).toString('base64');
});

// Legacy cascaded KDF: PBKDF2 → scrypt (for v2 credential migration)
ipcMain.handle('crypto:legacyCascadedKDF', async (_e: any, passphrase: string, saltB64: string, pbkdf2Iterations: number) => {
  const salt = Buffer.from(saltB64, 'base64');

  // Stage 1: PBKDF2-SHA256 (NO pepper — must match original v2 encryption)
  const pbkdf2Key = nodeCrypto.pbkdf2Sync(passphrase, salt, pbkdf2Iterations, 32, 'sha256');

  // Stage 2: scrypt (legacy)
  const scryptSalt = nodeCrypto.createHash('sha256').update(salt).update('scrypt-stage').digest();
  const finalKey = nodeCrypto.scryptSync(pbkdf2Key, scryptSalt, 32, {
    N: 131072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });

  pbkdf2Key.fill(0);

  return finalKey.toString('base64');
});

ipcMain.handle('dialog:showSave', async (_e: any, defaultName: string) => {
  if (!mainWindow) return null;
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: defaultName,
    filters: [{ name: 'MusiKey Credential', extensions: ['musikey'] }],
  });
  if (result.canceled || !result.filePath) return null;
  return result.filePath;
});

ipcMain.handle('fs:writeFile', async (_e: any, filePath: string, data: string) => {
  try {
    fs.writeFileSync(filePath, data, 'utf-8');
    return true;
  } catch {
    return false;
  }
});

ipcMain.handle('dialog:showOpen', async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    filters: [{ name: 'MusiKey Credential', extensions: ['musikey'] }],
    properties: ['openFile'],
  });
  if (result.canceled || result.filePaths.length === 0) return null;
  try {
    return fs.readFileSync(result.filePaths[0], 'utf-8');
  } catch {
    return null;
  }
});
