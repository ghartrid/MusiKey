const { app, BrowserWindow, ipcMain, dialog } = require('electron');
import * as path from 'path';
import * as fs from 'fs';
import * as nodeCrypto from 'crypto';
import * as store from './store';

let mainWindow: any = null;

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 700,
    height: 720,
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

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers
ipcMain.handle('store:getCredential', (_e: any, userId: string) => store.getCredential(userId));
ipcMain.handle('store:saveCredential', (_e: any, cred: any) => store.saveCredential(cred));
ipcMain.handle('store:listUsers', () => store.listUsers());
ipcMain.handle('store:deleteCredential', (_e: any, userId: string) => store.deleteCredential(userId));
ipcMain.handle('store:exportCredential', (_e: any, userId: string) => store.exportCredential(userId));
ipcMain.handle('store:importCredential', (_e: any, json: string) => store.importCredential(json));

// Cascaded KDF: PBKDF2 (600k) → scrypt (N=2^17, r=8, p=1) → 32-byte key
// scrypt is memory-hard (128 * N * r = 128MB), resistant to GPU/ASIC attacks
ipcMain.handle('crypto:cascadedKDF', async (_e: any, passphrase: string, saltB64: string, pbkdf2Iterations: number) => {
  const salt = Buffer.from(saltB64, 'base64');

  // Stage 1: PBKDF2-SHA256 (CPU-hard, 600k iterations)
  const pbkdf2Key = nodeCrypto.pbkdf2Sync(passphrase, salt, pbkdf2Iterations, 32, 'sha256');

  // Stage 2: scrypt (memory-hard, N=2^17=131072, r=8, p=1, 128*N*r = 128MB)
  const scryptSalt = nodeCrypto.createHash('sha256').update(salt).update('scrypt-stage').digest();
  const finalKey = nodeCrypto.scryptSync(pbkdf2Key, scryptSalt, 32, {
    N: 131072, // 2^17
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024, // 256MB max
  });

  // Zero intermediate key
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
