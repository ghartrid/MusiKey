const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('musikeyStore', {
  getCredential: (userId: string) => ipcRenderer.invoke('store:getCredential', userId),
  saveCredential: (cred: any) => ipcRenderer.invoke('store:saveCredential', cred),
  listUsers: () => ipcRenderer.invoke('store:listUsers'),
  deleteCredential: (userId: string) => ipcRenderer.invoke('store:deleteCredential', userId),
  listByRpId: (rpId: string) => ipcRenderer.invoke('store:listByRpId', rpId),
  exportCredential: (userId: string) => ipcRenderer.invoke('store:exportCredential', userId),
  importCredential: (json: string) => ipcRenderer.invoke('store:importCredential', json),
  showSaveDialog: (defaultName: string) => ipcRenderer.invoke('dialog:showSave', defaultName),
  showOpenDialog: () => ipcRenderer.invoke('dialog:showOpen'),
  writeFile: (filePath: string, data: string) => ipcRenderer.invoke('fs:writeFile', filePath, data),
  cascadedKDF: (passphrase: string, saltB64: string, iterations: number) =>
    ipcRenderer.invoke('crypto:cascadedKDF', passphrase, saltB64, iterations),
  legacyCascadedKDF: (passphrase: string, saltB64: string, iterations: number) =>
    ipcRenderer.invoke('crypto:legacyCascadedKDF', passphrase, saltB64, iterations),
  getServices: (userId: string) => ipcRenderer.invoke('store:getServices', userId),
  saveService: (userId: string, service: any) => ipcRenderer.invoke('store:saveService', userId, service),
  removeService: (userId: string, serviceId: string) => ipcRenderer.invoke('store:removeService', userId, serviceId),
  // Protocol server events
  onProtocolChallenge: (callback: (data: any) => void) => ipcRenderer.on('protocol:challenge-received', (_e: any, data: any) => callback(data)),
  onProtocolRegister: (callback: (data: any) => void) => ipcRenderer.on('protocol:register-request', (_e: any, data: any) => callback(data)),
  sendProtocolChallengeResponse: (data: any) => ipcRenderer.send('protocol:challenge-response', data),
  sendProtocolRegisterResponse: (data: any) => ipcRenderer.send('protocol:register-response', data),
});
