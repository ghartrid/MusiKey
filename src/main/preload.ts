const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('musikeyStore', {
  getCredential: (userId: string) => ipcRenderer.invoke('store:getCredential', userId),
  saveCredential: (cred: any) => ipcRenderer.invoke('store:saveCredential', cred),
  listUsers: () => ipcRenderer.invoke('store:listUsers'),
  deleteCredential: (userId: string) => ipcRenderer.invoke('store:deleteCredential', userId),
  exportCredential: (userId: string) => ipcRenderer.invoke('store:exportCredential', userId),
  importCredential: (json: string) => ipcRenderer.invoke('store:importCredential', json),
  showSaveDialog: (defaultName: string) => ipcRenderer.invoke('dialog:showSave', defaultName),
  showOpenDialog: () => ipcRenderer.invoke('dialog:showOpen'),
  cascadedKDF: (passphrase: string, saltB64: string, iterations: number) =>
    ipcRenderer.invoke('crypto:cascadedKDF', passphrase, saltB64, iterations),
});
