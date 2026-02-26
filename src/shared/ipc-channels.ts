export const IPC = {
  GET_CREDENTIAL: 'store:getCredential',
  SAVE_CREDENTIAL: 'store:saveCredential',
  LIST_USERS: 'store:listUsers',
  DELETE_CREDENTIAL: 'store:deleteCredential',
  EXPORT_CREDENTIAL: 'store:exportCredential',
  IMPORT_CREDENTIAL: 'store:importCredential',
  SHOW_SAVE_DIALOG: 'dialog:showSave',
  SHOW_OPEN_DIALOG: 'dialog:showOpen',
} as const;
