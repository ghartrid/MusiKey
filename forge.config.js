module.exports = {
  packagerConfig: {
    name: 'MusiKey',
    icon: './assets/icon',
    asar: true,
  },
  makers: [
    { name: '@electron-forge/maker-zip', platforms: ['darwin', 'linux', 'win32'] },
    { name: '@electron-forge/maker-deb', config: { maintainer: 'Graham', homepage: '' } },
  ],
};
