module.exports = {
  packagerConfig: {
    name: 'MusiKey',
    executableName: 'musikey',
    icon: './assets/icon',
    asar: true,
    appBundleId: 'com.musikey.app',
    appCategoryType: 'public.app-category.utilities',
  },
  makers: [
    {
      name: '@electron-forge/maker-zip',
      platforms: ['darwin', 'linux', 'win32'],
    },
    {
      name: '@electron-forge/maker-deb',
      config: {
        options: {
          maintainer: 'Graham',
          homepage: 'https://github.com/ghartrid/MusiKey',
          description: 'Musical entropy-based authentication — turns passphrases into encrypted musical compositions',
          section: 'utils',
          categories: ['Utility', 'Security'],
        },
      },
    },
  ],
};
