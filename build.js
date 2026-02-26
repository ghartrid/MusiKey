const esbuild = require('esbuild');
const path = require('path');
const fs = require('fs');

// Bundle renderer code into a single JS file
esbuild.buildSync({
  entryPoints: [path.join(__dirname, 'src', 'renderer', 'renderer.ts')],
  bundle: true,
  outfile: path.join(__dirname, 'dist', 'renderer', 'renderer.js'),
  platform: 'browser',
  target: 'chrome120',
  format: 'iife',
  sourcemap: false,
  minify: false,
});

// Copy HTML and CSS to dist
const srcRenderer = path.join(__dirname, 'src', 'renderer');
const distRenderer = path.join(__dirname, 'dist', 'renderer');

fs.copyFileSync(
  path.join(srcRenderer, 'index.html'),
  path.join(distRenderer, 'index.html')
);
fs.copyFileSync(
  path.join(srcRenderer, 'styles.css'),
  path.join(distRenderer, 'styles.css')
);

console.log('Build complete');
