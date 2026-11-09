import { copyFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [
    preact(),
    viteSingleFile(),
    {
      name: 'copy-standalone-vaultkeep',
      closeBundle() {
        copyFileSync(resolve(__dirname, 'dist/index.html'), resolve(__dirname, 'vaultkeep.html'));
      },
    },
  ],
  build: {
    target: 'es2022',
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
  },
});
