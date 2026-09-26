import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import os from 'os';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  cacheDir: path.join(os.tmpdir(), 'vite-aws-scanner'),
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'https://sec-plat.hnsolutions.in', changeOrigin: true, secure: true },
      '/socket.io': { target: 'https://sec-plat.hnsolutions.in', ws: true, changeOrigin: true, secure: true },
    },
  },
});
