import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import os from 'os';
import path from 'path';

export default defineConfig(({ mode }) => {
  // API proxy target for the dev server. Defaults to the local CSPM API;
  // override with VITE_API_PROXY in web/.env.local (untracked) to test the
  // UI against a deployed stack, e.g. VITE_API_PROXY=https://sec-plat.example.com
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const target = env.VITE_API_PROXY || 'http://localhost:3001';
  const secure = target.startsWith('https://');
  return {
    plugins: [react()],
    cacheDir: path.join(os.tmpdir(), 'vite-aws-scanner'),
    server: {
      port: 5173,
      proxy: {
        '/api':       { target, changeOrigin: true, secure },
        '/socket.io': { target, ws: true, changeOrigin: true, secure },
      },
    },
  };
});
