import path from 'path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  server: { host: '127.0.0.1', port: 5173, proxy: { '/v1': 'http://127.0.0.1:3000', '/health': 'http://127.0.0.1:3000' } },
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@counterparty-guard/shared/browser': path.resolve(__dirname, '../../packages/shared/src/browser.ts'),
      '@counterparty-guard/shared/demo': path.resolve(__dirname, '../../packages/shared/src/demo.ts'),
      '@counterparty-guard/shared': path.resolve(__dirname, '../../packages/shared/src/browser.ts'),
    },
  },

});
