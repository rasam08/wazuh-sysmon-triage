/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import { configDefaults } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';
import { triageApiMiddleware } from './server/triage-api';

function triageApiPlugin() {
  return {
    name: 'triage-api',
    configureServer(server: { middlewares: { use: (fn: typeof triageApiMiddleware) => void } }) {
      server.middlewares.use(triageApiMiddleware);
    },
    configurePreviewServer(server: { middlewares: { use: (fn: typeof triageApiMiddleware) => void } }) {
      server.middlewares.use(triageApiMiddleware);
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), triageApiPlugin()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
