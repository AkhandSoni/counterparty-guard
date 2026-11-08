import path from 'path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    jsx: 'automatic'
  },
  test: {
    globals: true,
    environment: 'node',
    include: [
      'packages/**/*.test.ts',
      'apps/**/*.test.{ts,tsx}',
      'tests/**/*.test.{ts,tsx}',
      'fixtures/**/*.test.{ts,tsx}',
      'scripts/**/*.test.{ts,tsx}'
    ],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/dist-ts/**',
      '**/.agents/**',
      '**/counterparty-guard-plan/**',
      '**/contracts/**'
    ],
    passWithNoTests: true
  },
  resolve: {
    alias: {
      '@counterparty-guard/shared': path.resolve(__dirname, './packages/shared/src/index.ts'),
      '@counterparty-guard/reputation': path.resolve(__dirname, './packages/reputation/src/index.ts'),
      '@counterparty-guard/fixtures': path.resolve(__dirname, './fixtures/index.ts'),
      '@': path.resolve(__dirname, './apps/web/src')
    }
  }
});
