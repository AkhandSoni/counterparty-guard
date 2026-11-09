import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
export const aliases = {
 '@':fileURLToPath(new URL('./apps/web/src',import.meta.url)),
 '@counterparty-guard/shared/browser':fileURLToPath(new URL('./packages/shared/src/browser.ts',import.meta.url)),
 '@counterparty-guard/shared/demo':fileURLToPath(new URL('./packages/shared/src/demo.ts',import.meta.url)),
 '@counterparty-guard/shared':fileURLToPath(new URL('./packages/shared/src/index.ts',import.meta.url)),
 '@counterparty-guard/providers':fileURLToPath(new URL('./packages/providers/src/index.ts',import.meta.url)),
 '@counterparty-guard/scoring':fileURLToPath(new URL('./packages/scoring/src/index.ts',import.meta.url)),
 '@counterparty-guard/reputation':fileURLToPath(new URL('./packages/reputation/src/index.ts',import.meta.url)),
 '@counterparty-guard/fixtures':fileURLToPath(new URL('./fixtures/index.ts',import.meta.url)),
};
export default defineConfig({resolve:{alias:aliases},esbuild:{jsx:'automatic'},test:{include:['packages/**/*.test.ts','apps/**/*.test.{ts,tsx}','fixtures/**/*.test.ts','scripts/demo/**/*.test.ts','tests/regression/**/*.test.ts'],exclude:['**/node_modules/**','**/dist/**','**/dist-ts/**'],testTimeout:15000}});
