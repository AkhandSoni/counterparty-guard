import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
export const aliases = {
 '@counterparty-guard/shared':fileURLToPath(new URL('./packages/shared/src/index.ts',import.meta.url)),
 '@counterparty-guard/providers':fileURLToPath(new URL('./packages/providers/src/index.ts',import.meta.url)),
 '@counterparty-guard/scoring':fileURLToPath(new URL('./packages/scoring/src/index.ts',import.meta.url)),
};
export default defineConfig({resolve:{alias:aliases},test:{include:['packages/{shared,providers,scoring}/**/*.test.ts','apps/api/**/*.test.ts'],testTimeout:10000}});
