import { defineConfig } from 'vitest/config';
import { aliases } from './vitest.config.js';
export default defineConfig({resolve:{alias:aliases},test:{include:['tests/integration/**/*.test.ts'],testTimeout:15000}});
