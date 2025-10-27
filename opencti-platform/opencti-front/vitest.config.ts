import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import relay from "vite-plugin-relay";
import * as path from "node:path";

export default defineConfig({
  plugins: [react(), relay],
  test: {
    environment: 'jsdom',
    setupFiles: './setup-vitest.ts',
    include: ['src/**/*.test.{ts,tsx}'],
    globals: true,
    coverage: {
      enabled: false,
      provider: 'v8',
      reporter: ['json', 'html'],
      reportsDirectory: './coverage/unit',
      include: ["src/**"],
      exclude: [
        '**/node_modules/**',
        'dist/**',
        'coverage/**',
        'tests-results/**',
        'packages/**',
        '**/__generated__'
      ]
    }
  },
  resolve: {
    alias: {
      '@components': path.resolve(__dirname, './src/private/components'),
    },
  }
})
