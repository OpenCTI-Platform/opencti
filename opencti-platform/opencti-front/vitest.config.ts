import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import relay from 'vite-plugin-relay';

export default defineConfig({
  plugins: [react(), relay],
  test: {
    environment: 'jsdom',
    setupFiles: './setup-vitest.ts',
    // Reuse each worker, its jsdom and the node_modules it loaded across test
    // files: per-file isolation spent most of the run re-importing them.
    // setup-vitest.ts resets modules, mocks and globals before each file.
    isolate: false,
    include: ['src/**/*.test.{ts,tsx}'],
    globals: true,
    server: {
      deps: {
        inline: ['formik-mui'],
      },
    },
    coverage: {
      enabled: false,
      provider: 'v8',
      reporter: ['json', 'html'],
      reportsDirectory: './coverage/unit',
      include: ['src/**'],
      exclude: [
        '**/node_modules/**',
        'dist/**',
        'coverage/**',
        'tests-results/**',
        'packages/**',
        '**/__generated__',
      ],
    },
  },
  resolve: {
    tsconfigPaths: true,
  },
});
