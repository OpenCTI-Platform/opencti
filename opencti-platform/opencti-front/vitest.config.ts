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
    // A worker now lives for the whole run. Without a cap of its own it
    // inherits the main process heap limit (8 GB in CI) and V8 collects so
    // lazily that four workers fill the runner. Live heap stays under 1 GB.
    execArgv: ['--max-old-space-size=2048'],
    // UI tests driven through user-event run ~10x slower on the CI runner
    // (coverage, 4 shared vCPUs) than locally, and the 5 s default trips on a
    // few of them. 15 s still flags a real hang.
    testTimeout: 15_000,
    // Opt-in order check: with isolate: false a test can depend on what ran
    // before it in the same worker. `yarn test:shuffle`, optionally with
    // --sequence.seed=<n> to replay a failing order.
    sequence: { shuffle: process.env.VITEST_SHUFFLE === 'true' },
    include: ['src/**/*.test.{ts,tsx}'],
    globals: true,
    server: {
      deps: {
        inline: ['formik-mui', 'react-virtualized'],
      },
    },
    coverage: {
      enabled: false,
      provider: 'istanbul',
      reporter: ['json', 'html'],
      reportsDirectory: './coverage/unit',
      include: ['src/**/*.{js,jsx,ts,tsx}'],
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
