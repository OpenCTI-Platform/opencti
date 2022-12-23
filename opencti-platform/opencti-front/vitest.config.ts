import { defineConfig } from 'vitest/config'
import relay from 'vite-plugin-relay';
import react from "@vitejs/plugin-react";
import fs from 'fs/promises';

export default defineConfig({
  plugins: [relay, react()],
  test: {
    globals: true,
    include: ['src/tests/*.test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    testTimeout: 1200000,
    environment: 'jsdom',
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'json', 'html'],
    },
  },
  esbuild: {
    loader: "tsx",
    include: /src\/.*\.[tj]sx?$/,
    exclude: [],
  },
  optimizeDeps: {
    esbuildOptions: {
      plugins: [
        {
          name: "load-js-files-as-jsx",
          setup(build) {
            build.onLoad({ filter: /src\/.*\.(js|ts)$/ }, async (args) => ({
              loader: "tsx",
              contents: await fs.readFile(args.path, "utf8"),
            }));
          },
        },
      ],
    },
  },
})
