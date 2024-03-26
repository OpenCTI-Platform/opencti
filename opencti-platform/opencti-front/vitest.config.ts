import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import relay from "vite-plugin-relay";

export default defineConfig({
  plugins: [react(), relay],
  test: {
    environment: 'jsdom',
    setupFiles: './setup-vitest.ts',
    include: ['src/**/**/*.test.{ts,tsx}'],
    globals: true
  },
})
