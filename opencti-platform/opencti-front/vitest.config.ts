import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import relay from "vite-plugin-relay";

export default defineConfig({
  plugins: [react(), relay],
  test: {
    environment: 'jsdom',
    setupFiles: 'src/__tests__/setup-relay-for-vitest.ts',
    include: ['src/__tests__/**/**/*.test.{ts,tsx}']
  },
})
