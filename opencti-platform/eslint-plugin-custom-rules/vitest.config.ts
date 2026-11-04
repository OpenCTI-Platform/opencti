import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // ESLint's RuleTester registers its cases through the global `describe` / `it`.
    globals: true,
    environment: 'node',
  },
});
