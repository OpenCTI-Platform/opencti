import { readFileSync } from 'fs';
import { join } from 'path';
import { test, expect } from '@playwright/test';

/**
 * Validates that the Vite production build is correctly configured for
 * non-root base path hosting (APP__BASE_PATH support).
 *
 * Two build-time requirements:
 * 1. `base: './'` in vite.config.ts  → asset paths must be relative (./assets/...)
 *    so they resolve correctly under any <base href>.
 * 2. `<base href="%BASE_PATH%/">` in index.html template → backend replaces the
 *    placeholder at runtime so the browser resolves relative assets to the right subpath.
 *
 * These tests run as part of the setup project (before any browser tests) and
 * fail fast if either fix is accidentally reverted.
 */

const distIndexHtml = readFileSync(join(process.cwd(), 'dist/index.html'), 'utf8');

test('dist/index.html — asset paths are relative (not absolute)', () => {
  expect(distIndexHtml).not.toMatch(/src="\/assets\//);
  expect(distIndexHtml).not.toMatch(/href="\/assets\//);
  expect(distIndexHtml).toMatch(/src="\.\/assets\//);
});

test('dist/index.html — base href contains BASE_PATH placeholder for runtime injection', () => {
  expect(distIndexHtml).toContain('<base href="%BASE_PATH%/">');
});
