import { readFile } from 'node:fs/promises';
import { describe, it, expect } from 'vitest';

/**
 * Validates build configuration invariants for non-root base path hosting (APP__BASE_PATH).
 *
 * Two source-level requirements:
 * 1. `base: './'` in vite.config.ts → produces relative asset paths in the build output
 *    so they resolve correctly under any <base href>.
 * 2. `<base href="%BASE_PATH%/">` in index.html → the backend replaces the placeholder
 *    at runtime so the browser resolves relative assets to the right subpath.
 *
 * These checks run against source files so no production build is required.
 */

const indexHtml = await readFile('dist/index.html', 'utf8');
const viteConfig = await readFile('vite.config.ts', 'utf8');

describe('base path build configuration', () => {
  it('index.html — contains BASE_PATH placeholder in <base href> for runtime injection', () => {
    expect(indexHtml).toContain('<base href="%BASE_PATH%/">');
  });

  it('index.html — static asset references are relative (not absolute)', () => {
    expect(indexHtml).not.toMatch(/src="\/assets\//);
    expect(indexHtml).not.toMatch(/href="\/assets\//);
    expect(indexHtml).toMatch(/src="\.\/assets\//);
  });

  it('vite.config.ts — base is set to relative "./" so built assets use relative paths', () => {
    expect(viteConfig).toMatch(/base:\s*['"]\.\/['"]/);
  });
});
