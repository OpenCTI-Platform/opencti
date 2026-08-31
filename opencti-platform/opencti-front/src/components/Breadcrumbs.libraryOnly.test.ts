import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The page path is drawn by the library, and by one file.
 */

const WRAPPER = 'src/components/Breadcrumbs.tsx';

/**
 * Comments are blanked before anything is asserted.
 */
const stripComments = (text: string) => text
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/(^|[^:])\/\/.*$/gm, '$1');

const source = stripComments(readFileSync(path.resolve(WRAPPER), 'utf8'));

describe('the page path is built from the library', () => {
  it('takes Breadcrumbs from the design system', () => {
    expect(source).toMatch(/import \{[^}]*\bBreadcrumbs\b[^}]*\} from '@filigran\/design-system'/s);
  });

  it('imports no MUI symbol', () => {
    // Typography, useTheme and the Theme type all left with the hand-built path.
    expect(source).not.toMatch(/from '@mui\//);
  });

  it('cuts no label by character count', () => {
    // truncate(label, 30) / truncate(label, 50) were the product's own
    // truncation; the library ellipsizes in CSS and keeps the full string.
    expect(source).not.toMatch(/\btruncate\s*\(/);
  });

  it('passes destinations as `to`, never as `href`', () => {
    expect(source).toMatch(/\bto:\s*link\b/);
    expect(source).not.toMatch(/\bhref:\s/);
  });

  it('hands the router link component over once, at this single call site', () => {
    expect(source).toMatch(/linkComponent=\{Link\}/);
  });

  it('names the landmark through the product translations', () => {
    // The library default is the English literal; this host is localised.
    expect(source).toMatch(/label=\{t_i18n\('Breadcrumb'\)\}/);
  });

  it('keeps the id the data grid reads and the test id the e2e models read', () => {
    expect(source).toMatch(/id="page-breadcrumb"/);
    expect(source).toMatch(/data-testid="navigation"/);
  });

  it('states the bottom margin on the library spacing scale', () => {
    // theme.spacing(1) was 8px; a bare number in an sx was spacing units, not
    // pixels, so the equivalent is mb-2 and never mb-1.
    expect(source).toMatch(/\bmb-2\b/);
    expect(source).not.toMatch(/\bmb-1\b/);
  });
});
