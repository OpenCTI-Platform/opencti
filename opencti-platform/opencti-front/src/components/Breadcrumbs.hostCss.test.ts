/**
 * Locks FDS-WORKAROUND #40 (LIBRARY-FEEDBACK.md #40): the breadcrumb link keeps its
 * underline on hover and on focus. Static guard; cascade analysis and the reason a
 * browser measurement is the real proof: see fds-migration/MIGRATION-DECISIONS.md#breadcrumb-underline
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const FRONT_SRC = path.join(__dirname, '..');
const HOST_CSS = 'static/css/design-system-host.css';

const read = (relative: string) => fs.readFileSync(path.join(FRONT_SRC, relative), 'utf8');

const loadOrder = () => {
  const entry = read('front.tsx');
  return [...entry.matchAll(/^import\s+['"]([^'"]+\.css)['"];?$/gm)].map((m) => m[1]);
};

interface Rule { selector: string; body: string; sheet: string; order: number }

const rulesOf = (css: string, sheet: string, order: number): Rule[] => {
  const stripped = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const rules: Rule[] = [];
  for (const match of stripped.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = match[1].trim();
    if (!selector || selector.startsWith('@')) continue;
    rules.push({ selector, body: match[2], sheet, order });
  }
  return rules;
};

const specificity = (selector: string): [number, number, number] => {
  const ids = (selector.match(/#[\w-]+/g) ?? []).length;
  const classes = (selector.match(/\.[\w-]+|\[[^\]]+\]|:(?!:)(?!hover\b|focus\b|visited\b)[\w-]+/g) ?? []).length
    + (selector.match(/:(?:hover|focus|visited)\b/g) ?? []).length;
  const types = (selector.match(/(?:^|[\s>+~])([a-z][\w-]*)/g) ?? []).length;
  return [ids, classes, types];
};

const beats = (a: Rule, b: Rule) => {
  const sa = specificity(a.selector);
  const sb = specificity(b.selector);
  for (let i = 0; i < 3; i += 1) {
    if (sa[i] !== sb[i]) return sa[i] > sb[i];
  }
  return a.order > b.order;
};

const reachesBreadcrumbLink = (selector: string) => selector
  .split(',')
  .map((part) => part.trim())
  .some((part) => {
    if (!/:(?:hover|focus)\b/.test(part)) return false;
    if (/#page-breadcrumb\b/.test(part)) return true;
    // A bare anchor selector — `a:hover`, `a:focus` — reaches every link in the application,
    // the breadcrumb's included.
    return /^a:(?:hover|focus)$/.test(part.replace(/:visited\b/g, ''));
  });

const removesTheLine = (body: string) => /text-decoration(?:-line)?\s*:\s*(?!underline)[^;]*/.test(body)
  && !/text-decoration-line\s*:\s*underline/.test(body);

const allRules = (): Rule[] => {
  const require = createRequire(import.meta.url);
  const order = loadOrder();
  const out: Rule[] = [];
  order.forEach((specifier, index) => {
    const file = specifier.startsWith('.')
      ? path.join(FRONT_SRC, specifier.replace(/^\.\//, ''))
      : require.resolve(specifier);
    out.push(...rulesOf(fs.readFileSync(file, 'utf8'), specifier, index));
  });
  return out;
};

describe('the breadcrumb link keeps its underline on hover and on focus', () => {
  it('loads the host stylesheet after the library and the product globals', () => {
    // The tie-break below is only meaningful if this holds.
    const order = loadOrder();
    const host = order.findIndex((s) => s.endsWith(HOST_CSS));
    expect(host, `${HOST_CSS} is not imported by front.tsx`).toBeGreaterThan(-1);
    expect(host).toBe(order.length - 1);
  });

  it('declares the underline on the landmark, for both states', () => {
    const host = rulesOf(read(HOST_CSS), HOST_CSS, 99)
      .filter((r) => r.selector.includes('#page-breadcrumb') && /text-decoration-line\s*:\s*underline/.test(r.body));
    expect(host.length, 'no host rule restores the underline on #page-breadcrumb').toBe(1);
    for (const state of [':hover', ':focus']) {
      expect(host[0].selector, `the host rule does not cover a${state}`).toContain(`a${state}`);
    }
  });

  it('wins over every rule in the served CSS that would take the line away', () => {
    const rules = allRules();
    const winner = rules.find((r) => r.selector.includes('#page-breadcrumb')
      && /text-decoration-line\s*:\s*underline/.test(r.body));
    expect(winner, 'the workaround rule is absent from the loaded stylesheets').toBeDefined();

    const competitors = rules.filter((r) => reachesBreadcrumbLink(r.selector) && removesTheLine(r.body));
    // The defect this guards against exists because such a rule DOES ship. If
    // the sweep finds none, it is the sweep that broke, not the product.
    expect(competitors.length, 'found no anchor reset at all — the sweep stopped matching').toBeGreaterThan(0);

    const lost = competitors
      .filter((c) => !beats(winner as Rule, c))
      .map((c) => `${c.sheet}: ${c.selector.replace(/\s+/g, ' ')}`);
    expect(lost).toEqual([]);
  });
});
