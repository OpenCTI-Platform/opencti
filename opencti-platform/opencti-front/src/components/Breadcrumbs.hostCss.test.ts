/**
 * Locks FDS-WORKAROUND #40: the breadcrumb link keeps its underline on hover
 * and on focus.
 *
 * The library ships `.underline` as an UNLAYERED utility, so the cascade is
 * settled by specificity alone. At rest `.underline` (0,1,0) beats this
 * product's global `a` reset (0,0,1). On hover and on focus it loses, because
 * `a:hover` / `a:focus` are (0,1,1) — one pseudo-class above the utility — and
 * the shorthand `text-decoration: none` takes the line away. The host rule
 * scopes the fix to the landmark, which puts it at (1,1,1) and back in front.
 *
 * Neither repository can see that on its own: the library's gates never load a
 * product stylesheet, and no product gate reads the library's. So this guard
 * reads BOTH — the served `index.css` from the installed package and this
 * product's own global sheets — and settles the cascade the way a browser
 * would: specificity first, load order only as the tie-break, with the order
 * itself read from `front.tsx` rather than assumed.
 *
 * It is a static guard and says so. What proves the RENDERING is the browser
 * measurement recorded in LIBRARY-FEEDBACK.md #40, taken against two separate
 * CSS builds — with and without this block — because the first attempt at that
 * proof disabled a rule through `cssRules`, which is inaccessible under
 * `file://`, and so measured nothing at all. jsdom cannot stand in for it: it
 * resolves no cascade for `:hover`.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const FRONT_SRC = path.join(__dirname, '..');
const HOST_CSS = 'static/css/design-system-host.css';

const read = (relative: string) => fs.readFileSync(path.join(FRONT_SRC, relative), 'utf8');

/** The stylesheets the application loads, in the order `front.tsx` loads them. */
const loadOrder = () => {
  const entry = read('front.tsx');
  return [...entry.matchAll(/^import\s+['"]([^'"]+\.css)['"];?$/gm)].map((m) => m[1]);
};

interface Rule { selector: string; body: string; sheet: string; order: number }

/** Flattens a stylesheet into rules, ignoring at-rule wrappers we do not need. */
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

/** CSS specificity of a single compound selector, as (id, class, type). */
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

/** True when the selector applies to a breadcrumb link in the hover/focus state. */
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
