/**
 * Locks custom-theme-tokens.css: every rule, applied to the library's own palette,
 * must land on the library's own value — lightness AND chroma, so under a custom theme
 * a field, a border or a hover sits the same distance from its surface, and carries as
 * much colour, as it does in the default one. The one exception is the `highlight`
 * family, floored so a field never vanishes into its modal.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FDS } from '../../components/fds-tokens.generated';

const css = fs.readFileSync(path.join(__dirname, 'custom-theme-tokens.css'), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '');

type Mode = 'dark' | 'light';
interface Decl { mode: Mode; setting: string; token: string; value: string }

const decls: Decl[] = [...css.matchAll(/:root\.(dark|light)\.fds-custom-(\w+)\s*\{([^}]*)\}/g)]
  .flatMap(([, mode, setting, body]) => [...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)]
    .map(([, token, value]) => ({ mode: mode as Mode, setting, token, value: value.trim() })));

const lin = (c: number) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const oklch = (hex: string): [number, number, number] => {
  const [r, g, b] = [1, 3, 5].map((i) => lin(parseInt(hex.slice(i, i + 2), 16) / 255));
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const A = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s;
  const B = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s;
  return [0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s, Math.hypot(A, B),
    ((Math.atan2(B, A) * 180) / Math.PI + 360) % 360];
};

const RULE = /^oklch\(from var\((--[\w-]+)\) calc\(l ([+-]) ([\d.]+)\) (?:(min|max)\(calc\(c \* ([\d.]+)\), )?calc\(c ([+-]) ([\d.]+)\)\)? h\)$/;

/** Resolves a declared value against the library palette, as the browser would with no override. */
const resolve = (mode: Mode, value: string): [number, number, number] => {
  const palette = FDS.colors[mode] as Record<string, string>;
  const ref = (name: string): [number, number, number] => {
    const own = decls.find((d) => d.mode === mode && d.token === name);
    return own ? resolve(mode, own.value) : oklch(palette[name]);
  };
  const plain = /^var\((--[\w-]+)\)$/.exec(value);
  if (plain) return ref(plain[1]);
  const r = RULE.exec(value);
  if (!r) throw new Error(`unsupported value: ${value}`);
  const [, root, lSign, lStep, pick, factor, cSign, cStep] = r;
  const [L, C, H] = ref(root);
  const shifted = C + (cSign === '+' ? 1 : -1) * Number(cStep);
  // No factor: the surface is achromatic, so only the shift carries the colour.
  const chroma = pick === undefined ? shifted
    : (pick === 'min' ? Math.min(C * Number(factor), shifted) : Math.max(C * Number(factor), shifted));
  return [L + (lSign === '+' ? 1 : -1) * Number(lStep), Math.max(0, chroma), H];
};

/** The library's own best surface-to-field step: the floor the highlight family may not go under. */
const floorOf = (mode: Mode): number => {
  const palette = FDS.colors[mode] as Record<string, string>;
  return [0, 1, 2, 3].reduce((best, layer) => Math.max(best, Math.abs(
    oklch(palette[`--bg-elevation-highlight-layer-${layer}`])[0]
    - oklch(palette[`--bg-elevation-default-layer-${layer}`])[0],
  )), 0);
};

const FAMILIES = ['bg-elevation-highlight', 'bg-elevation-hover', 'bg-elevation-heading',
  'border-elevation-subtle', 'border-elevation-subtle-soft', 'border-elevation-default'];

describe('custom-theme-tokens.css', () => {
  it('parses into declarations', () => {
    expect(decls.length).toBeGreaterThan(60);
  });

  it.each(['dark', 'light'] as Mode[])('reproduces the library value, chroma included, in %s', (mode) => {
    const palette = FDS.colors[mode] as Record<string, string>;
    const floor = floorOf(mode);
    decls.filter((d) => d.mode === mode).forEach((d) => {
      const [L, C, H] = resolve(mode, d.value);
      const [libL, libC] = oklch(palette[d.token]);
      // A floored member sits further from its surface than the library puts it, on purpose,
      // so it is the floor that holds it, not the library's value. The next test covers it.
      const layer = /^--bg-elevation-highlight-layer-(\d)$/.exec(d.token)?.[1];
      if (layer !== undefined
        && Math.abs(libL - oklch(palette[`--bg-elevation-default-layer-${layer}`])[0]) < floor) return;
      expect(Math.abs(L - libL), `${mode} ${d.token} L`).toBeLessThan(0.01);
      expect(Math.abs(C - libC), `${mode} ${d.token} C`).toBeLessThan(0.005);
      // The hue is the customer's, never the library's: its own palette drifts up to 22 degrees
      // between a surface and its members, and rotating a chosen colour by that much changes it.
      const [, rootC, rootH] = resolve(mode, `var(${/var\((--[\w-]+)\)/.exec(d.value)?.[1]})`);
      if (rootC > 0.002) expect(H, `${mode} ${d.token} H`).toBeCloseTo(rootH, 6);
    });
  });

  it.each(['dark', 'light'] as Mode[])('never lets a field sit closer to its surface than the floor in %s', (mode) => {
    const floor = floorOf(mode);
    [0, 1, 2, 3].forEach((layer) => {
      const field = decls.find((d) => d.mode === mode && d.token === `--bg-elevation-highlight-layer-${layer}`);
      if (!field) return;
      const [L] = resolve(mode, field.value);
      const [base] = resolve(mode, `var(--bg-elevation-default-layer-${layer})`);
      expect(Math.abs(L - base), `${mode} layer-${layer}`).toBeGreaterThanOrEqual(floor - 0.001);
    });
  });

  it.each(['dark', 'light'] as Mode[])('covers every per-layer family in %s, not the few a screenshot showed', (mode) => {
    const tokens = new Set(decls.filter((d) => d.mode === mode).map((d) => d.token));
    [0, 1, 2, 3].forEach((layer) => FAMILIES.forEach((family) => {
      expect(tokens.has(`--${family}-layer-${layer}`), `--${family}-layer-${layer}`).toBe(true);
    }));
    expect(tokens.has('--bg-elevation-default-layer-2')).toBe(true);
    expect(tokens.has('--bg-elevation-default-layer-0-gradient')).toBe(true);
    expect(tokens.has('--color-filigran-brand-tertiary')).toBe(true);
    expect(tokens.has('--color-filigran-tonic-tertiary')).toBe(true);
    expect(tokens.has('--text-default-secondary')).toBe(true);
  });

  it('leaves the disabled families grey, because desaturation is what reads as disabled', () => {
    expect(decls.filter((d) => d.token.includes('-disabled-layer-'))).toEqual([]);
  });

  it('never writes a setting root, which the hook owns as an inline value', () => {
    const roots = ['--bg-elevation-default-layer-0', '--bg-elevation-default-layer-1',
      '--bg-elevation-default-layer-3', '--color-filigran-brand-primary',
      '--color-filigran-tonic-primary', '--text-default-primary'];
    expect(decls.filter((d) => roots.includes(d.token))).toEqual([]);
  });

  it('is loaded by the app entry', () => {
    // Order does not matter: `:root.dark.fds-custom-*` outranks the library's `.dark`.
    const entry = fs.readFileSync(path.join(__dirname, '../../front.tsx'), 'utf8');
    expect(entry).toContain("import './static/css/custom-theme-tokens.css';");
  });
});
