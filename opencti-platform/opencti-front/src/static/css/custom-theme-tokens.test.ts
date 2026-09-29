/**
 * Locks custom-theme-tokens.css: every rule, applied to the library's own palette,
 * must land on the library's own value — so under a custom theme a field, a border
 * or a hover sits the same distance from its surface as it does in the default one.
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
const oklab = (hex: string): number[] => {
  const [r, g, b] = [1, 3, 5].map((i) => lin(parseInt(hex.slice(i, i + 2), 16) / 255));
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,
  ];
};

/** Resolves a declared value against the library palette, as the browser would with no override. */
const resolve = (mode: Mode, value: string): number[] => {
  const palette = FDS.colors[mode] as Record<string, string>;
  const ref = (v: string): number[] => {
    if (v === 'black') return oklab('#000000');
    if (v === 'white') return oklab('#ffffff');
    const name = /^var\((--[\w-]+)\)$/.exec(v)?.[1];
    if (!name) throw new Error(`unsupported value: ${v}`);
    const own = decls.find((d) => d.mode === mode && d.token === name);
    return own ? resolve(mode, own.value) : oklab(palette[name]);
  };
  const mix = /^color-mix\(in oklab,\s*(.+?),\s*(\S+)\s+(\d+)%\)$/.exec(value);
  if (!mix) return ref(value);
  const [a, b, p] = [ref(mix[1]), ref(mix[2]), Number(mix[3]) / 100];
  return a.map((x, i) => x * (1 - p) + b[i] * p);
};

const FAMILIES = ['bg-elevation-highlight', 'bg-elevation-hover', 'bg-elevation-heading',
  'border-elevation-subtle', 'border-elevation-subtle-soft', 'border-elevation-default'];

describe('custom-theme-tokens.css', () => {
  it('parses into declarations', () => {
    expect(decls.length).toBeGreaterThan(60);
  });

  it.each(['dark', 'light'] as Mode[])('reproduces the library lightness step for every member in %s', (mode) => {
    const palette = FDS.colors[mode] as Record<string, string>;
    decls.filter((d) => d.mode === mode).forEach((d) => {
      const [lightness] = resolve(mode, d.value);
      expect(Math.abs(lightness - oklab(palette[d.token])[0]), `${mode} ${d.token}`).toBeLessThan(0.01);
    });
  });

  it.each(['dark', 'light'] as Mode[])('covers every per-layer family in %s, not the few a screenshot showed', (mode) => {
    const tokens = new Set(decls.filter((d) => d.mode === mode).map((d) => d.token));
    [0, 1, 2, 3].forEach((layer) => FAMILIES.forEach((family) => {
      expect(tokens.has(`--${family}-layer-${layer}`), `--${family}-layer-${layer}`).toBe(true);
    }));
    expect(tokens.has('--bg-elevation-default-layer-2')).toBe(true);
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
