import { describe, expect, it } from 'vitest';
import { patchesForTheme, SUPERSEDED } from '../../../src/migrations/1787800000000-align-builtin-theme-rows-with-wcag-defaults';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../../../src/modules/theme/theme-constants';

const CURRENT = { Dark: DARK_DEFAULTS, Light: LIGHT_DEFAULTS } as const;

/**
 * The fields `1787822440159-add-filigran-built-in-themes` compares, and how it compares
 * them: `ThemeDefaultComparable` with a strict `===` on every key. Reproduced here so the
 * hand-off between the two migrations is asserted rather than assumed.
 */
const COMPARED_FIELDS = [
  'theme_background', 'theme_paper', 'theme_nav', 'theme_primary', 'theme_secondary',
  'theme_accent', 'theme_text_color', 'theme_logo', 'theme_logo_collapsed', 'theme_logo_login',
  'theme_login_aside_color', 'theme_login_aside_gradient_start', 'theme_login_aside_gradient_end',
  'theme_login_aside_image',
] as const;

const isThemeDefaultLike = (row: Record<string, unknown>, name: 'Dark' | 'Light') => COMPARED_FIELDS
  .every((key) => Object.prototype.hasOwnProperty.call(row, key)
    && row[key] === CURRENT[name][key as keyof typeof DARK_DEFAULTS])
  && row.built_in === true;

/**
 * A row as an existing installation carries it before either migration runs.
 * `which` picks among the historical defaults a field has had.
 */
const legacyRow = (name: 'Dark' | 'Light', which = 0) => ({
  ...Object.fromEntries(COMPARED_FIELDS.map((k) => [k, CURRENT[name][k as keyof typeof DARK_DEFAULTS]])),
  ...Object.fromEntries(Object.entries(SUPERSEDED[name])
    .map(([k, vals]) => [k, vals[Math.min(which, vals.length - 1)]])),
  built_in: true,
}) as Record<string, string | boolean>;

const applyPatches = (row: Record<string, unknown>, name: 'Dark' | 'Light') => {
  const patched = { ...row };
  for (const { key, value } of patchesForTheme(name, row as Record<string, string>)) {
    patched[key] = value[0];
  }
  return patched;
};

describe('align built-in theme rows with the WCAG defaults', () => {
  it('rewrites a row that still carries the superseded default', () => {
    const patches = patchesForTheme('Dark', { theme_primary: SUPERSEDED.Dark.theme_primary[0] });
    expect(patches).toEqual([{ key: 'theme_primary', value: [DARK_DEFAULTS.theme_primary] }]);
  });

  it('leaves an administrator colour untouched', () => {
    expect(patchesForTheme('Dark', { theme_primary: '#ff7a00' })).toEqual([]);
    expect(patchesForTheme('Light', { theme_secondary: '#8bff00' })).toEqual([]);
  });

  it('is idempotent — a row already on the current default is not rewritten', () => {
    expect(patchesForTheme('Dark', { theme_primary: DARK_DEFAULTS.theme_primary })).toEqual([]);
    expect(patchesForTheme('Light', { theme_secondary: LIGHT_DEFAULTS.theme_secondary })).toEqual([]);
  });

  it('matches the superseded value case-insensitively', () => {
    const patches = patchesForTheme('Light', { theme_secondary: SUPERSEDED.Light.theme_secondary[0].toUpperCase() });
    expect(patches).toEqual([{ key: 'theme_secondary', value: [LIGHT_DEFAULTS.theme_secondary] }]);
  });

  it('normalises a value that moved by letter case alone', () => {
    expect(patchesForTheme('Dark', { theme_text_color: '#F2F2F3' }))
      .toEqual([{ key: 'theme_text_color', value: [DARK_DEFAULTS.theme_text_color] }]);
    expect(patchesForTheme('Dark', { theme_text_color: DARK_DEFAULTS.theme_text_color })).toEqual([]);
  });

  it('touches no field the bridge did not move', () => {
    expect(patchesForTheme('Light', { theme_primary: '#0015a8', theme_logo: '' })).toEqual([]);
  });

  it('carries every field the constants moved, and only those', () => {
    for (const [name, fields] of Object.entries(SUPERSEDED)) {
      for (const [key, values] of Object.entries(fields)) {
        expect(values.length).toBeGreaterThan(0);
        for (const superseded of values) {
          // The guard is meaningless if a superseded value equals the current one.
          expect(CURRENT[name as 'Dark' | 'Light'][key as keyof typeof DARK_DEFAULTS]).not.toBe(superseded);
        }
      }
    }
    expect(Object.keys(SUPERSEDED.Dark)).toHaveLength(7);
    expect(Object.keys(SUPERSEDED.Light)).toHaveLength(5);
  });

  // Found on a real installation: Light's secondary was seeded as #00BD94 on some, and as
  // #00f0bc on others. A guard that knows only one of them silently skips the other, and the
  // row then fails the downstream comparison and gets duplicated instead of renamed.
  it('accepts every historical default a field has carried', () => {
    for (const value of SUPERSEDED.Light.theme_secondary) {
      expect(patchesForTheme('Light', { theme_secondary: value }))
        .toEqual([{ key: 'theme_secondary', value: [LIGHT_DEFAULTS.theme_secondary] }]);
    }
  });

  it('rewrites a whole untouched legacy row in one pass', () => {
    expect(patchesForTheme('Dark', legacyRow('Dark') as Record<string, string>)).toHaveLength(7);
    expect(patchesForTheme('Light', legacyRow('Light') as Record<string, string>)).toHaveLength(5);
  });

  describe('hand-off to 1787822440159-add-filigran-built-in-themes', () => {
    it.each([['Dark', 0], ['Light', 0], ['Light', 1]] as const)(
      'leaves an untouched %s row (historical default #%i) matching the constants, so that migration renames instead of duplicating',
      (name, which) => {
        const before = legacyRow(name, which);
        // Precondition: without this pass the comparison fails and a second theme is seeded.
        expect(isThemeDefaultLike(before, name)).toBe(false);

        expect(isThemeDefaultLike(applyPatches(before, name), name)).toBe(true);
      },
    );

    it.each(['Dark', 'Light'] as const)(
      'leaves a customised %s row NOT matching, so that migration preserves and demotes it',
      (name) => {
        const customised = { ...legacyRow(name), theme_primary: '#ff7a00' };

        const after = applyPatches(customised, name);
        expect(after.theme_primary).toBe('#ff7a00');
        expect(isThemeDefaultLike(after, name)).toBe(false);
      },
    );

    it('carries our WCAG values into the row that gets renamed', () => {
      const after = applyPatches(legacyRow('Dark'), 'Dark');

      expect(after.theme_primary).toBe(DARK_DEFAULTS.theme_primary);
      expect(after.theme_background).toBe(DARK_DEFAULTS.theme_background);
      expect(after.theme_text_color).toBe(DARK_DEFAULTS.theme_text_color);
    });
  });
});
