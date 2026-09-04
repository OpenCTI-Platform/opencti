import { describe, expect, it } from 'vitest';
import { isRowOnDefaults, patchesForTheme, SUPERSEDED } from '../../../src/migrations/1787822440160-align-builtin-theme-rows-with-wcag-defaults';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../../../src/modules/theme/theme-constants';

const CURRENT = { Dark: DARK_DEFAULTS, Light: LIGHT_DEFAULTS } as const;
type ThemeName = 'Dark' | 'Light';

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

const isThemeDefaultLike = (row: Record<string, unknown>, name: ThemeName) => COMPARED_FIELDS
  .every((key) => Object.prototype.hasOwnProperty.call(row, key)
    && row[key] === CURRENT[name][key as keyof typeof DARK_DEFAULTS])
  && row.built_in === true;

/** A row exactly as it is seeded today, on the current defaults. */
const currentRow = (name: ThemeName) => Object.fromEntries(
  COMPARED_FIELDS.map((k) => [k, CURRENT[name][k as keyof typeof DARK_DEFAULTS]]),
) as Record<string, string>;

/**
 * A row as an existing installation carries it before either migration runs: every moved
 * field back on a historical default. `which` picks among the historical values a field has had.
 */
const legacyRow = (name: ThemeName, which = 0): Record<string, string> => ({
  ...currentRow(name),
  ...Object.fromEntries(Object.entries(SUPERSEDED[name])
    .map(([k, vals]) => [k, vals[Math.min(which, vals.length - 1)]])),
});

const applyPatches = (row: Record<string, string>, name: ThemeName) => {
  const patched: Record<string, unknown> = { ...row, built_in: true };
  for (const { key, value } of patchesForTheme(name, row)) patched[key] = value[0];
  return patched;
};

describe('align built-in theme rows with the WCAG defaults', () => {
  describe('the row is judged as a whole', () => {
    it.each(['Dark', 'Light'] as const)('%s: a fully-default row has every moved field aligned', (name) => {
      const expected = Object.keys(SUPERSEDED[name]);

      const patches = patchesForTheme(name, legacyRow(name));

      expect(patches.map((p) => p.key).sort()).toEqual([...expected].sort());
      for (const { key, value } of patches) {
        expect(value).toEqual([CURRENT[name][key as keyof typeof DARK_DEFAULTS]]);
      }
    });

    // Product ruling: one unrecognised value anywhere marks the row as customised, and the
    // row is then left ENTIRELY alone -- not partially aligned.
    it.each(['Dark', 'Light'] as const)('%s: one customised field means ZERO writes', (name) => {
      const customised = { ...legacyRow(name), theme_primary: '#ff7a00' };

      expect(patchesForTheme(name, customised)).toEqual([]);
    });

    it('skips the row whichever field is customised, including one the bridge never moved', () => {
      for (const key of COMPARED_FIELDS) {
        const row = { ...legacyRow('Dark'), [key]: '#ff7a00' };
        expect(patchesForTheme('Dark', row)).toEqual([]);
      }
    });

    it('treats a missing field as unrecognised rather than assuming a default', () => {
      const { theme_paper: _dropped, ...incomplete } = legacyRow('Dark');

      expect(isRowOnDefaults('Dark', incomplete)).toBe(false);
      expect(patchesForTheme('Dark', incomplete)).toEqual([]);
    });

    it('recognises both the current and the historical values as defaults', () => {
      expect(isRowOnDefaults('Dark', currentRow('Dark'))).toBe(true);
      expect(isRowOnDefaults('Dark', legacyRow('Dark'))).toBe(true);
      expect(isRowOnDefaults('Light', legacyRow('Light', 1))).toBe(true);
    });
  });

  it('is idempotent — a row already on the current defaults is not rewritten', () => {
    expect(patchesForTheme('Dark', currentRow('Dark'))).toEqual([]);
    expect(patchesForTheme('Light', currentRow('Light'))).toEqual([]);
  });

  it('matches a historical value case-insensitively', () => {
    const row = { ...currentRow('Light'), theme_secondary: SUPERSEDED.Light.theme_secondary[0].toUpperCase() };

    expect(patchesForTheme('Light', row))
      .toEqual([{ key: 'theme_secondary', value: [LIGHT_DEFAULTS.theme_secondary] }]);
  });

  it('normalises a value that moved by letter case alone', () => {
    const row = { ...currentRow('Dark'), theme_text_color: '#F2F2F3' };

    expect(patchesForTheme('Dark', row))
      .toEqual([{ key: 'theme_text_color', value: [DARK_DEFAULTS.theme_text_color] }]);
  });

  // Found on a real installation: Light's secondary was seeded as #00BD94 on some, and as
  // #00f0bc on others. A guard that knows only one of them treats the other as customisation
  // and skips the whole row, which then gets duplicated instead of renamed.
  it('accepts every historical default a field has carried', () => {
    for (const value of SUPERSEDED.Light.theme_secondary) {
      const row = { ...currentRow('Light'), theme_secondary: value };
      expect(patchesForTheme('Light', row))
        .toEqual([{ key: 'theme_secondary', value: [LIGHT_DEFAULTS.theme_secondary] }]);
    }
  });

  it('carries every field the constants moved, and only those', () => {
    for (const [name, fields] of Object.entries(SUPERSEDED)) {
      for (const [key, values] of Object.entries(fields)) {
        expect(values.length).toBeGreaterThan(0);
        for (const superseded of values) {
          // The guard is meaningless if a superseded value equals the current one.
          expect(CURRENT[name as ThemeName][key as keyof typeof DARK_DEFAULTS]).not.toBe(superseded);
        }
      }
    }
    expect(Object.keys(SUPERSEDED.Dark)).toHaveLength(7);
    expect(Object.keys(SUPERSEDED.Light)).toHaveLength(5);
  });

  it('rewrites a whole untouched legacy row in one pass', () => {
    expect(patchesForTheme('Dark', legacyRow('Dark'))).toHaveLength(7);
    expect(patchesForTheme('Light', legacyRow('Light'))).toHaveLength(5);
  });

  describe('hand-off to 1787822440159-add-filigran-built-in-themes', () => {
    it.each([['Dark', 0], ['Light', 0], ['Light', 1]] as const)(
      'an untouched %s row (historical default #%i) ends up matching, so that migration renames instead of duplicating',
      (name, which) => {
        const before = legacyRow(name, which);
        // Precondition: without this pass the comparison fails and a second theme is seeded.
        expect(isThemeDefaultLike({ ...before, built_in: true }, name)).toBe(false);

        expect(isThemeDefaultLike(applyPatches(before, name), name)).toBe(true);
      },
    );

    it.each(['Dark', 'Light'] as const)(
      'a customised %s row stays exactly as it was, so that migration preserves and demotes it',
      (name) => {
        const customised: Record<string, string> = { ...legacyRow(name), theme_primary: '#ff7a00' };

        const after = applyPatches(customised, name);

        // Untouched in full: the customised colour AND every field still on a legacy default.
        expect(after.theme_primary).toBe('#ff7a00');
        for (const key of Object.keys(SUPERSEDED[name])) {
          if (key === 'theme_primary') continue;
          expect(after[key]).toBe(customised[key]);
        }
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
