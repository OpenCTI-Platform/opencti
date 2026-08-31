import { describe, expect, it } from 'vitest';
import { patchesForTheme, SUPERSEDED } from '../../../src/migrations/1788160000000-align-filigran-theme-rows-with-wcag-defaults';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../../../src/modules/theme/theme-constants';

describe('align the Filigran built-in theme rows with the WCAG defaults', () => {
  it('rewrites a row that still carries the superseded default', () => {
    const patches = patchesForTheme('Filigran Dark', { theme_primary: SUPERSEDED['Filigran Dark'].theme_primary });
    expect(patches).toEqual([{ key: 'theme_primary', value: [DARK_DEFAULTS.theme_primary] }]);
  });

  it('leaves an administrator colour untouched', () => {
    expect(patchesForTheme('Filigran Dark', { theme_primary: '#ff7a00' })).toEqual([]);
    expect(patchesForTheme('Filigran Light', { theme_secondary: '#8bff00' })).toEqual([]);
  });

  it('is idempotent — a row already on the current default is not rewritten', () => {
    expect(patchesForTheme('Filigran Dark', { theme_primary: DARK_DEFAULTS.theme_primary })).toEqual([]);
    expect(patchesForTheme('Filigran Light', { theme_secondary: LIGHT_DEFAULTS.theme_secondary })).toEqual([]);
  });

  it('matches the superseded value case-insensitively', () => {
    const patches = patchesForTheme('Filigran Light', { theme_secondary: SUPERSEDED['Filigran Light'].theme_secondary.toUpperCase() });
    expect(patches).toEqual([{ key: 'theme_secondary', value: [LIGHT_DEFAULTS.theme_secondary] }]);
  });

  it('normalises a value that moved by letter case alone', () => {
    const patches = patchesForTheme('Filigran Dark', { theme_text_color: '#F2F2F3' });
    expect(patches).toEqual([{ key: 'theme_text_color', value: [DARK_DEFAULTS.theme_text_color] }]);
    // and does not re-patch once normalised
    expect(patchesForTheme('Filigran Dark', { theme_text_color: DARK_DEFAULTS.theme_text_color })).toEqual([]);
  });

  it('touches no field the bridge did not move', () => {
    expect(patchesForTheme('Filigran Light', { theme_primary: '#0015a8' })).toEqual([]);
  });

  it('carries every field the constants moved', () => {
    // The guard is meaningless if the superseded value equals the current one:
    // each listed field must be one the constants have actually moved past.
    for (const [name, fields] of Object.entries(SUPERSEDED)) {
      const current = name === 'Filigran Dark' ? DARK_DEFAULTS : LIGHT_DEFAULTS;
      for (const [key, superseded] of Object.entries(fields)) {
        expect(current[key as keyof typeof DARK_DEFAULTS]).not.toBe(superseded);
      }
    }
    expect(Object.keys(SUPERSEDED['Filigran Dark'])).toHaveLength(7);
    expect(Object.keys(SUPERSEDED['Filigran Light'])).toHaveLength(5);
  });

  it('rewrites a whole untouched legacy row in one pass', () => {
    const row = { ...SUPERSEDED['Filigran Dark'] } as Record<string, string>;
    expect(patchesForTheme('Filigran Dark', row)).toHaveLength(7);
  });
});
