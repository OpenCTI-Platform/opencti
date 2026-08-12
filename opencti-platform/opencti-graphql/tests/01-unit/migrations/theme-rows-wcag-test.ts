import { describe, expect, it } from 'vitest';
import { patchesForTheme, SUPERSEDED } from '../../../src/migrations/1786487525777-align-builtin-theme-rows-with-wcag-defaults';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../../../src/modules/theme/theme-constants';

describe('align built-in theme rows with the WCAG defaults', () => {
  it('rewrites a row that still carries the superseded default', () => {
    const patches = patchesForTheme('Dark', { theme_primary: SUPERSEDED.Dark.theme_primary });
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
    const patches = patchesForTheme('Light', { theme_secondary: SUPERSEDED.Light.theme_secondary.toUpperCase() });
    expect(patches).toEqual([{ key: 'theme_secondary', value: [LIGHT_DEFAULTS.theme_secondary] }]);
  });

  it('touches no field the bridge did not move', () => {
    const row = { theme_primary: '#0015a8', theme_background: '#f2f2f3', theme_nav: '#f2f2f3' };
    expect(patchesForTheme('Light', row)).toEqual([]);
  });

  it('targets a default the constants have actually moved past', () => {
    // The guard is meaningless if the superseded value equals the current one.
    expect(DARK_DEFAULTS.theme_primary).not.toBe(SUPERSEDED.Dark.theme_primary);
    expect(LIGHT_DEFAULTS.theme_secondary).not.toBe(SUPERSEDED.Light.theme_secondary);
  });
});
