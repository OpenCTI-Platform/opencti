import { describe, expect, it } from 'vitest';
import { isLightThemeName, BUILT_IN_DARK_THEME_NAME, BUILT_IN_LIGHT_THEME_NAME, LEGACY_DARK_THEME_NAME, LEGACY_LIGHT_THEME_NAME } from './themeName';

describe('isLightThemeName', () => {
  it('accepts the built-in light theme', () => {
    expect(isLightThemeName(BUILT_IN_LIGHT_THEME_NAME)).toBe(true);
  });

  // The rename migration only renames a row it finds untouched; an installation that had
  // customised its light theme keeps the legacy name, so both must resolve to light.
  it('accepts the legacy light theme still in the wild', () => {
    expect(isLightThemeName(LEGACY_LIGHT_THEME_NAME)).toBe(true);
  });

  it.each([BUILT_IN_DARK_THEME_NAME, LEGACY_DARK_THEME_NAME, 'Corporate', 'filigran-2026', '', null, undefined])(
    'resolves %p to dark',
    (name) => {
      expect(isLightThemeName(name)).toBe(false);
    },
  );

  it('is exact, not a prefix match', () => {
    // `freeUpFiligranThemeName` can produce these; they are ordinary user themes.
    expect(isLightThemeName('Filigran Light - custom')).toBe(false);
    expect(isLightThemeName('Light theme')).toBe(false);
  });
});
