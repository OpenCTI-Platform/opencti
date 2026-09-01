/**
 * Single place that decides whether a theme name means "light". Two names do —
 * `Filigran Light` and the legacy `Light` — and both are still in the wild.
 * Why, and the three consumers that must agree: fds-migration/MIGRATION-DECISIONS.md#light-theme-names
 */
export const BUILT_IN_DARK_THEME_NAME = 'Filigran Dark';
export const BUILT_IN_LIGHT_THEME_NAME = 'Filigran Light';
export const LEGACY_DARK_THEME_NAME = 'Dark';
export const LEGACY_LIGHT_THEME_NAME = 'Light';

const LIGHT_THEME_NAMES: ReadonlySet<string> = new Set([
  BUILT_IN_LIGHT_THEME_NAME,
  LEGACY_LIGHT_THEME_NAME,
]);

export const isLightThemeName = (name?: string | null): boolean => !!name && LIGHT_THEME_NAMES.has(name);

export default isLightThemeName;
