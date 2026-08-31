/**
 * Single place that decides whether a theme name means "light".
 *
 * There are three consumers and they must never disagree: `themeBuilder` picks
 * the MUI palette, `useFdsThemeScope` writes the `.light`/`.dark` class the
 * design-system components resolve their custom properties against, and the
 * body `data-theme` attribute the product's own stylesheets target. When one of
 * them answered differently the app rendered a light MUI surface with dark
 * design-system tokens on it.
 *
 * Two names are light, and both are still in the wild:
 *   - `Filigran Light`, the built-in shipped since the built-in themes change;
 *   - `Light`, the legacy name. Installations that had customised it keep it:
 *     the migration only renames a row it finds untouched, and demotes a
 *     customised one to a normal theme under its original name.
 *
 * Anything else is dark, which is what `themeBuilder` has always done with
 * custom themes.
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
