import themeDark from './ThemeDark';
import themeLight from './ThemeLight';
import type { AppThemeType, ExtendedThemeOptions } from './Theme';

// Fills out theme based on selected custom theme with automatic fallback to default themes
const ThemeBuilder = (theme?: AppThemeType): ExtendedThemeOptions => {
  const defaultTheme = buildOverrideDefault(theme);
  // default to builtin theme
  let modifiedTheme = defaultTheme;
  if (theme?.theme_advanced_override && theme?.theme_advanced_override.trim() !== '') {
    try {
      const parsed = JSON.parse(theme.theme_advanced_override);
      // Only update theme if override is an object after being parsed
      if (typeof parsed === 'object') {
        modifiedTheme = parsed;
      }
      // base theme is defined, update properties of theme where defined in selected theme.
      addThemePropertiesIfMissing(defaultTheme, modifiedTheme);
    } catch (_) {
      // reset to default theme if anything fails
      modifiedTheme = defaultTheme;
    }
  }
  return modifiedTheme;
};

const buildOverrideDefault = (theme?: AppThemeType) => {
  const platformThemeLogo = theme?.theme_logo ?? null;
  const platformThemeLogoCollapsed = theme?.theme_logo_collapsed ?? null;
  const platformThemeBackground = theme?.theme_background ?? null;
  const platformThemePaper = theme?.theme_paper ?? null;
  const platformThemeNav = theme?.theme_nav ?? null;
  const platformThemePrimary = theme?.theme_primary ?? null;
  const platformThemeSecondary = theme?.theme_secondary ?? null;
  const platformThemeAccent = theme?.theme_accent ?? null;
  const platformThemeTextColor = theme?.theme_text_color ?? 'rgba(255, 255, 255, 0.7)';
  if (theme?.name === 'Light') {
    return themeLight(
      platformThemeLogo,
      platformThemeLogoCollapsed,
      platformThemeBackground,
      platformThemePaper,
      platformThemeNav,
      platformThemePrimary,
      platformThemeSecondary,
      platformThemeAccent,
      platformThemeTextColor,
    );
  }
  return themeDark(
    platformThemeLogo,
    platformThemeLogoCollapsed,
    platformThemeBackground,
    platformThemePaper,
    platformThemeNav,
    platformThemePrimary,
    platformThemeSecondary,
    platformThemeAccent,
    platformThemeTextColor,
  );
};

const addThemePropertiesIfMissing = (defaultTheme: object, selectedTheme: object) => {
  // read through default theme and add properties to selected theme
  for (const key in defaultTheme) {
    if (Object.hasOwn(defaultTheme, key)) {
      // Check if the property exists in the selected theme, if not add it
      if (selectedTheme[key] === undefined) {
        selectedTheme[key] = defaultTheme[key];
      } else if (selectedTheme[key] !== undefined && typeof selectedTheme[key] === 'object' && selectedTheme[key] !== null) {
        // if it does exist and is a nested object recursively check
        addThemePropertiesIfMissing(defaultTheme[key], selectedTheme[key]); // Recurse
      }
    }
  }
};

export default ThemeBuilder;
