import { Theme } from '../components/Theme';
import { THEME_DARK_DEFAULT_BACKGROUND, THEME_DARK_DEFAULT_PAPER } from '../components/ThemeDark';
import { THEME_LIGHT_DEFAULT_BACKGROUND, THEME_LIGHT_DEFAULT_PAPER } from '../components/ThemeLight';

type CustomThemeKey
  = | 'theme_background'
    | 'theme_paper'
    | 'theme_nav'
    | 'theme_primary'
    | 'theme_secondary'
    | 'theme_accent'
    | 'theme_text_color';

/**
 * Checks if saved theme has overriden the default theme.
 * Should not be usefull after the saved themes have been aligne with Design System.
 *
 * @param theme The theme to check.
 * @param key Key of the saved theme to check.
 * @returns True is there is a custom color defined.
 */
export const hasCustomColor = (theme: Theme, key: CustomThemeKey) => {
  if (key === 'theme_background') {
    const defaultColor = theme.palette.mode === 'dark'
      ? THEME_DARK_DEFAULT_BACKGROUND
      : THEME_LIGHT_DEFAULT_BACKGROUND;
    return theme.palette.background.default !== defaultColor;
  }
  if (key === 'theme_paper') {
    const defaultColor = theme.palette.mode === 'dark'
      ? THEME_DARK_DEFAULT_PAPER
      : THEME_LIGHT_DEFAULT_PAPER;
    return theme.palette.background.paper !== defaultColor;
  }
  return false;
};
