import { useEffect } from 'react';
import { isLightThemeName } from '../themeName';
import { FDS } from '../../components/fds-tokens.generated';

export type FdsThemeMode = 'light' | 'dark';

export interface FdsCustomTheme {
  background?: string | null;
  paper?: string | null;
  nav?: string | null;
  primary?: string | null;
  secondary?: string | null;
  accent?: string | null;
  text?: string | null;
}

/** One setting, one token. The defaults these override live in ThemeDark/ThemeLight. */
const SETTING_TOKENS = {
  background: '--bg-elevation-default-layer-0',
  paper: '--bg-elevation-default-layer-1',
  accent: '--bg-elevation-default-layer-3',
  nav: '--bg-elevation-heading-layer-0',
  primary: '--color-filigran-brand-primary',
  secondary: '--color-filigran-tonic-primary',
  text: '--text-default-primary',
} as const satisfies Record<keyof FdsCustomTheme, string>;

const SETTINGS = Object.keys(SETTING_TOKENS) as (keyof FdsCustomTheme)[];

/**
 * Single writer of the `.light` / `.dark` class FDS components read, on the document
 * ROOT because FDS portals its floating layers into `<body>`. See
 * fds-migration/MIGRATION-DECISIONS.md#theme-scope-root
 *
 * MUI's palette does not drive CSS custom properties, so a customised colour is
 * written here as its token. The tokens derived from it (fields, borders, hovers)
 * are rules in static/css/custom-theme-tokens.css, switched on by the
 * `fds-custom-<setting>` class set alongside.
 */
const useFdsThemeScope = (
  themeName: string | undefined,
  custom: FdsCustomTheme = {},
): FdsThemeMode => {
  const mode: FdsThemeMode = isLightThemeName(themeName) ? 'light' : 'dark';
  const { background, paper, nav, primary, secondary, accent, text } = custom;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', mode === 'dark');
    root.classList.toggle('light', mode === 'light');
  }, [mode]);

  useEffect(() => {
    const root = document.documentElement;
    const values: FdsCustomTheme = { background, paper, nav, primary, secondary, accent, text };
    const palette = FDS.colors[mode] as Record<string, string>;
    SETTINGS.forEach((setting) => {
      const token = SETTING_TOKENS[setting];
      const value = values[setting];
      // A value equal to the library's is not written: the default theme keeps following the library.
      const customised = !!value && value.toLowerCase() !== palette[token]?.toLowerCase();
      if (customised) root.style.setProperty(token, value);
      else root.style.removeProperty(token);
      root.classList.toggle(`fds-custom-${setting}`, customised);
    });
  }, [background, paper, nav, primary, secondary, accent, text, mode]);

  return mode;
};

export default useFdsThemeScope;
