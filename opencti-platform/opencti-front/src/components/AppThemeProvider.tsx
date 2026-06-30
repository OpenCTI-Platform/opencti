import React, { FunctionComponent, useMemo } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { ThemeOptions } from '@mui/material/styles/createTheme';
import {
  THEME_DARK_DEFAULT_ACCENT,
  THEME_DARK_DEFAULT_BACKGROUND,
  THEME_DARK_DEFAULT_PAPER,
  THEME_DARK_DEFAULT_PRIMARY,
  THEME_DARK_DEFAULT_SECONDARY,
  THEME_DARK_DEFAULT_TEXT,
} from './ThemeDark';
import { useDocumentFaviconModifier, useDocumentThemeModifier } from '../utils/hooks/useDocumentModifier';
import { AppThemeProvider_settings$data } from './__generated__/AppThemeProvider_settings.graphql';
import { useExportTheme } from '../utils/ExportThemeContext';
import ThemeBuilder from './ThemeBuilder';
import type { AppThemeType } from './Theme';

interface AppThemeProviderProps {
  children: React.ReactNode;
  settings: AppThemeProvider_settings$data;
  activeTheme?: { id: string } & AppThemeType | null;
}

const themeBuilder = (theme: AppThemeType) => {
  return ThemeBuilder(theme);
};

const defaultTheme: AppThemeType = {
  name: 'Dark',
  theme_accent: THEME_DARK_DEFAULT_ACCENT,
  theme_background: THEME_DARK_DEFAULT_BACKGROUND,
  theme_logo: '',
  theme_logo_collapsed: '',
  theme_logo_login: '',
  theme_nav: THEME_DARK_DEFAULT_BACKGROUND,
  theme_paper: THEME_DARK_DEFAULT_PAPER,
  theme_primary: THEME_DARK_DEFAULT_PRIMARY,
  theme_secondary: THEME_DARK_DEFAULT_SECONDARY,
  theme_text_color: THEME_DARK_DEFAULT_TEXT,
};

const AppThemeProvider: FunctionComponent<AppThemeProviderProps> = ({
  children,
  settings,
  activeTheme,
}) => {
  useDocumentFaviconModifier(settings?.platform_favicon);

  const { exportTheme } = useExportTheme();
  const themeToUse = exportTheme ?? activeTheme ?? settings.platform_theme;

  const muiTheme = useMemo(() => {
    const appTheme: AppThemeType = {
      name: themeToUse?.name ?? defaultTheme.name,
      theme_accent: themeToUse?.theme_accent ?? defaultTheme.theme_accent,
      theme_background: themeToUse?.theme_background ?? defaultTheme.theme_background,
      theme_logo: themeToUse?.theme_logo ?? defaultTheme.theme_logo,
      theme_logo_collapsed: themeToUse?.theme_logo_collapsed ?? defaultTheme.theme_logo_collapsed,
      theme_logo_login: themeToUse?.theme_logo_login ?? defaultTheme.theme_logo_login,
      theme_nav: themeToUse?.theme_nav ?? defaultTheme.theme_nav,
      theme_paper: themeToUse?.theme_paper ?? defaultTheme.theme_paper,
      theme_primary: themeToUse?.theme_primary ?? defaultTheme.theme_primary,
      theme_secondary: themeToUse?.theme_secondary ?? defaultTheme.theme_secondary,
      theme_text_color: themeToUse?.theme_text_color ?? defaultTheme.theme_text_color,
      theme_advanced_override: themeToUse?.theme_advanced_override ?? defaultTheme.theme_advanced_override,
    };
    return createTheme(themeBuilder(appTheme) as ThemeOptions);
  }, [themeToUse]);

  // Compute the lowercase palette mode used by the body `data-theme`
  // attribute. This must match `theme.palette.mode` so that CSS files
  // targeting `body[data-theme="dark"]` / `body[data-theme="light"]`
  // (e.g. CKEditor theming) apply on the very first render.
  const themeMode = (themeToUse?.name ?? defaultTheme.name) === 'Light' ? 'light' : 'dark';
  useDocumentThemeModifier(themeMode);

  return <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>;
};

export const ConnectedThemeProvider = createFragmentContainer(
  AppThemeProvider,
  {
    settings: graphql`
      fragment AppThemeProvider_settings on ThemeSettings {
        platform_title
        platform_favicon
        platform_theme {
          name
          theme_logo
          theme_logo_login
          theme_logo_collapsed
          theme_text_color
          id
          built_in
          theme_nav
          theme_primary
          theme_secondary
          theme_accent
          theme_background
          theme_paper
          theme_advanced_override
        }
      }
    `,
  },
);

export default AppThemeProvider;
