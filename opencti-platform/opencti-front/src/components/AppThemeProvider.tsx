import React, { FunctionComponent, useContext } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { createTheme, StyledEngineProvider, ThemeProvider } from '@mui/material/styles';
import { ThemeOptions } from '@mui/material/styles/createTheme';
import { UserContext, UserContextType } from '../utils/hooks/useAuth';
import themeDark from './ThemeDark';
import themeLight from './ThemeLight';
import {
  useDocumentFaviconModifier,
  useDocumentModifier,
  useDocumentThemeModifier,
} from '../utils/hooks/useDocumentModifier';
import { AppThemeProvider_settings$data } from './__generated__/AppThemeProvider_settings.graphql';

interface AppThemeProviderProps {
  children: React.ReactNode
  settings: AppThemeProvider_settings$data
}

const themeBuilder = (settings: AppThemeProvider_settings$data, themeColor: string) => {
  if (themeColor === 'light') {
    const platformThemeLightLogo = settings?.platform_theme_light_logo;
    const platformThemeLightBackground = settings?.platform_theme_light_background;
    const platformThemeLightPaper = settings?.platform_theme_light_paper;
    const platformThemeLightNav = settings?.platform_theme_light_nav;
    const platformThemeLightPrimary = settings?.platform_theme_light_primary;
    const platformThemeLightSecondary = settings?.platform_theme_light_secondary;
    const platformThemeLightAccent = settings?.platform_theme_light_accent;
    return themeLight(
      platformThemeLightLogo,
      platformThemeLightBackground,
      platformThemeLightPaper,
      platformThemeLightNav,
      platformThemeLightPrimary,
      platformThemeLightSecondary,
      platformThemeLightAccent,
    );
  }
  const platformThemeDarkLogo = settings?.platform_theme_dark_logo ?? null;
  const platformThemeDarkBackground = settings?.platform_theme_dark_background ?? null;
  const platformThemeDarkPaper = settings?.platform_theme_dark_paper ?? null;
  const platformThemeDarkNav = settings?.platform_theme_dark_nav ?? null;
  const platformThemeDarkPrimary = settings?.platform_theme_dark_primary ?? null;
  const platformThemeDarkSecondary = settings?.platform_theme_dark_secondary ?? null;
  const platformThemeDarkAccent = settings?.platform_theme_dark_accent ?? null;
  return themeDark(
    platformThemeDarkLogo,
    platformThemeDarkBackground,
    platformThemeDarkPaper,
    platformThemeDarkNav,
    platformThemeDarkPrimary,
    platformThemeDarkSecondary,
    platformThemeDarkAccent,
  );
};

const AppThemeProvider: FunctionComponent<AppThemeProviderProps> = ({ children, settings }) => {
  const { me } = useContext<UserContextType>(UserContext);
  const platformTitle = settings?.platform_title ?? 'OpenCTI - Cyber Threat Intelligence Platform';
  useDocumentModifier(platformTitle);
  useDocumentFaviconModifier(settings?.platform_favicon);
  // region theming
  const defaultTheme = settings?.platform_theme ?? null;
  const platformTheme = defaultTheme !== null && defaultTheme !== 'auto' ? defaultTheme : 'dark';
  const theme = me?.theme && me.theme !== 'default' ? me.theme : platformTheme;
  const themeComponent = themeBuilder(settings, theme);
  const muiTheme = createTheme(themeComponent as ThemeOptions);
  useDocumentThemeModifier(theme);
  // endregion
  return (
    <StyledEngineProvider injectFirst>
      <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>
    </StyledEngineProvider>
  );
};

export const ConnectedThemeProvider = createFragmentContainer(
  AppThemeProvider,
  {
    settings: graphql`
        fragment AppThemeProvider_settings on Settings {
            platform_title
            platform_favicon
            platform_theme
            platform_theme_dark_background
            platform_theme_dark_paper
            platform_theme_dark_nav
            platform_theme_dark_primary
            platform_theme_dark_secondary
            platform_theme_dark_accent
            platform_theme_dark_logo
            platform_theme_light_background
            platform_theme_light_paper
            platform_theme_light_nav
            platform_theme_light_primary
            platform_theme_light_secondary
            platform_theme_light_accent
            platform_theme_light_logo
        }
    `,
  },
);

export default AppThemeProvider;
