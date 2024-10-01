import React, { FunctionComponent, useContext } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { ThemeOptions } from '@mui/material/styles/createTheme';
import { UserContext, UserContextType } from '../utils/hooks/useAuth';
import themeDark from './ThemeDark';
import themeLight from './ThemeLight';
import { useDocumentFaviconModifier, useDocumentThemeModifier } from '../utils/hooks/useDocumentModifier';
import { AppThemeProvider_settings$data } from './__generated__/AppThemeProvider_settings.graphql';
import { RootPrivateQuery$data } from '../private/__generated__/RootPrivateQuery.graphql';
import { deserializeThemeManifest } from '../private/components/settings/themes/ThemeType';

interface AppThemeProviderProps {
  children: React.ReactNode;
  settings: AppThemeProvider_settings$data;
  themes: RootPrivateQuery$data['themes'];
}

interface AppThemeType {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
}

const themeBuilder = (
  theme: AppThemeType,
) => {
  const platformThemeLogo = theme?.theme_logo ?? null;
  const platformThemeLogoCollapsed = theme?.theme_logo_collapsed ?? null;
  const platformThemeBackground = theme?.theme_background ?? null;
  const platformThemePaper = theme?.theme_paper ?? null;
  const platformThemeNav = theme?.theme_nav ?? null;
  const platformThemePrimary = theme?.theme_primary ?? null;
  const platformThemeSecondary = theme?.theme_secondary ?? null;
  const platformThemeAccent = theme?.theme_accent ?? null;
  if (theme?.name === 'Light') {
    // needed until everything is customizable, like text colors
    return themeLight(
      platformThemeLogo,
      platformThemeLogoCollapsed,
      platformThemeBackground,
      platformThemePaper,
      platformThemeNav,
      platformThemePrimary,
      platformThemeSecondary,
      platformThemeAccent,
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
  );
};

const AppThemeProvider: FunctionComponent<AppThemeProviderProps> = ({
  children,
  settings,
  themes,
}) => {
  const { me } = useContext<UserContextType>(UserContext);
  useDocumentFaviconModifier(settings?.platform_favicon);
  // region theming
  const defaultThemeName = settings?.platform_theme ?? null;
  const defaultTheme = {
    name: 'dark',
    theme_accent: '#0f1e38',
    theme_background: '#070d19',
    theme_logo: '',
    theme_logo_collapsed: '',
    theme_logo_login: '',
    theme_nav: '#070d19',
    theme_paper: '#09101e',
    theme_primary: '#0fbcff',
    theme_secondary: '#00f1bd',
  };
  const platformTheme = defaultThemeName !== null && defaultThemeName !== 'auto' ? defaultThemeName : 'dark';
  const themeName = me?.theme && me.theme !== 'default' ? me.theme : platformTheme;
  const theme: AppThemeType = themes?.edges
    ?.filter((node) => !!node)
    .map(({ node }) => {
      const manifestFields = deserializeThemeManifest(node.manifest);
      return {
        name: node.name,
        ...manifestFields,
        theme_logo: manifestFields.theme_logo ?? '',
        theme_logo_collapsed: manifestFields.theme_logo_collapsed ?? '',
        theme_logo_login: manifestFields.theme_logo_login ?? '',
      };
    })
    .find(({ name }) => name === themeName)
    ?? defaultTheme;
  const themeComponent = themeBuilder(theme);
  const muiTheme = createTheme(themeComponent as ThemeOptions);
  useDocumentThemeModifier(themeName);
  // endregion
  return <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>;
};

export const ConnectedThemeProvider = createFragmentContainer(
  AppThemeProvider,
  {
    settings: graphql`
      fragment AppThemeProvider_settings on Settings {
        platform_title
        platform_favicon
        platform_theme
      }
    `,
  },
);

export default AppThemeProvider;
