import React, { FunctionComponent, useContext } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { ThemeOptions } from '@mui/material/styles/createTheme';
import { UserContext, UserContextType } from '../utils/hooks/useAuth';
import themeDark from './ThemeDark';
import themeLight from './ThemeLight';
import { useDocumentFaviconModifier, useDocumentThemeModifier } from '../utils/hooks/useDocumentModifier';
import { AppThemeProvider_settings$data } from './__generated__/AppThemeProvider_settings.graphql';
import { AppThemeProvider_publicsettings$data } from './__generated__/AppThemeProvider_publicsettings.graphql';

const setUserThemeMutation = graphql`
  mutation AppThemeProviderSetUserThemeMutation($input: [EditInput!]!) {
    meEdit(input: $input) {
      theme
    }
  }
`;

interface AppThemeProviderProps {
  children: React.ReactNode;
  settings: AppThemeProvider_settings$data | AppThemeProvider_publicsettings$data;
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
  theme_text_color: string;
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
  const platformThemeTextColor = theme?.theme_text_color ?? 'rgba(255, 255, 255, 0.7)';
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

const defaultTheme: AppThemeType = {
  name: 'Dark',
  theme_accent: '#0f1e38',
  theme_background: '#070d19',
  theme_logo: '',
  theme_logo_collapsed: '',
  theme_logo_login: '',
  theme_nav: '#070d19',
  theme_paper: '#09101e',
  theme_primary: '#0fbcff',
  theme_secondary: '#00f1bd',
  theme_text_color: '#ffffff',
};

const AppThemeProvider: FunctionComponent<AppThemeProviderProps> = ({
  children,
  settings,
}) => {
  const { me } = useContext<UserContextType>(UserContext);
  useDocumentFaviconModifier(settings?.platform_favicon);
  //
  // console.log('settings?.platform_theme', settings?.platform_theme);
  // // region theming
  //
  // // The ID of the platform's default theme
  // const defaultThemeId = settings?.platform_theme ?? null;
  // const platformThemeId = defaultThemeId !== null && defaultThemeId !== 'auto'
  //   ? defaultThemeId
  //   : 'Dark';
  //
  // // The current user's theme ID
  // const userThemeId = me?.theme;
  //
  // // Use the user's theme if present and not default
  // const themeId = me?.theme && me.theme !== 'default' ? userThemeId : platformThemeId;
  //
  // const theme = themes?.edges
  //   ?.find((edge) => edge?.node.id === themeId)
  //   ?.node;

  // If the user's theme ID is not amongst the available themes, change their
  // theme to the system default. This could happen if the user's selected
  // theme is deleted by an admin.
  // if (!theme) {
  //   commitMutation({
  //     ...defaultCommitMutation,
  //     mutation: setUserThemeMutation,
  //     variables: {
  //       input: [{
  //         key: 'theme',
  //         value: 'default',
  //       }],
  //     },
  //   });
  // }

  // Construct app theme for theme builder
  const appTheme: AppThemeType = {
    name: settings.platform_theme?.name ?? defaultTheme.name,
    theme_accent: settings.platform_theme?.theme_accent ?? defaultTheme.theme_accent,
    theme_background: settings.platform_theme?.theme_background ?? defaultTheme.theme_background,
    theme_logo: settings.platform_theme?.theme_logo ?? defaultTheme.theme_logo,
    theme_logo_collapsed: settings.platform_theme?.theme_logo_collapsed ?? defaultTheme.theme_logo_collapsed,
    theme_logo_login: settings.platform_theme?.theme_logo_login ?? defaultTheme.theme_logo_login,
    theme_nav: settings.platform_theme?.theme_nav ?? defaultTheme.theme_nav,
    theme_paper: settings.platform_theme?.theme_paper ?? defaultTheme.theme_paper,
    theme_primary: settings.platform_theme?.theme_primary ?? defaultTheme.theme_primary,
    theme_secondary: settings.platform_theme?.theme_secondary ?? defaultTheme.theme_secondary,
    theme_text_color: settings.platform_theme?.theme_text_color ?? defaultTheme.theme_text_color,
  };

  const themeComponent = themeBuilder(appTheme);
  const muiTheme = createTheme(themeComponent as ThemeOptions);
  useDocumentThemeModifier(appTheme.name);
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
          theme_text_color
          theme_accent
          theme_background
          theme_paper
        }
      }
    `,
  },
);

export const ConnectedPublicThemeProvider = createFragmentContainer(
  AppThemeProvider,
  {
    settings: graphql`
      fragment AppThemeProvider_publicsettings on PublicSettings {
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
          theme_text_color
          theme_accent
          theme_background
          theme_paper
        }
      }
    `,
  },
);

export default AppThemeProvider;
