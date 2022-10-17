import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { createTheme, StyledEngineProvider, ThemeProvider } from '@mui/material/styles';
import { UserContext } from '../utils/Security';
import themeDark from './ThemeDark';
import themeLight from './ThemeLight';
import {
  useDocumentFaviconModifier,
  useDocumentThemeModifier,
  useDocumentModifier,
} from '../utils/hooks/useDocumentModifier';
import { isNotEmptyField } from '../utils/utils';

const themeBuilder = (settings, themeColor) => {
  if (themeColor === 'light') {
    const platformThemeLightLogo = settings?.platform_theme_light_logo ?? null;
    const platformThemeLightBackground = settings?.platform_theme_light_background ?? null;
    const platformThemeLightPaper = settings?.platform_theme_light_paper ?? null;
    const platformThemeLightNav = settings?.platform_theme_light_nav ?? null;
    const platformThemeLightPrimary = settings?.platform_theme_light_primary ?? null;
    const platformThemeLightSecondary = settings?.platform_theme_light_secondary ?? null;
    const platformThemeLightAccent = settings?.platform_theme_light_accent ?? null;
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

const AppThemeProvider = (props) => {
  const { children } = props;
  const { me } = useContext(UserContext);
  const platformTitle = props.settings?.platform_title ?? 'OpenCTI - Cyber Threat Intelligence Platform';
  useDocumentModifier(platformTitle);
  useDocumentFaviconModifier(props.settings?.platform_favicon);
  // region theming
  const defaultTheme = props.settings?.platform_theme ?? null;
  const platformTheme = defaultTheme !== null && defaultTheme !== 'auto' ? defaultTheme : 'dark';
  const theme = isNotEmptyField(me?.theme) && me.theme !== 'default' ? me.theme : platformTheme;
  const themeComponent = themeBuilder(props.settings, theme);
  const muiTheme = createTheme(themeComponent);
  useDocumentThemeModifier(theme);
  // endregion
  return (
    <StyledEngineProvider injectFirst>
      <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>
    </StyledEngineProvider>
  );
};

AppThemeProvider.propTypes = {
  children: PropTypes.node,
  settings: PropTypes.object,
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
