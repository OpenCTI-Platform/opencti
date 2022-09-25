import React, { useContext, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import * as R from 'ramda';
import {
  createTheme,
  StyledEngineProvider,
  ThemeProvider,
} from '@mui/material/styles';
import { UserContext } from '../utils/Security';
import themeDark from './ThemeDark';
import themeLight from './ThemeLight';
import { APP_BASE_PATH, fileUri } from '../relay/environment';
import favImage from '../static/images/favicon.png';

const AppThemeProvider = (props) => {
  const { children } = props;
  const { me } = useContext(UserContext);
  const platformTitle = R.pathOr(
    'OpenCTI - Cyber Threat Intelligence Platform',
    ['settings', 'platform_title'],
    props,
  );
  const platformThemeSettings = R.pathOr(
    null,
    ['settings', 'platform_theme'],
    props,
  );
  const platformTheme = platformThemeSettings !== null && platformThemeSettings !== 'auto'
    ? props.settings.platform_theme
    : 'dark';
  const theme = me && me.theme !== null && me.theme !== undefined && me.theme !== 'default'
    ? me.theme
    : platformTheme;
  const platformThemeDarkLogo = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_logo'],
    props,
  );
  const platformThemeDarkBackground = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_background'],
    props,
  );
  const platformThemeDarkPaper = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_paper'],
    props,
  );
  const platformThemeDarkNav = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_nav'],
    props,
  );
  const platformThemeDarkPrimary = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_primary'],
    props,
  );
  const platformThemeDarkSecondary = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_secondary'],
    props,
  );
  const platformThemeDarkAccent = R.pathOr(
    null,
    ['settings', 'platform_theme_dark_accent'],
    props,
  );
  const platformThemeLightLogo = R.pathOr(
    null,
    ['settings', 'platform_theme_light_logo'],
    props,
  );
  const platformThemeLightBackground = R.pathOr(
    null,
    ['settings', 'platform_theme_light_background'],
    props,
  );
  const platformThemeLightPaper = R.pathOr(
    null,
    ['settings', 'platform_theme_light_paper'],
    props,
  );
  const platformThemeLightNav = R.pathOr(
    null,
    ['settings', 'platform_theme_light_nav'],
    props,
  );
  const platformThemeLightPrimary = R.pathOr(
    null,
    ['settings', 'platform_theme_light_primary'],
    props,
  );
  const platformThemeLightSecondary = R.pathOr(
    null,
    ['settings', 'platform_theme_light_secondary'],
    props,
  );
  const platformThemeLightAccent = R.pathOr(
    null,
    ['settings', 'platform_theme_light_accent'],
    props,
  );
  useEffect(() => {
    document.title = platformTitle;
    document.body.setAttribute('data-theme', theme);
    document.getElementById('favicon').href = R.pathOr(
      fileUri(favImage),
      ['settings', 'platform_favicon'],
      props,
    );
    document.getElementById(
      'manifest',
    ).href = `${APP_BASE_PATH}/static/ext/manifest.json`;
  }, []);
  let muiTheme = createTheme(
    themeDark(
      platformThemeDarkLogo,
      platformThemeDarkBackground,
      platformThemeDarkPaper,
      platformThemeDarkNav,
      platformThemeDarkPrimary,
      platformThemeDarkSecondary,
      platformThemeDarkAccent,
    ),
  );
  if (theme === 'light') {
    muiTheme = createTheme(
      themeLight(
        platformThemeLightLogo,
        platformThemeLightBackground,
        platformThemeLightPaper,
        platformThemeLightNav,
        platformThemeLightPrimary,
        platformThemeLightSecondary,
        platformThemeLightAccent,
      ),
    );
  }
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
