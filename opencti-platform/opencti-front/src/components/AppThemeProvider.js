import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { pathOr } from 'ramda';
import { createTheme, ThemeProvider } from '@material-ui/core/styles';
import { UserContext } from '../utils/Security';
import themeDark from './ThemeDark';
import themeLight from './ThemeLight';

const AppThemeProvider = (props) => {
  const { children } = props;
  const { me } = useContext(UserContext);
  const platformThemeSettings = pathOr(
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
  const platformThemeDarkLogo = pathOr(
    null,
    ['settings', 'platform_theme_dark_logo'],
    props,
  );
  const platformThemeDarkPrimary = pathOr(
    null,
    ['settings', 'platform_theme_dark_primary'],
    props,
  );
  const platformThemeDarkSecondary = pathOr(
    null,
    ['settings', 'platform_theme_dark_secondary'],
    props,
  );
  const platformThemeLightLogo = pathOr(
    null,
    ['settings', 'platform_theme_light_logo'],
    props,
  );
  const platformThemeLightPrimary = pathOr(
    null,
    ['settings', 'platform_theme_light_primary'],
    props,
  );
  const platformThemeLightSecondary = pathOr(
    null,
    ['settings', 'platform_theme_light_secondary'],
    props,
  );
  let muiTheme = createTheme(
    themeDark(
      platformThemeDarkLogo,
      platformThemeDarkPrimary,
      platformThemeDarkSecondary,
    ),
  );
  if (theme === 'light') {
    muiTheme = createTheme(
      themeLight(
        platformThemeLightLogo,
        platformThemeLightPrimary,
        platformThemeLightSecondary,
      ),
    );
  }
  return <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>;
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
        platform_theme
        platform_theme_dark_primary
        platform_theme_dark_secondary
        platform_theme_dark_logo
        platform_theme_light_primary
        platform_theme_light_secondary
        platform_theme_light_logo
      }
    `,
  },
);

export default AppThemeProvider;
