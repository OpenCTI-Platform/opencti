import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { pathOr } from 'ramda';
import { createMuiTheme, ThemeProvider } from '@material-ui/core/styles';
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
  let muiTheme = createMuiTheme(themeDark);
  if (theme === 'light') {
    muiTheme = createMuiTheme(themeLight);
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
      }
    `,
  },
);

export default AppThemeProvider;
