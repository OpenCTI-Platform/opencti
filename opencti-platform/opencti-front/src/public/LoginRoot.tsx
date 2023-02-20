import React from 'react';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import Login from './components/Login';
import { environment } from '../relay/environment';
import { LoginRootPublicQuery } from './__generated__/LoginRootPublicQuery.graphql';

export const rootPublicQuery = graphql`
  query LoginRootPublicQuery {
    settings {
      platform_theme
      platform_login_message
      platform_theme_dark_logo_login
      platform_theme_light_logo_login
      platform_providers {
        name
        type
        provider
      }
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
    }
  }
`;

const queryRef = loadQuery<LoginRootPublicQuery>(environment, rootPublicQuery, {});

const LoginRoot = ({ type }: { type: string }) => {
  const data = usePreloadedQuery<LoginRootPublicQuery>(rootPublicQuery, queryRef);
  const { settings } = data;
  return (
    <StyledEngineProvider injectFirst={true}>
      <ConnectedThemeProvider settings={settings}>
        <CssBaseline />
        <ConnectedIntlProvider settings={settings}>
          <Login settings={settings} type={type} />
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </StyledEngineProvider>
  );
};

export default LoginRoot;
