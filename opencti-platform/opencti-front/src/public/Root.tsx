import React from 'react';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import Login from './components/Login';
import { RootPublicQuery } from './__generated__/RootPublicQuery.graphql';
import { environment } from '../relay/environment';

export const rootPublicQuery = graphql`
  query RootPublicQuery {
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

const queryRef = loadQuery<RootPublicQuery>(environment, rootPublicQuery, {});

const Root = ({ type }: { type : string }) => {
  const data = usePreloadedQuery<RootPublicQuery>(rootPublicQuery, queryRef);
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

export default Root;
