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
      platform_enterprise_edition {
        license_validated
      }
      platform_theme
      platform_login_message
      platform_consent_message
      platform_banner_text
      platform_banner_level
      platform_consent_confirm_text
      platform_whitemark
      platform_providers {
        name
        type
        provider
      }
      playground_enabled
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
      ...PublicSettingsProvider_settings
    }
    themes {
      edges {
        node {
          id
          name
          manifest
        }
      }
    }
  }
`;

const queryRef = loadQuery<LoginRootPublicQuery>(
  environment,
  rootPublicQuery,
  {},
);

const LoginRoot = ({ type }: { type: string }) => {
  const data = usePreloadedQuery<LoginRootPublicQuery>(
    rootPublicQuery,
    queryRef,
  );
  const { settings, themes } = data;
  return (
    <StyledEngineProvider injectFirst={true}>
      <ConnectedThemeProvider settings={settings} themes={themes}>
        <CssBaseline />
        <ConnectedIntlProvider settings={settings}>
          <Login settings={settings} themes={themes} type={type} />
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </StyledEngineProvider>
  );
};

export default LoginRoot;
