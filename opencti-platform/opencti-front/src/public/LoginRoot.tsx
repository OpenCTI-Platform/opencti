import React from 'react';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ConnectedPublicThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import Login from './components/Login';
import { environment } from '../relay/environment';
import { LoginRootPublicQuery } from './__generated__/LoginRootPublicQuery.graphql';

export const rootPublicQuery = graphql`
  query LoginRootPublicQuery {
    publicSettings {
      platform_enterprise_edition_license_validated
      platform_theme {
        id
        name
        theme_background
        theme_paper
        theme_nav
        theme_primary
        theme_secondary
        theme_accent
        theme_text_color
        theme_logo
        theme_logo_collapsed
        theme_logo_login
      }
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
      ...AppIntlProvider_settings
      ...AppThemeProvider_publicsettings
      ...PublicSettingsProvider_settings
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

  return (
    <StyledEngineProvider injectFirst={true}>
      <ConnectedPublicThemeProvider settings={data.publicSettings} >
        <CssBaseline />
        <ConnectedIntlProvider settings={data.publicSettings}>
          <Login settings={data.publicSettings} type={type} />
        </ConnectedIntlProvider>
      </ConnectedPublicThemeProvider>
    </StyledEngineProvider>
  );
};

export default LoginRoot;
