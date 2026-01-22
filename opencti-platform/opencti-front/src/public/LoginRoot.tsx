import React from 'react';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import LoginPage from './components/login/LoginPage';
import { environment } from '../relay/environment';
import { LoginRootPublicQuery } from './__generated__/LoginRootPublicQuery.graphql';
import { LoginContextProvider } from './components/login/loginContext';
import OtpValidationPage from './components/login/OtpValidationPage';
import OtpActivation from './components/login/OtpActivation';

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
      ...ExternalAuthsFragment
      ...LoginLogoFragment
      ...AppIntlProvider_settings
      ...AppThemeProvider_settings
      ...PublicSettingsProvider_settings
      ...ConsentMessageFragment
      metrics_definition {
        entity_type
        metrics {
          attribute
          name
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

  return (
    <StyledEngineProvider injectFirst={true}>
      <ConnectedThemeProvider settings={data.publicSettings}>
        <CssBaseline />
        <ConnectedIntlProvider settings={data.publicSettings}>
          <LoginContextProvider>
            {type === '2FA_VALIDATION' && (
              <OtpValidationPage settings={data.publicSettings} />
            )}
            {type === '2FA_ACTIVATION' && (
              <OtpActivation />
            )}
            {type === 'LOGIN' && (
              <LoginPage settings={data.publicSettings} />
            )}
          </LoginContextProvider>
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </StyledEngineProvider>
  );
};

export default LoginRoot;
