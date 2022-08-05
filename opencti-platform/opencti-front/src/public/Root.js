import React from 'react';
import { graphql } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { QueryRenderer } from '../relay/environment';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import Login from './components/Login';

const rootPublicQuery = graphql`
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

const Root = ({ type }) => (
  <QueryRenderer
    query={rootPublicQuery}
    variables={{}}
    render={({ props }) => {
      if (props && props.settings) {
        return (
          <StyledEngineProvider injectFirst={true}>
            <ConnectedThemeProvider settings={props.settings}>
              <CssBaseline />
              <ConnectedIntlProvider settings={props.settings}>
                <Login settings={props.settings} type={type} />
              </ConnectedIntlProvider>
            </ConnectedThemeProvider>
          </StyledEngineProvider>
        );
      }
      return <div />;
    }}
  />
);

export default Root;
