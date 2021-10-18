import React from 'react';
import graphql from 'babel-plugin-relay/macro';
import CssBaseline from '@material-ui/core/CssBaseline';
import { QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Index from './Index';
import { UserContext } from '../utils/Security';
import AuthBoundaryComponent from './components/AuthBoundary';
import { getAccount } from '../services/account.service';

const rootPrivateQuery = graphql`
  query RootPrivateQuery {
    me {
      id
      name
      lastname
      language
      theme
      user_email
      theme
      access_token
      capabilities {
        name
      }
    }
    settings {
      platform_map_tile_server_dark
      platform_map_tile_server_light
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
    }
  }
`;

const clearToken = () => {
  localStorage.removeItem('token');
};

const clearClientId = () => {
  localStorage.removeItem('client_id');
};

const Root = () => (
  <AuthBoundaryComponent>
    <QueryRenderer
      query={rootPrivateQuery}
      variables={{}}
      render={({ props }) => {
        clearToken();
        clearClientId();
        if (props) {
          if (props.me && props.me.access_token) {
            const token = props.me.access_token;
            localStorage.setItem('token', token);
            getAccount().then((res) => {
              const account = res.data;
              if (account) {
                const clientId = account.clients?.[0].client_id;
                localStorage.setItem('client_id', clientId);
              } else {
                clearToken();
              }
            });
          }
          return (
            <UserContext.Provider
              value={{ me: props.me, settings: props.settings }}
            >
              <ConnectedThemeProvider settings={props.settings}>
                <CssBaseline />
                <ConnectedIntlProvider settings={props.settings}>
                  <Index me={props.me} />
                </ConnectedIntlProvider>
              </ConnectedThemeProvider>
            </UserContext.Provider>
          );
        }
        return <div />;
      }}
    />
  </AuthBoundaryComponent>
);

export default Root;
