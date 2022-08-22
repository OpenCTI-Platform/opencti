import React from 'react';
import graphql from 'babel-plugin-relay/macro';
import CssBaseline from '@material-ui/core/CssBaseline';
import { QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Index from './Index';
import { UserContext } from '../utils/Security';
import AuthBoundaryComponent from './components/AuthBoundary';
import RootPublic from '../public/Root';

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

const Root = () => (
  <AuthBoundaryComponent>
    <QueryRenderer
      query={rootPrivateQuery}
      variables={{}}
      render={(data) => {
        const { props, retry } = data;
        // Check in conjunction with query renderer. Rather than throwing an error for failed root
        // query pass the empty data and do the login render here since query render can't do
        // redirect or render stuff.
        if (props === null) {
          return <RootPublic />;
        }
        if (props) {
          if (props.me && props.me.access_token) {
            const token = props.me.access_token;
            localStorage.setItem('token', token);
          }
          return (
            <UserContext.Provider
              value={{ me: props.me, settings: props.settings }}
            >
              <ConnectedThemeProvider settings={props.settings}>
                <CssBaseline />
                <ConnectedIntlProvider settings={props.settings}>
                  <Index retry={retry} me={props.me} />
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
