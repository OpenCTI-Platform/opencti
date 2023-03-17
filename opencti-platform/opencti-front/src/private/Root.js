import React, { useEffect } from 'react';
import graphql from 'babel-plugin-relay/macro';
import CssBaseline from '@material-ui/core/CssBaseline';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { commitMutation, QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Index from './Index';
import { UserContext } from '../utils/Security';
import AuthBoundaryComponent from './components/AuthBoundary';
import RootPublic from '../public/Root';
import { toastGenericError } from '../utils/bakedToast';

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

const rootTokenRenewMutation = graphql`
  mutation RootTokenRenewMutation {
    meTokenRenew {
      access_token
    }
  }
`;

const logoutMutation = graphql`
  mutation RootLogoutMutation {
    logout
  }
`;

const clearToken = () => {
  localStorage.removeItem('token');
};

function checkToken(history) {
  const token = localStorage.getItem('token');
  if (token === null) {
    return;
  }
  const jwtToken = JSON.parse(atob(token.split('.')[1]));
  const expiration = ((jwtToken.exp - 60) * 1000) - Date.now();
  if (expiration < 90000) {
    commitMutation({
      mutation: rootTokenRenewMutation,
      onCompleted: ({ meTokenRenew }) => {
        localStorage.setItem('token', meTokenRenew.access_token);
      },
      onError: (err) => {
        if (err.res.errors?.[0].name === 'AuthFailure') {
          commitMutation({
            mutation: logoutMutation,
            variables: {},
            onCompleted: () => {
              history.push('/');
              localStorage.removeItem('token');
            },
          });
        } else {
          toastGenericError('failed to refresh token');
        }
      },
    });
  }
}

function setupTokenAndRefresh(token) {
  localStorage.setItem('token', token);
}

const Root = ({ history }) => {
  useEffect(() => {
    clearToken();
    const intervalId = setInterval(() => {
      checkToken(history);
    }, 30000);
    return () => clearInterval(intervalId);
  }, []);

  return (
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
          clearToken();
          if (props) {
            if (props.me && props.me.access_token) {
              setupTokenAndRefresh(props.me.access_token);
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
};

export default compose(withRouter)(Root);
