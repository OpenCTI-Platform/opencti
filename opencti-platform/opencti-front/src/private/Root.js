import React from 'react';
import graphql from 'babel-plugin-relay/macro';
import CssBaseline from '@material-ui/core/CssBaseline';
import { QueryRenderer } from '../relay/environment';
import QueryRendererDarkLight from '../relay/environmentDarkLight';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Index from './Index';
import { UserContext } from '../utils/Security';
import AuthBoundaryComponent from './components/AuthBoundary';

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

// const DarkLightAssetsQuery = graphql`
//   query DarkLightAssetsQuery {
//     computingDeviceList {
//       id
//       name
//     }
//   }
// `;

const Root = () => (
  <AuthBoundaryComponent>
    <QueryRenderer
      query={rootPrivateQuery}
      variables={{}}
      render={({ props }) => {
        if (props) {
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
