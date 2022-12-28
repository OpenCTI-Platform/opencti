import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Index from './Index';
import { UserContext } from '../utils/hooks/useAuth';
import { RootPrivateQuery } from './__generated__/RootPrivateQuery.graphql';
import platformModuleHelper from '../utils/platformModulesHelper';

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
      individual_id
      capabilities {
        name
      }
    }
    settings {
      platform_map_tile_server_dark
      platform_map_tile_server_light
      platform_hidden_types
      platform_entities_files_ref
      platform_theme
      platform_feature_flags {
        id
        enable
      }
      platform_modules {
        id
        enable
      }
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
    }
    about {
      version
    }
  }
`;

const Root = () => {
  const data = useLazyLoadQuery<RootPrivateQuery>(rootPrivateQuery, {});
  const { me, settings } = data;
  // TODO : Use the hook useHelper when all project is pure function //
  const helper = platformModuleHelper(settings);
  return (
    <UserContext.Provider value={{ me, settings, helper }}>
      <StyledEngineProvider injectFirst={true}>
        <ConnectedThemeProvider settings={settings}>
          <ConnectedIntlProvider settings={settings}>
            <Index />
          </ConnectedIntlProvider>
        </ConnectedThemeProvider>
      </StyledEngineProvider>
    </UserContext.Provider>
  );
};

export default Root;
