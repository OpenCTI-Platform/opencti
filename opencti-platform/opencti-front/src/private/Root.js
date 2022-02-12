import React from 'react';
import * as R from 'ramda';
import { useLazyLoadQuery } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import CssBaseline from '@mui/material/CssBaseline';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Index from './Index';
import { UserContext } from '../utils/Security';

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

const isFeatureEnable = (settings, id) => {
  const flags = settings.platform_feature_flags || [];
  const feature = R.find((f) => f.id === id, flags);
  return feature !== undefined && feature.enable === true;
};
const isModuleEnable = (settings, id) => {
  const modules = settings.platform_modules || [];
  const module = R.find((f) => f.id === id, modules);
  return module !== undefined && module.enable === true;
};
const buildHelper = (settings) => ({
  isModuleEnable: (id) => isModuleEnable(settings, id),
  isRuleEngineEnable: () => isModuleEnable(settings, 'RULE_ENGINE'),
  isFeatureEnable: (id) => isFeatureEnable(settings, id),
  isRuntimeFieldEnable: () => isFeatureEnable(settings, 'RUNTIME_SORTING'),
});
const Root = () => {
  const data = useLazyLoadQuery(rootPrivateQuery);
  const { me, settings } = data;
  const helper = buildHelper(settings);
  return <UserContext.Provider value={{ me, settings, helper }}>
      <ConnectedThemeProvider settings={settings}>
        <CssBaseline/>
        <ConnectedIntlProvider settings={settings}>
          <Index me={me}/>
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </UserContext.Provider>;
};

export default Root;
