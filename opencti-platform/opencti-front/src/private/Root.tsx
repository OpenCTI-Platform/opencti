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
      individual_id
      capabilities {
        name
      }
      default_hidden_types
      default_marking {
        entity_type
        values {
          id
          definition
        }
      }
    }
    settings {
      platform_map_tile_server_dark
      platform_map_tile_server_light
      platform_theme
      platform_feature_flags {
        id
        enable
      }
      platform_modules {
        id
        enable
        running
      }
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
      ...PasswordPolicies
      ...Policies
    }
    about {
      version
    }
    entitySettings {
      ...useEntitySettingsConnection_entitySettings
    }
    schemaSCOs: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSDOs: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSROs: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

const Root = () => {
  const data = useLazyLoadQuery<RootPrivateQuery>(rootPrivateQuery, {});
  const { me, settings, entitySettings, schemaSCOs, schemaSDOs, schemaSROs } = data;
  const schema = {
    scos: schemaSCOs.edges.map((sco) => sco.node),
    sdos: schemaSDOs.edges.map((sco) => sco.node),
    sros: schemaSROs.edges.map((sco) => sco.node),
  };
  // TODO : Use the hook useHelper when all project is pure function //
  const platformModuleHelpers = platformModuleHelper(settings);
  return (
    <UserContext.Provider value={{ me, settings, entitySettings, platformModuleHelpers, schema }}>
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
