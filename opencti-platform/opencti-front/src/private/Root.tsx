import { StyledEngineProvider } from '@mui/material/styles';
import React, { FunctionComponent } from 'react';
import { graphql, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { SYSTEM_BANNER_HEIGHT } from '../public/components/SystemBanners';
import { UserContext } from '../utils/hooks/useAuth';
import platformModuleHelper from '../utils/platformModulesHelper';
import { ONE_SECOND } from '../utils/Time';
import { isNotEmptyField } from '../utils/utils';
import {
  RootPrivateQuery,
  RootPrivateQuery$data,
} from './__generated__/RootPrivateQuery.graphql';
import Index from './Index';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import Loader from '../components/Loader';

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
      default_dashboards {
        id
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
      id
      platform_demo
      platform_banner_text
      platform_banner_level
      platform_map_tile_server_dark
      platform_map_tile_server_light
      platform_theme
      platform_session_idle_timeout
      platform_session_timeout
      platform_feature_flags {
        id
        enable
      }
      platform_modules {
        id
        enable
        running
      }
      enterprise_edition
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

const computeBannerSettings = (settings: RootPrivateQuery$data['settings']) => {
  const bannerLevel = settings.platform_banner_level;
  const bannerText = settings.platform_banner_text;
  const isBannerActivated = isNotEmptyField(bannerLevel) && isNotEmptyField(bannerText);
  const idleTimeout = settings.platform_session_idle_timeout ?? 0;
  const sessionTimeout = settings.platform_session_timeout ?? 0;
  const idleLimit = idleTimeout ? Math.floor(idleTimeout / ONE_SECOND) : 0;
  const sessionLimit = sessionTimeout
    ? Math.floor(sessionTimeout / ONE_SECOND)
    : 0;
  const bannerHeight = isBannerActivated ? `${SYSTEM_BANNER_HEIGHT}px` : '0';
  const bannerHeightNumber = isBannerActivated ? SYSTEM_BANNER_HEIGHT : 0;
  return {
    bannerText,
    bannerLevel,
    bannerHeight,
    bannerHeightNumber,
    idleLimit,
    sessionLimit,
  };
};

interface RootComponentProps {
  queryRef: PreloadedQuery<RootPrivateQuery>;
}

const RootComponent: FunctionComponent<RootComponentProps> = ({ queryRef }) => {
  const queryData = usePreloadedQuery(rootPrivateQuery, queryRef);
  const { me, settings, entitySettings, schemaSCOs, schemaSDOs, schemaSROs } = queryData;
  const schema = {
    scos: schemaSCOs.edges.map((sco) => sco.node),
    sdos: schemaSDOs.edges.map((sco) => sco.node),
    sros: schemaSROs.edges.map((sco) => sco.node),
  };
  // TODO : Use the hook useHelper when all project is pure function //
  const bannerSettings = computeBannerSettings(settings);
  const platformModuleHelpers = platformModuleHelper(settings);
  return (
    <UserContext.Provider
      value={{
        me,
        settings,
        bannerSettings,
        entitySettings,
        platformModuleHelpers,
        schema,
      }}
    >
      <StyledEngineProvider injectFirst={true}>
        <ConnectedThemeProvider settings={settings}>
          <ConnectedIntlProvider settings={settings}>
            <Index settings={settings} />
          </ConnectedIntlProvider>
        </ConnectedThemeProvider>
      </StyledEngineProvider>
    </UserContext.Provider>
  );
};

const Root = () => {
  const queryRef = useQueryLoading<RootPrivateQuery>(rootPrivateQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <RootComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
