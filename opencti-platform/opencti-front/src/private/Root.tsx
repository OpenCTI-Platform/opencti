import { StyledEngineProvider } from '@mui/material/styles';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { AnalyticsProvider } from 'use-analytics';
import Analytics from 'analytics';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { SYSTEM_BANNER_HEIGHT } from '../public/components/SystemBanners';
import { UserContext } from '../utils/hooks/useAuth';
import platformModuleHelper from '../utils/platformModulesHelper';
import { ONE_SECOND } from '../utils/Time';
import { isNotEmptyField } from '../utils/utils';
import { RootPrivateQuery } from './__generated__/RootPrivateQuery.graphql';
import Index from './Index';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import Loader from '../components/Loader';
import generateAnalyticsConfig from './Analytics';
import { RootSettings$data, RootSettings$key } from './__generated__/RootSettings.graphql';

const rootSettingsFragment = graphql`
  fragment RootSettings on Settings {
    id
    platform_demo
    platform_banner_text
    platform_user_statuses {
      status
      message
    }
    platform_banner_level
    platform_critical_alerts {
      message
      type
      details {
        users {
          id 
          name 
        }
      }
    }
    platform_map_tile_server_dark
    platform_map_tile_server_light
    platform_theme
    platform_whitemark
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
      warning
    }
    enterprise_edition
    ...AppThemeProvider_settings
    ...AppIntlProvider_settings
    ...PasswordPolicies
    ...Policies
    analytics_google_analytics_v4
  }
`;

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
      unit_system
      default_dashboards {
        id
        name
      }
      default_dashboard {
        id
      }
      default_time_field
      default_hidden_types
      default_marking {
        entity_type
        values {
          id
          definition
        }
      }
      administrated_organizations {
        id
        name
        authorized_authorities
      }
      allowed_marking {
        id
        entity_type
        standard_id
        definition_type
        definition
        x_opencti_color
        x_opencti_order
      }
    }
    settings {
      ...RootSettings
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
    schemaSMOs: subTypes(type: "Stix-Meta-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSCRs: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaRelationsTypesMapping {
      key
      values
    }
    schemaRelationsRefTypesMapping {
      key
      values
    }
  }
`;

const computeBannerSettings = (settings: RootSettings$data) => {
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
  const { me, settings: settingsFragment, entitySettings, schemaSCOs, schemaSDOs, schemaSMOs, schemaSCRs, schemaRelationsTypesMapping, schemaRelationsRefTypesMapping } = queryData;
  const settings = useFragment<RootSettings$key>(rootSettingsFragment, settingsFragment);
  const schema = {
    scos: schemaSCOs.edges.map((sco) => sco.node),
    sdos: schemaSDOs.edges.map((sco) => sco.node),
    smos: schemaSMOs.edges.map((smo) => smo.node),
    scrs: schemaSCRs.edges.map((scr) => scr.node),
    schemaRelationsTypesMapping: new Map(schemaRelationsTypesMapping.map((n) => [n.key, n.values])),
    schemaRelationsRefTypesMapping: new Map(schemaRelationsRefTypesMapping.map((n) => [n.key, n.values])),
  };
  // TODO : Use the hook useHelper when all project is pure function //
  const bannerSettings = computeBannerSettings(settings);
  const platformModuleHelpers = platformModuleHelper(settings);
  const platformAnalyticsConfiguration = generateAnalyticsConfig(settings);
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
            <AnalyticsProvider instance={Analytics(platformAnalyticsConfiguration)}>
              <Index settings={settings} />
            </AnalyticsProvider>
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
