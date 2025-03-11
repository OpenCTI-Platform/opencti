import { StyledEngineProvider } from '@mui/material/styles';
import React, { FunctionComponent, useMemo } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useSubscription } from 'react-relay';
import { AnalyticsProvider } from 'use-analytics';
import Analytics from 'analytics';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { SYSTEM_BANNER_HEIGHT } from '../public/components/SystemBanners';
import { FilterDefinition, UserContext } from '../utils/hooks/useAuth';
import platformModuleHelper from '../utils/platformModulesHelper';
import { ONE_SECOND } from '../utils/Time';
import { isNotEmptyField } from '../utils/utils';
import Index from './Index';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import Loader from '../components/Loader';
import generateAnalyticsConfig from './Analytics';
import { RootMe_data$key } from './__generated__/RootMe_data.graphql';
import { RootPrivateQuery } from './__generated__/RootPrivateQuery.graphql';
import { RootSettings$data, RootSettings$key } from './__generated__/RootSettings.graphql';

const rootSettingsFragment = graphql`
  fragment RootSettings on Settings {
    id
    platform_title
    platform_demo
    platform_banner_text
    request_access_enabled
    platform_user_statuses {
      status
      message
    }
    platform_banner_level
    platform_critical_alerts {
      message
      type
      details {
        groups {
          id 
          name 
        }
      }
    }
    platform_language
    platform_map_tile_server_dark
    platform_map_tile_server_light
    platform_openbas_url
    platform_openbas_disable_display
    platform_openerm_url
    platform_openmtd_url
    platform_xtmhub_url
    platform_theme
    platform_whitemark
    platform_organization {
      id
    }
    platform_session_idle_timeout
    platform_session_timeout
    platform_feature_flags {
      id
      enable
    }
    playground_enabled
    platform_modules {
      id
      enable
      running
      warning
    }
    platform_enterprise_edition {
      license_validated
      license_expired
      license_expiration_date
      license_start_date
      license_expiration_prevention
      license_valid_cert
      license_customer
      license_enterprise
      license_platform
      license_platform_match
      license_type
    }
    ...AppThemeProvider_settings
    ...AppIntlProvider_settings
    ...PasswordPolicies
    ...Policies
    analytics_google_analytics_v4
    platform_ai_enabled
    platform_ai_type
    platform_ai_has_token
    platform_trash_enabled
    platform_protected_sensitive_config {
      enabled
      markings {
        enabled
        protected_ids
      }
      groups {
        enabled
        protected_ids
      }
      roles {
        enabled
        protected_ids
      }
      rules {
        enabled
        protected_ids
      }
      file_indexing {
        enabled
        protected_ids
      }
      platform_organization {
        enabled
        protected_ids
      }
      ce_ee_toggle {
        enabled
        protected_ids
      }
      connector_reset {
        enabled
        protected_ids
      }
    }
  }
`;

const meUserFragment = graphql`
  fragment RootMe_data on MeUser {
    id
    name
    entity_type
    lastname
    language
    theme
    user_email
    individual_id
    no_creators
    restrict_delete
    draftContext {
      id
      name
      draft_status
      processingCount
    }
    effective_confidence_level {
      max_confidence
      overrides {
        entity_type
        max_confidence
      }
    }
    capabilities {
      name
    }
    unit_system
    submenu_show_icons
    submenu_auto_collapse
    monochrome_labels
    default_dashboards {
      id
      name
    }
    default_dashboard {
      id
    }
    default_time_field
    default_hidden_types
    effective_confidence_level {
      max_confidence
    }
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
    max_shareable_marking {
      id
      definition_type
      x_opencti_order
    }
    personal_notifiers {
      id
      name
    }
    can_manage_sensitive_config
  }
`;

const subscription = graphql`
  subscription RootMeSubscription {
    me {
      ...RootMe_data
    }
  }
`;

const rootPrivateQuery = graphql`
  query RootPrivateQuery {
    me {
      ...RootMe_data
    }
    settings {
      ...RootSettings
    }
    themes {
      edges {
        node {
          name
          manifest
        }
      }
    }
    about {
      version
    }
    entitySettings {
      edges {
        node {
          id
          ...EntitySettingSettings_entitySetting
        }
      }
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
      values {
        name
        toTypes
      }
    }
    filterKeysSchema {
      entity_type
      filters_schema {
        filterKey
        filterDefinition {
          filterKey
          label
          type
          multiple
          subEntityTypes
          elementsForFilterValuesSearch
          subFilters {
            filterKey
            label
            type
            multiple
            subEntityTypes
            elementsForFilterValuesSearch
          }
        }
      }
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
  const {
    me: meFragment,
    settings: settingsFragment,
    themes,
    entitySettings,
    schemaSCOs,
    schemaSDOs,
    schemaSMOs,
    schemaSCRs,
    schemaRelationsTypesMapping,
    schemaRelationsRefTypesMapping,
    filterKeysSchema,
  } = queryData;
  const settings = useFragment<RootSettings$key>(rootSettingsFragment, settingsFragment);
  const me = useFragment<RootMe_data$key>(meUserFragment, meFragment);

  const subConfig = useMemo(
    () => ({
      subscription,
      variables: {},
    }),
    [me.id],
  );
  useSubscription(subConfig);

  const schema = {
    scos: schemaSCOs.edges.map((sco) => sco.node),
    sdos: schemaSDOs.edges.map((sco) => sco.node),
    smos: schemaSMOs.edges.map((smo) => smo.node),
    scrs: schemaSCRs.edges.map((scr) => scr.node),
    schemaRelationsTypesMapping: new Map(schemaRelationsTypesMapping.map((n) => [n.key, n.values])),
    schemaRelationsRefTypesMapping: new Map(schemaRelationsRefTypesMapping.map((n) => [n.key, n.values])),
    filterKeysSchema: new Map(filterKeysSchema.map((n) => {
      const filtersSchema = new Map(n.filters_schema.map((o) => [o.filterKey, o.filterDefinition as FilterDefinition]));
      return [n.entity_type, filtersSchema];
    })),
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
        <ConnectedThemeProvider settings={settings} themes={themes}>
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
