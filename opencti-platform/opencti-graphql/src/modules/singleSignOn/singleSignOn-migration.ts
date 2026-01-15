import {
  type ConfigurationTypeInput,
  type GroupsManagement,
  type GroupsManagementInput,
  type OrganizationsManagement,
  type OrganizationsManagementInput,
  type SingleSignOnAddInput,
  type SingleSignOnMigrationResult,
  StrategyType,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { now } from 'moment';
import { nowTime } from '../../utils/format';
import { internalAddSingleSignOn } from './singleSignOn-domain';
import type { AuthContext, AuthUser } from '../../types/user';
import { v4 as uuid } from 'uuid';
import { EnvStrategyType, isAuthenticationProviderMigrated, LOCAL_STRATEGY_IDENTIFIER } from '../../config/providers-configuration';
import { configRemapping, MIGRATED_STRATEGY } from '../../config/providers-initialization';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import { settingsEditField } from '../../domain/settings';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { AuthRequired } from '../../config/errors';

// Key that should not be present after migration
const DEPRECATED_KEYS = ['roles_management'];

// Key that have dedicated usage in OpenCTI and must not be in the configuration array
const NO_CONFIGURATION_KEY = ['label', 'disabled'];

const GROUP_MANAGEMENT_KEY = 'groups_management';
const ORG_MANAGEMENT_KEY = 'organizations_management';

interface ConfigurationType {
  configuration: ConfigurationTypeInput[];
  groups_management?: GroupsManagementInput;
  organizations_management?: OrganizationsManagementInput;
  skipped_configuration: string[];
}

const computeConfiguration = (envConfiguration: any, strategy: StrategyType) => {
  const configuration: ConfigurationTypeInput[] = [];
  let groups_management: GroupsManagementInput | undefined;
  let organizations_management: OrganizationsManagementInput | undefined;
  const skipped_configuration: string[] = [];

  if (envConfiguration.config) {
    // TODO we will need to move this function inside current file
    const mappedConfig = strategy === StrategyType.OpenIdConnectStrategy ? envConfiguration.config : configRemapping(envConfiguration.config);
    for (const configKey in mappedConfig) {
      logApp.debug(`[SSO MIGRATION] current config key:${configKey}`);

      if (DEPRECATED_KEYS.some((deprecatedKey) => deprecatedKey === configKey)) {
        // 1. Check if it's a deprecated key that should be ignored
        skipped_configuration.push(configKey);
        logApp.warn(`[SSO MIGRATION] ${configKey} is deprecated, ignored during migration`);
      } else if (NO_CONFIGURATION_KEY.some((noConfigKey) => noConfigKey === configKey)) {
        logApp.info(`[SSO MIGRATION] config key removed:${configKey}`);
      } else if (configKey === GROUP_MANAGEMENT_KEY) {
        // 2. Extract group management
        const currentValue = mappedConfig[configKey];
        logApp.info('[SSO MIGRATION] groups management configured', currentValue);

        const { group_attributes, group_attribute, groups_mapping, groups_path, read_userinfo, token_reference } = currentValue;
        groups_management = {};

        // SAML, OpenId and LDAP
        if (groups_mapping) {
          groups_management['groups_mapping'] = groups_mapping;
        } else {
          groups_management['groups_mapping'] = [];
        }

        // SAML only
        if (group_attributes) {
          groups_management['group_attributes'] = group_attributes;
        } else if (strategy === StrategyType.SamlStrategy) {
          groups_management['group_attributes'] = ['groups'];
        }

        // OpenId only
        if (groups_path) {
          groups_management['groups_path'] = groups_path;
        } else if (strategy === StrategyType.OpenIdConnectStrategy) {
          groups_management['groups_path'] = ['groups'];
        }
        // OpenId only
        if (read_userinfo) {
          groups_management['read_userinfo'] = read_userinfo;
        } else if (strategy === StrategyType.OpenIdConnectStrategy) {
          groups_management['read_userinfo'] = false;
        }
        // OpenId only
        if (token_reference) {
          groups_management['token_reference'] = token_reference;
        } else if (strategy === StrategyType.OpenIdConnectStrategy) {
          groups_management['token_reference'] = 'access_token';
        }
        // LDAP only
        if (group_attribute) {
          groups_management['group_attribute'] = group_attribute;
        } else if (strategy === StrategyType.LdapStrategy) {
          groups_management['group_attribute'] = 'cn';
        }
      } else if (configKey === ORG_MANAGEMENT_KEY) {
      // 3. Extract organization management
        const currentValue = mappedConfig[configKey];
        logApp.info('[SSO MIGRATION] organizations management configured', currentValue);

        const { organizations_path, organizations_mapping } = currentValue;
        organizations_management = {};

        // SAML, OpenId and LDAP
        if (organizations_path) {
          organizations_management['organizations_path'] = organizations_path;
        } else if (strategy === StrategyType.SamlStrategy || StrategyType.OpenIdConnectStrategy || StrategyType.LdapStrategy) {
          organizations_management['organizations_path'] = ['organizations'];
        }

        if (organizations_mapping) {
          organizations_management['organizations_mapping'] = organizations_mapping;
        } else {
          organizations_management['organizations_mapping'] = [];
        }
      } else {
        // 5. Everything else is configuration
        const currentValue = mappedConfig[configKey];
        if (typeof currentValue === 'number') {
          const currentConfig: ConfigurationTypeInput = {
            key: configKey,
            type: 'number',
            value: `${mappedConfig[configKey]}`,
          };
          configuration.push(currentConfig);
        } else if (typeof currentValue === 'boolean') {
          const currentConfig: ConfigurationTypeInput = {
            key: configKey,
            type: 'boolean',
            value: `${mappedConfig[configKey]}`,
          };
          configuration.push(currentConfig);
        } else if (Array.isArray(currentValue)) {
          const currentConfig: ConfigurationTypeInput = {
            key: configKey,
            type: 'array',
            value: JSON.stringify(mappedConfig[configKey].map((val: string) => val)),
          };
          configuration.push(currentConfig);
        } else {
          const currentConfig: ConfigurationTypeInput = {
            key: configKey,
            type: 'string',
            value: `${mappedConfig[configKey]}`,
          };
          configuration.push(currentConfig);
        }
      }
    }
  }
  const result: ConfigurationType = {
    configuration, groups_management, organizations_management, skipped_configuration,
  };
  return result;
};

const computeEnabled = (envConfiguration: any) => {
  return !(envConfiguration?.config?.disabled === true);
};

const computeAuthenticationName = (ssoKey: string, envConfiguration: any, identifier: string) => {
  const providerLabel = envConfiguration?.config?.label || ssoKey;
  return `${providerLabel} ${identifier} migrated on ${nowTime()}`;
};

const computeAuthenticationLabel = (ssoKey: string, envConfiguration: any) => {
  const providerName = envConfiguration?.config?.label || ssoKey;
  return `${providerName}`;
};

const parseSAMLStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management, organizations_management } = computeConfiguration(envConfiguration, StrategyType.SamlStrategy);
  const identifier = envConfiguration?.identifier || 'saml';

  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.SamlStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration, identifier),
    identifier,
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.SamlStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
    organizations_management,
  };
  return authEntity;
};

const parseOpenIdStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management, organizations_management } = computeConfiguration(envConfiguration, StrategyType.OpenIdConnectStrategy);
  const identifier = envConfiguration?.identifier || 'oic';

  const authEntity: SingleSignOnAddInput = {
    identifier,
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration, identifier),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
    organizations_management,
  };
  return authEntity;
};

const parseLDAPStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management, organizations_management } = computeConfiguration(envConfiguration, StrategyType.LdapStrategy);
  const identifier = envConfiguration?.identifier || 'ldapauth';

  const authEntity: SingleSignOnAddInput = {
    identifier,
    strategy: StrategyType.LdapStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration, identifier),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.LdapStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
    organizations_management,
  };
  return authEntity;
};

const parseLocalStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.LocalStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration, LOCAL_STRATEGY_IDENTIFIER),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.LocalStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    identifier: LOCAL_STRATEGY_IDENTIFIER,
  };
  return authEntity;
};

export const parseSingleSignOnRunConfiguration = async (context: AuthContext, user: AuthUser, envConfiguration: any, dryRun: boolean) => {
  const authenticationStrategiesInput: SingleSignOnAddInput[] = [];
  for (const ssoKey in envConfiguration) {
    const currentSSOconfig = envConfiguration[ssoKey];
    logApp.info(`[SSO MIGRATION] reading ${ssoKey}`);

    if (currentSSOconfig.strategy) {
      if (!MIGRATED_STRATEGY.some((strategyName) => strategyName === currentSSOconfig.strategy)) {
        // Allow migration only for full migrated strategies.
        logApp.info(`[SSO MIGRATION] ${currentSSOconfig.strategy} detected but migration is not implemented yet`);
      } else {
        switch (currentSSOconfig.strategy) {
          case EnvStrategyType.STRATEGY_LOCAL:
            logApp.info('[SSO MIGRATION] Looking at LocalStrategy migration');
            authenticationStrategiesInput.push(parseLocalStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_OPENID:
            logApp.info('[SSO MIGRATION] Looking at OpenID migration');
            authenticationStrategiesInput.push(parseOpenIdStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_SAML:
            logApp.info('[SSO MIGRATION] Looking at SAML migration');
            authenticationStrategiesInput.push(parseSAMLStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_LDAP:
            logApp.info('[SSO MIGRATION] Looking at LDAP migration');
            authenticationStrategiesInput.push(parseLDAPStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_CERT:
            logApp.warn(`[SSO MIGRATION] NOT IMPLEMENTED ${currentSSOconfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_HEADER:
            logApp.warn(`[SSO MIGRATION] NOT IMPLEMENTED ${currentSSOconfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_FACEBOOK:
            logApp.warn(`[SSO MIGRATION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_AUTH0:
            logApp.warn(`[SSO MIGRATION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_GITHUB:
            logApp.warn(`[SSO MIGRATION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_GOOGLE:
            logApp.warn(`[SSO MIGRATION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
            break;

          default:
            logApp.error('[SSO MIGRATION] unknown strategy in configuration', {
              providerKey: ssoKey,
              strategy: currentSSOconfig.strategy,
            });
            break;
        }
      }
    } else {
      logApp.error('[SSO MIGRATION] strategy not defined in configuration', { providerKey: ssoKey });
    }
  }

  // checking capa before doing all database changes
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) throw AuthRequired('SETTINGS_SET_ACCESSES is required');
  if (dryRun) {
    // When dryRun: convert authenticationStrategiesInput into display object
    const authenticationStrategies: SingleSignOnMigrationResult[] = [];
    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      const queryResult: SingleSignOnMigrationResult = {
        enabled: authenticationStrategiesInput[i].enabled,
        name: authenticationStrategiesInput[i].name,
        label: authenticationStrategiesInput[i].label,
        strategy: authenticationStrategiesInput[i].strategy,
        description: authenticationStrategiesInput[i].description,
        id: uuid(),
        configuration: authenticationStrategiesInput[i].configuration,
        groups_management: authenticationStrategiesInput[i].groups_management as GroupsManagement,
        organizations_management: authenticationStrategiesInput[i].organizations_management as OrganizationsManagement,
        identifier: authenticationStrategiesInput[i].identifier,
      };
      authenticationStrategies.push(queryResult);
    }
    return authenticationStrategies;
  } else {
    // When no dry run: save in database, and then convert BasicStore into display object
    logApp.info('[SSO MIGRATION] starting to write migrated SSO in database');
    const authenticationStrategies: SingleSignOnMigrationResult[] = [];
    const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
    const migratedIdentifier: string[] = [];
    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      const currentAuthProvider = authenticationStrategiesInput[i];
      const identifier = currentAuthProvider.identifier;
      if (identifier && !isAuthenticationProviderMigrated(settings, identifier)) {
        logApp.info(`[SSO MIGRATION] creating new configuration for ${identifier}`);
        const created = await internalAddSingleSignOn(context, user, currentAuthProvider, true);
        const queryResult: SingleSignOnMigrationResult = {
          enabled: created.enabled,
          name: created.name,
          label: created.label,
          strategy: created.strategy,
          description: created.description,
          id: created.id,
          configuration: created.configuration,
          identifier: created.identifier,
        };
        migratedIdentifier.push(identifier);
        authenticationStrategies.push(queryResult);
      } else {
        logApp.info(`[SSO MIGRATION] skipping ${currentAuthProvider.strategy} - ${identifier} as it's already in database.`, { auth_strategy_migrated: settings?.auth_strategy_migrated });
      }
    }

    if (migratedIdentifier.length > 0) {
      let newList: string[];
      if (settings.auth_strategy_migrated) {
        newList = migratedIdentifier.concat(settings.auth_strategy_migrated);
      } else {
        newList = migratedIdentifier;
      }
      logApp.info('[SSO MIGRATION] New list of migrated identifier saved in settings', { newList });
      await settingsEditField(context, user, settings.id, [
        { key: 'auth_strategy_migrated', value: newList },
      ]);
    }

    return authenticationStrategies;
  }
};
