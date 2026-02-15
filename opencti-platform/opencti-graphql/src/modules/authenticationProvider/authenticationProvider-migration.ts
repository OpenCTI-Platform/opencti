import {
  type GroupsManagement,
  type GroupsManagementInput,
  type OrganizationsManagement,
  type OrganizationsManagementInput,
  type AuthenticationProviderMigrationResult,
  AuthenticationProviderType,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { now } from 'moment';
import { nowTime } from '../../utils/format';
import { AUTH_SECRET_LIST, getAllIdentifiers, addAuthenticationProvider, SECRET_TYPE } from './authenticationProvider-domain';
import type { AuthContext, AuthUser } from '../../types/user';
import { v4 as uuid } from 'uuid';
import { EnvStrategyType, isAuthenticationProviderMigrated, MIGRATED_STRATEGY } from './providers-configuration';
import { configRemapping } from './providers-initialization';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { AuthRequired } from '../../config/errors';

// Key that should not be present after migration
const DEPRECATED_KEYS = ['roles_management'];

// Key that have dedicated usage in OpenCTI and must not be in the configuration array
const NO_CONFIGURATION_KEY = ['label', 'disabled'];

const GROUP_MANAGEMENT_KEY = 'groups_management';
const ORG_MANAGEMENT_KEY = 'organizations_management';
const CREDENTIALS_PROVIDER_KEY = 'credentials_provider';

interface ConfigurationType {
  configuration: ConfigurationTypeInput[];
  groups_management?: GroupsManagementInput;
  organizations_management?: OrganizationsManagementInput;
  skipped_configuration: string[];
}

const computeConfiguration = (envConfiguration: any, strategy: AuthenticationProviderType) => {
  const configuration: ConfigurationTypeInput[] = [];
  let groups_management: GroupsManagementInput | undefined;
  let organizations_management: OrganizationsManagementInput | undefined;
  const skipped_configuration: string[] = [];

  if (envConfiguration.config) {
    // TODO we will need to move this function inside current file
    const mappedConfig = strategy === AuthenticationProviderType.Oidc ? envConfiguration.config : configRemapping(envConfiguration.config);
    for (const configKey in mappedConfig) {
      logApp.debug(`[AUTH PROVIDER CONVERSION] current config key:${configKey}`);

      if (DEPRECATED_KEYS.some((deprecatedKey) => deprecatedKey === configKey)) {
        // 1. Check if it's a deprecated key that should be ignored
        skipped_configuration.push(configKey);
        logApp.warn(`[AUTH PROVIDER CONVERSION] ${configKey} is deprecated, ignored during conversion`);
      } else if (NO_CONFIGURATION_KEY.some((noConfigKey) => noConfigKey === configKey)) {
        logApp.info(`[AUTH PROVIDER CONVERSION] config key removed:${configKey}`);
      } else if (configKey === GROUP_MANAGEMENT_KEY) {
        // 2. Extract group management
        const currentValue = mappedConfig[configKey];
        logApp.info('[AUTH PROVIDER CONVERSION] groups management configured', currentValue);

        const {
          group_attributes,
          group_attribute,
          groups_mapping,
          groups_path,
          groups_scope,
          read_userinfo,
          token_reference,
          groups_splitter,
          groups_header,
        } = currentValue;
        groups_management = {};

        // SAML, OpenId and LDAP
        groups_management['groups_mapping'] = groups_mapping ?? [];

        // SAML only
        if (group_attributes) {
          groups_management['group_attributes'] = group_attributes;
        } else if (strategy === AuthenticationProviderType.Saml) {
          groups_management['group_attributes'] = ['groups'];
        }

        // OpenId only
        if (groups_path) {
          groups_management['groups_path'] = groups_path;
        } else if (strategy === AuthenticationProviderType.Oidc) {
          groups_management['groups_path'] = ['groups'];
        }
        // OpenId only
        if (read_userinfo) {
          groups_management['read_userinfo'] = read_userinfo;
        } else if (strategy === AuthenticationProviderType.Oidc) {
          groups_management['read_userinfo'] = false;
        }
        // OpenId only
        if (strategy === AuthenticationProviderType.Oidc && groups_scope) {
          groups_management['groups_scope'] = groups_scope;
        }
        // OpenId only
        if (token_reference) {
          groups_management['token_reference'] = token_reference;
        } else if (strategy === AuthenticationProviderType.Oidc) {
          groups_management['token_reference'] = 'access_token';
        }
        // LDAP only
        if (group_attribute) {
          groups_management['group_attribute'] = group_attribute;
        } else if (strategy === AuthenticationProviderType.Ldap) {
          groups_management['group_attribute'] = 'cn';
        }
      } else if (configKey === ORG_MANAGEMENT_KEY) {
      // 3. Extract organization management
        const currentValue = mappedConfig[configKey];
        logApp.info('[AUTH PROVIDER CONVERSION] organizations management configured', currentValue);

        const {
          organizations_path,
          organizations_mapping,
          organizations_scope,
          read_userinfo,
          token_reference,
          organizations_splitter,
          organizations_header,
        } = currentValue;
        organizations_management = {};

        // SAML, OpenId and LDAP
        if (organizations_path) {
          organizations_management['organizations_path'] = organizations_path;
        } else {
          organizations_management['organizations_path'] = ['organizations'];
        }
        // OpenId only
        if (strategy === AuthenticationProviderType.Oidc && organizations_scope) {
          organizations_management['organizations_scope'] = organizations_scope;
        }
        // OpenId only
        if (read_userinfo) {
          organizations_management['read_userinfo'] = read_userinfo;
        } else if (strategy === AuthenticationProviderType.Oidc) {
          organizations_management['read_userinfo'] = false;
        }
        // OpenId only
        if (token_reference) {
          organizations_management['token_reference'] = token_reference;
        } else if (strategy === AuthenticationProviderType.Oidc) {
          organizations_management['token_reference'] = 'access_token';
        }

        organizations_management['organizations_mapping'] = organizations_mapping ?? [];
      } else if (configKey === CREDENTIALS_PROVIDER_KEY) {
        skipped_configuration.push(configKey);
        logApp.warn(`[AUTH PROVIDER CONVERSION] ${configKey} is not supported yet, ignored during conversion`);
      } else if (configKey === 'redirect_uris' && strategy === AuthenticationProviderType.Oidc) {
        const currentConfig: ConfigurationTypeInput = {
          key: 'redirect_uri',
          type: 'string',
          value: mappedConfig[configKey][0],
        };
        configuration.push(currentConfig);
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
            type: AUTH_SECRET_LIST.includes(configKey) ? SECRET_TYPE : 'string',
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

const computeAuthenticationName = (providerKey: string, envConfiguration: any, identifier: string) => {
  const providerLabel = envConfiguration?.config?.label || providerKey;
  return `${providerLabel} ${identifier} migrated on ${nowTime()}`;
};

const computeAuthenticationLabel = (providerKey: string, envConfiguration: any) => {
  const providerName = envConfiguration?.config?.label || providerKey;
  return `${providerName}`;
};

const parseSAMLStrategyConfiguration = (providerKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management, organizations_management } = computeConfiguration(envConfiguration, AuthenticationProviderType.Saml);
  const identifier = envConfiguration?.identifier || 'saml';

  const authEntity: SingleSignOnAddInput = {
    strategy: AuthenticationProviderType.Saml,
    name: computeAuthenticationName(providerKey, envConfiguration, identifier),
    identifier,
    label: computeAuthenticationLabel(providerKey, envConfiguration),
    description: `${AuthenticationProviderType.Saml} Automatically ${dryRun ? 'detected' : 'created'} from ${providerKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
    organizations_management,
  };
  return authEntity;
};

const parseOpenIdStrategyConfiguration = (providerKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management, organizations_management } = computeConfiguration(envConfiguration, AuthenticationProviderType.Oidc);
  const identifier = envConfiguration?.identifier || 'oic';

  const authEntity: SingleSignOnAddInput = {
    identifier,
    strategy: AuthenticationProviderType.Oidc,
    name: computeAuthenticationName(providerKey, envConfiguration, identifier),
    label: computeAuthenticationLabel(providerKey, envConfiguration),
    description: `${AuthenticationProviderType.Oidc} Automatically ${dryRun ? 'detected' : 'created'} from ${providerKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
    organizations_management,
  };
  return authEntity;
};

const parseLDAPStrategyConfiguration = (providerKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management, organizations_management } = computeConfiguration(envConfiguration, AuthenticationProviderType.Ldap);
  const identifier = envConfiguration?.identifier || 'ldapauth';

  const authEntity: SingleSignOnAddInput = {
    identifier,
    strategy: AuthenticationProviderType.Ldap,
    name: computeAuthenticationName(providerKey, envConfiguration, identifier),
    label: computeAuthenticationLabel(providerKey, envConfiguration),
    description: `${AuthenticationProviderType.Ldap} Automatically ${dryRun ? 'detected' : 'created'} from ${providerKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
    organizations_management,
  };
  return authEntity;
};

export const parseAuthenticationProviderConfiguration = async (context: AuthContext, user: AuthUser, envConfiguration: any, dryRun: boolean) => {
  const authenticationStrategiesInput: SingleSignOnAddInput[] = [];
  for (const providerKey in envConfiguration) {
    const currentProviderConfig = envConfiguration[providerKey];
    logApp.info(`[AUTH PROVIDER CONVERSION] reading ${providerKey}`);

    if (currentProviderConfig.strategy) {
      if (!MIGRATED_STRATEGY.some((strategyName) => strategyName === currentProviderConfig.strategy)) {
        // Allow migration only for full migrated strategies.
        logApp.info(`[AUTH PROVIDER CONVERSION] ${currentProviderConfig.strategy} detected but conversion is not implemented yet`);
      } else {
        switch (currentProviderConfig.strategy) {
          case EnvStrategyType.STRATEGY_OPENID:
            logApp.info('[AUTH PROVIDER CONVERSION] Looking at OpenID conversion');
            authenticationStrategiesInput.push(parseOpenIdStrategyConfiguration(providerKey, currentProviderConfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_SAML:
            logApp.info('[AUTH PROVIDER CONVERSION] Looking at SAML conversion');
            authenticationStrategiesInput.push(parseSAMLStrategyConfiguration(providerKey, currentProviderConfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_LDAP:
            logApp.info('[AUTH PROVIDER CONVERSION] Looking at LDAP conversion');
            authenticationStrategiesInput.push(parseLDAPStrategyConfiguration(providerKey, currentProviderConfig, dryRun));
            break;
          case EnvStrategyType.STRATEGY_FACEBOOK:
            logApp.warn(`[AUTH PROVIDER CONVERSION] DEPRECATED ${currentProviderConfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_AUTH0:
            logApp.warn(`[AUTH PROVIDER CONVERSION] DEPRECATED ${currentProviderConfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_GITHUB:
            logApp.warn(`[AUTH PROVIDER CONVERSION] DEPRECATED ${currentProviderConfig.strategy} detected.`);
            break;
          case EnvStrategyType.STRATEGY_GOOGLE:
            logApp.warn(`[AUTH PROVIDER CONVERSION] DEPRECATED ${currentProviderConfig.strategy} detected.`);
            break;

          default:
            logApp.error('[AUTH PROVIDER CONVERSION] unknown strategy in configuration', {
              providerKey: providerKey,
              strategy: currentProviderConfig.strategy,
            });
            break;
        }
      }
    } else {
      logApp.error('[AUTH PROVIDER CONVERSION] strategy not defined in configuration', { providerKey: providerKey });
    }
  }

  // checking capa before doing all database changes
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) throw AuthRequired('SETTINGS_SET_ACCESSES is required');
  if (dryRun) {
    // When dryRun: convert authenticationStrategiesInput into display object
    const authenticationStrategies: AuthenticationProviderMigrationResult[] = [];
    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      const queryResult: AuthenticationProviderMigrationResult = {
        enabled: authenticationStrategiesInput[i].enabled,
        name: authenticationStrategiesInput[i].name,
        button_label_override: authenticationStrategiesInput[i].label,
        type: authenticationStrategiesInput[i].strategy,
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
    logApp.info('[AUTH PROVIDER CONVERSION] starting to write migrated provider in database');
    const authenticationStrategies: AuthenticationProviderMigrationResult[] = [];
    const identifiersInDb = await getAllIdentifiers(context, user);

    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      const currentAuthProvider = authenticationStrategiesInput[i];
      try {
        const identifier = currentAuthProvider.identifier;
        if (identifier && !isAuthenticationProviderMigrated(identifiersInDb, identifier)) {
          logApp.info(`[AUTH PROVIDER CONVERSION] creating new configuration for ${identifier}`);
          const created = await addAuthenticationProvider(context, user, currentAuthProvider, currentAuthProvider.type, true);
          const queryResult: AuthenticationProviderMigrationResult = {
            enabled: created.enabled,
            name: created.name,
            button_label_override: created.button_label_override,
            type: created.type,
            description: created.description,
            id: created.id,
            configuration: created.configuration,
            identifier_override: created.identifier_override,
          };
          authenticationStrategies.push(queryResult);
        } else {
          logApp.info(`[AUTH PROVIDER CONVERSION] skipping ${currentAuthProvider.strategy} - ${identifier} as it's already in database.`);
        }
      } catch (error) {
        logApp.error(`[AUTH PROVIDER CONVERSION] Error when trying to convert ${currentAuthProvider.identifier}`, { cause: error });
      }
    }
    return authenticationStrategies;
  }
};
