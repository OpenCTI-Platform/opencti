import {
  type ConfigurationTypeInput,
  type GroupsManagement,
  type GroupsManagementInput,
  type SingleSignOnAddInput,
  type SingleSignOnMigrationResult,
  StrategyType,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { now } from 'moment';
import { nowTime } from '../../utils/format';
import { addSingleSignOn } from './singleSignOn-domain';
import type { AuthContext, AuthUser } from '../../types/user';
import { v4 as uuid } from 'uuid';
import { EnvStrategyType } from '../../config/providers-configuration';
import { configRemapping } from '../../config/providers-initialization';

// Key that should not be present after migration
const DEPRECATED_KEYS = ['roles_management'];

// Key that have dedicated usage in OpenCTI and must not be in the configuration array
const NO_CONFIGURATION_KEY = ['label'];

const GROUP_MANAGEMENT_KEY = 'groups_management';
const ORG_MANAGEMENT_KEY = 'organizations_management';

interface ConfigurationType {
  configuration: ConfigurationTypeInput[];
  groups_management?: GroupsManagementInput;
  skipped_configuration: string[];
}

const computeConfiguration = (envConfiguration: any, strategy: StrategyType) => {
  const configuration: ConfigurationTypeInput[] = [];
  let groups_management: GroupsManagementInput | undefined;
  const skipped_configuration: string[] = [];

  if (envConfiguration.config) {
    // TODO we will need to move this function inside current file
    const mappedConfig = configRemapping(envConfiguration.config);

    for (const configKey in mappedConfig) {
      logApp.info(`[SSO MIGRATION] current config key:${configKey}`);

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

        const { group_attributes, groups_mapping, groups_path, read_userinfo } = currentValue;
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
      } else if (configKey === ORG_MANAGEMENT_KEY) {
      // 3. Extract organization management
        // TODO
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
    configuration, groups_management, skipped_configuration,
  };
  return result;
};

const computeEnabled = (envConfiguration: any) => {
  return !(envConfiguration?.disabled === true);
};

const computeAuthenticationName = (ssoKey: string, envConfiguration: any) => {
  const providerName = envConfiguration?.config?.label || ssoKey;
  return `${providerName}-${nowTime()}`;
};

const computeAuthenticationLabel = (ssoKey: string, envConfiguration: any) => {
  const providerName = envConfiguration?.config?.label || ssoKey;
  return `${providerName}`;
};

const parseLDAPStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.LdapStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.LdapStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseSAMLStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration, groups_management } = computeConfiguration(envConfiguration, StrategyType.SamlStrategy);
  const identifier = envConfiguration?.identifier || 'saml';

  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.SamlStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    identifier,
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.SamlStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration,
    groups_management,
  };
  return authEntity;
};

const parseOpenIdStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseLocalStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.LocalStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.LocalStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseGoogleStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nGoogle configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseGithubStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nGithub configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseFacebookStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nFacebook configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseAuth0StrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nAuth0 configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseHeaderStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.HeaderStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.HeaderStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseCertStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.ClientCertStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    label: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.ClientCertStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

export const parseSingleSignOnRunConfiguration = async (context: AuthContext, user: AuthUser, envConfiguration: any, dryRun: boolean) => {
  const authenticationStrategiesInput: SingleSignOnAddInput[] = [];
  for (const ssoKey in envConfiguration) {
    const currentSSOconfig = envConfiguration[ssoKey];
    logApp.info(`[SSO MIGRATION] reading ${ssoKey}`, currentSSOconfig);
    if (currentSSOconfig.strategy) {
      switch (currentSSOconfig.strategy) {
        case EnvStrategyType.STRATEGY_LOCAL:
          authenticationStrategiesInput.push(parseLocalStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_OPENID:
          authenticationStrategiesInput.push(parseOpenIdStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_SAML:
          authenticationStrategiesInput.push(parseSAMLStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_LDAP:
          authenticationStrategiesInput.push(parseLDAPStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_FACEBOOK:
          authenticationStrategiesInput.push(parseFacebookStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_AUTH0:
          authenticationStrategiesInput.push(parseAuth0StrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_GITHUB:
          authenticationStrategiesInput.push(parseGithubStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_GOOGLE:
          authenticationStrategiesInput.push(parseGoogleStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_CERT:
          authenticationStrategiesInput.push(parseCertStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_HEADER:
          authenticationStrategiesInput.push(parseHeaderStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;

        default:
          logApp.error('[SSO MIGRATION] unknown strategy in configuration', { providerKey: ssoKey, strategy: currentSSOconfig.strategy });
          break;
      }
    } else {
      logApp.error('[SSO MIGRATION] strategy not defined in configuration', { providerKey: ssoKey });
    }
  }

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
      };
      authenticationStrategies.push(queryResult);
    }
    return authenticationStrategies;
  } else {
    // When no dry run: save in database, and then convert BasicStore into display object
    const authenticationStrategies: SingleSignOnMigrationResult[] = [];
    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      const created = await addSingleSignOn(context, user, authenticationStrategiesInput[i]);
      const queryResult: SingleSignOnMigrationResult = {
        enabled: created.enabled,
        name: created.name,
        label: created.label,
        strategy: created.strategy,
        description: created.description,
        id: created.id,
        configuration: created.configuration,
      };
      authenticationStrategies.push(queryResult);
    }
    return authenticationStrategies;
  }
};
