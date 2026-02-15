import {
  type AuthenticationProviderMigrationResult,
  AuthenticationProviderType,
  type ConfigurationTypeInput,
  type GroupsManagementInput,
  type LdapConfiguration,
  type OidcConfiguration,
  type OrganizationsManagementInput,
  type SamlConfiguration,
  StrategyType,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { now } from 'moment';
import { nowTime } from '../../utils/format';
import { findAllAuthenticationProvider, getAllIdentifiers, SECRET_TYPE, secretFieldsByType } from './authenticationProvider-domain';
import type { AuthContext, AuthUser } from '../../types/user';
import { EnvStrategyType, isAuthenticationProviderMigrated } from './providers-configuration';
import { configRemapping } from './providers-initialization';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { AuthRequired } from '../../config/errors';
import { patchAttribute } from '../../database/middleware';
import { getSettings } from '../../domain/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings, CertAuthConfig, HeadersAuthConfig, LocalAuthConfig } from '../../types/settings';
import { elDeleteElements } from '../../database/engine';

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

const computeConfiguration = (envConfiguration: any, strategy: StrategyType) => {
  const configuration: ConfigurationTypeInput[] = [];
  let groups_management: GroupsManagementInput | undefined;
  let organizations_management: OrganizationsManagementInput | undefined;
  const skipped_configuration: string[] = [];

  if (envConfiguration.config) {
    // TODO we will need to move this function inside current file
    const mappedConfig = strategy === StrategyType.OpenIdConnectStrategy ? envConfiguration.config : configRemapping(envConfiguration.config);
    for (const configKey in mappedConfig) {
      logApp.debug(`[SSO CONVERSION] current config key:${configKey}`);

      if (DEPRECATED_KEYS.some((deprecatedKey) => deprecatedKey === configKey)) {
        // 1. Check if it's a deprecated key that should be ignored
        skipped_configuration.push(configKey);
        logApp.warn(`[SSO CONVERSION] ${configKey} is deprecated, ignored during conversion`);
      } else if (NO_CONFIGURATION_KEY.some((noConfigKey) => noConfigKey === configKey)) {
        logApp.info(`[SSO CONVERSION] config key removed:${configKey}`);
      } else if (configKey === GROUP_MANAGEMENT_KEY) {
        // 2. Extract group management
        const currentValue = mappedConfig[configKey];
        logApp.info('[SSO CONVERSION] groups management configured', currentValue);

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
        if (strategy === StrategyType.OpenIdConnectStrategy && groups_scope) {
          groups_management['groups_scope'] = groups_scope;
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
        // HEADER only
        if (groups_splitter) {
          groups_management['groups_splitter'] = groups_splitter;
        } else if (strategy === StrategyType.HeaderStrategy) {
          groups_management['groups_splitter'] = ',';
        }
        // HEADER only
        if (groups_header) {
          groups_management['groups_header'] = groups_header;
        } else if (strategy === StrategyType.HeaderStrategy) {
          groups_management['groups_header'] = '';
        }
      } else if (configKey === ORG_MANAGEMENT_KEY) {
        // 3. Extract organization management
        const currentValue = mappedConfig[configKey];
        logApp.info('[SSO CONVERSION] organizations management configured', currentValue);

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
        } else if ([StrategyType.SamlStrategy, StrategyType.OpenIdConnectStrategy, StrategyType.LdapStrategy].includes(strategy)) {
          organizations_management['organizations_path'] = ['organizations'];
        }
        // OpenId only
        if (strategy === StrategyType.OpenIdConnectStrategy && organizations_scope) {
          organizations_management['organizations_scope'] = organizations_scope;
        }
        // OpenId only
        if (read_userinfo) {
          organizations_management['read_userinfo'] = read_userinfo;
        } else if (strategy === StrategyType.OpenIdConnectStrategy) {
          organizations_management['read_userinfo'] = false;
        }
        // OpenId only
        if (token_reference) {
          organizations_management['token_reference'] = token_reference;
        } else if (strategy === StrategyType.OpenIdConnectStrategy) {
          organizations_management['token_reference'] = 'access_token';
        }
        // HEADER only
        if (organizations_splitter) {
          organizations_management['organizations_splitter'] = organizations_splitter;
        } else if (strategy === StrategyType.HeaderStrategy) {
          organizations_management['organizations_splitter'] = ',';
        }
        // HEADER only
        if (organizations_header) {
          organizations_management['organizations_header'] = organizations_header;
        } else if (strategy === StrategyType.HeaderStrategy) {
          organizations_management['organizations_header'] = '';
        }

        organizations_management['organizations_mapping'] = organizations_mapping ?? [];
      } else if (configKey === CREDENTIALS_PROVIDER_KEY) {
        skipped_configuration.push(configKey);
        logApp.warn(`[SSO CONVERSION] ${configKey} is not supported yet, ignored during conversion`);
      } else if (configKey === 'redirect_uris' && strategy === StrategyType.OpenIdConnectStrategy) {
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
            type: Object.values(secretFieldsByType).flat().includes(configKey) ? SECRET_TYPE : 'string',
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
  const { configuration /* , groups_management, organizations_management */ } = computeConfiguration(envConfiguration, StrategyType.SamlStrategy);
  const identifier = envConfiguration?.identifier || 'saml';

  const authEntity: AuthenticationProviderMigrationResult = {
    // strategy: StrategyType.SamlStrategy,
    type: AuthenticationProviderType.Saml,
    identifier_override: identifier,
    name: computeAuthenticationName(ssoKey, envConfiguration, identifier),
    button_label_override: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.SamlStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: configuration as unknown as SamlConfiguration,
    // groups_management,
    // organizations_management,
  };
  return authEntity;
};

const parseOpenIdStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration /* , groups_management, organizations_management */ } = computeConfiguration(envConfiguration, StrategyType.OpenIdConnectStrategy);
  const identifier = envConfiguration?.identifier || 'oic';

  const authEntity: AuthenticationProviderMigrationResult = {
    type: AuthenticationProviderType.Oidc,
    identifier_override: identifier,
    // strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration, identifier),
    button_label_override: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: configuration as unknown as OidcConfiguration,
    // groups_management,
    // organizations_management,
  };
  return authEntity;
};

const parseLDAPStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const { configuration /* , groups_management, organizations_management */ } = computeConfiguration(envConfiguration, StrategyType.LdapStrategy);
  const identifier = envConfiguration?.identifier || 'ldapauth';

  const authEntity: AuthenticationProviderMigrationResult = {
    type: AuthenticationProviderType.Ldap,
    identifier_override: identifier,
    // strategy: StrategyType.LdapStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration, identifier),
    button_label_override: computeAuthenticationLabel(ssoKey, envConfiguration),
    description: `${StrategyType.LdapStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: configuration as unknown as LdapConfiguration,
    // groups_management,
    // organizations_management,
  };
  return authEntity;
};

const parseHEADERStrategyConfiguration = async (context: AuthContext, user: AuthUser, ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const settings = await getSettings(context) as unknown as BasicStoreSettings;
  const config: HeadersAuthConfig = {
    enabled: computeEnabled(envConfiguration),
    header_email: envConfiguration?.config?.header_email,
    header_name: envConfiguration?.config?.header_name,
    header_firstname: envConfiguration?.config?.header_firstname,
    header_lastname: envConfiguration?.config?.header_lastname,
    auto_create_group: envConfiguration?.config?.auto_create_group ?? false,
    headers_audit: envConfiguration?.config?.headers_audit ?? [],
    logout_uri: envConfiguration?.config?.logout_uri,
    // Groups management
    groups_header: envConfiguration?.config?.groups_management?.groups_header,
    groups_splitter: envConfiguration?.config?.groups_management?.groups_splitter,
    groups_mapping: envConfiguration?.config?.groups_management?.groups_mapping ?? [],
    // Organizations management
    organizations_default: envConfiguration?.config?.organizations_default ?? [],
    organizations_header: envConfiguration?.config?.organizations_management?.organizations_header,
    organizations_splitter: envConfiguration?.config?.organizations_management?.organizations_splitter,
    organizations_mapping: envConfiguration?.config?.organizations_management?.organizations_mapping ?? [],
  };
  const data = { headers_auth: config };
  if (!dryRun && !settings.headers_auth) { // Migrate only if not already done
    await patchAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, data);
  }
  return data;
};

const parseCERTStrategyConfiguration = async (context: AuthContext, user: AuthUser, ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const settings = await getSettings(context) as unknown as BasicStoreSettings;
  const config: CertAuthConfig = { enabled: computeEnabled(envConfiguration), button_label: computeAuthenticationLabel(ssoKey, envConfiguration) };
  const data = { cert_auth: config };
  if (!dryRun && !settings.cert_auth) { // Migrate only if not already done
    await patchAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, data);
  }
  return data;
};

const parseLocalStrategyConfiguration = async (context: AuthContext, user: AuthUser, envConfiguration: any, dryRun: boolean) => {
  const settings = await getSettings(context) as unknown as BasicStoreSettings;
  const config: LocalAuthConfig = { enabled: computeEnabled(envConfiguration) };
  const data = { local_auth: config };
  if (!dryRun && !settings.local_auth) { // Migrate only if not already done
    await patchAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, data);
  }
  return data;
};

export const parseAuthenticationProviderConfiguration = async (context: AuthContext, user: AuthUser, envConfiguration: any, dryRun: boolean) => {
  const authenticationStrategiesInput: AuthenticationProviderMigrationResult[] = [];
  for (const ssoKey in envConfiguration) {
    const currentSSOconfig = envConfiguration[ssoKey];
    logApp.info(`[SSO CONVERSION] reading ${ssoKey}`);
    if (currentSSOconfig.strategy) {
      switch (currentSSOconfig.strategy) {
        case EnvStrategyType.STRATEGY_LOCAL:
          logApp.info('[SSO CONVERSION] Looking at LocalStrategy conversion');
          await parseLocalStrategyConfiguration(context, user, currentSSOconfig, dryRun);
          break;
        case EnvStrategyType.STRATEGY_OPENID:
          logApp.info('[SSO CONVERSION] Looking at OpenID conversion');
          authenticationStrategiesInput.push(parseOpenIdStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_SAML:
          logApp.info('[SSO CONVERSION] Looking at SAML conversion');
          authenticationStrategiesInput.push(parseSAMLStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_LDAP:
          logApp.info('[SSO CONVERSION] Looking at LDAP conversion');
          authenticationStrategiesInput.push(parseLDAPStrategyConfiguration(ssoKey, currentSSOconfig, dryRun));
          break;
        case EnvStrategyType.STRATEGY_CERT:
          logApp.info('[SSO MIGRATION] Looking at CERT migration');
          await parseCERTStrategyConfiguration(context, user, ssoKey, currentSSOconfig, dryRun);
          break;
        case EnvStrategyType.STRATEGY_HEADER:
          logApp.info('[SSO MIGRATION] Looking at HEADER migration');
          await parseHEADERStrategyConfiguration(context, user, ssoKey, currentSSOconfig, dryRun);
          break;
        case EnvStrategyType.STRATEGY_FACEBOOK:
          logApp.warn(`[SSO CONVERSION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
          break;
        case EnvStrategyType.STRATEGY_AUTH0:
          logApp.warn(`[SSO CONVERSION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
          break;
        case EnvStrategyType.STRATEGY_GITHUB:
          logApp.warn(`[SSO CONVERSION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
          break;
        case EnvStrategyType.STRATEGY_GOOGLE:
          logApp.warn(`[SSO CONVERSION] DEPRECATED ${currentSSOconfig.strategy} detected.`);
          break;

        default:
          logApp.error('[SSO CONVERSION] unknown strategy in configuration', {
            providerKey: ssoKey,
            strategy: currentSSOconfig.strategy,
          });
          break;
      }
    }
  }
  // checking capa before doing all database changes
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) throw AuthRequired('SETTINGS_SET_ACCESSES is required');
  if (dryRun) {
    // When dryRun: convert authenticationStrategiesInput into display object
    const authenticationStrategies: AuthenticationProviderMigrationResult[] = [];
    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      // const queryResult: AuthenticationProviderMigrationResult = {
      //   enabled: authenticationStrategiesInput[i].enabled,
      //   name: authenticationStrategiesInput[i].name,
      //   label: authenticationStrategiesInput[i].label,
      //   strategy: authenticationStrategiesInput[i].strategy,
      //   description: authenticationStrategiesInput[i].description,
      //   id: uuid(),
      //   configuration: authenticationStrategiesInput[i].configuration,
      //   groups_management: authenticationStrategiesInput[i].groups_management as GroupsManagement,
      //   organizations_management: authenticationStrategiesInput[i].organizations_management as OrganizationsManagement,
      //   identifier: authenticationStrategiesInput[i].identifier,
      // };
      // authenticationStrategies.push(queryResult);
    }
    return authenticationStrategies;
  } else {
    // When no dry run: save in database, and then convert BasicStore into display object
    logApp.info('[SSO CONVERSION] starting to write migrated SSO in database');
    const authenticationStrategies: AuthenticationProviderMigrationResult[] = [];
    // Remove singleton strategies already migrated
    const ssoAuthentications = await findAllAuthenticationProvider(context, user);
    const singletons = [AuthenticationProviderType.Ldap, AuthenticationProviderType.Oidc, AuthenticationProviderType.Saml];
    const elements = ssoAuthentications.filter((auth) => !singletons.includes(auth.type));
    await elDeleteElements(context, user, elements, { forceDelete: true, forceRefresh: true });
    // Handle migration
    const identifiersInDb = await getAllIdentifiers(context, user);
    for (let i = 0; i < authenticationStrategiesInput.length; i++) {
      const currentAuthProvider = authenticationStrategiesInput[i];
      try {
        const identifier = currentAuthProvider.identifier_override;
        if (identifier && !isAuthenticationProviderMigrated(identifiersInDb, identifier)) {
          logApp.info(`[SSO CONVERSION] creating new configuration for ${identifier}`);
          // const created = await internalAddSingleSignOn(context, user, currentAuthProvider, true);
          // const queryResult: SingleSignOnMigrationResult = {
          //   enabled: created.enabled,
          //   name: created.name,
          //   label: created.label,
          //   strategy: created.strategy,
          //   description: created.description,
          //   id: created.id,
          //   configuration: created.configuration,
          //   identifier: created.identifier,
          // };
          // authenticationStrategies.push(queryResult);
        } else {
          logApp.info(`[SSO CONVERSION] skipping ${currentAuthProvider.type} - ${identifier} as it's already in database.`);
        }
      } catch (error) {
        logApp.error(`[SSO CONVERSION] Error when trying to convert ${currentAuthProvider.identifier_override}`, { cause: error });
      }
    }
    return authenticationStrategies;
  }
};
