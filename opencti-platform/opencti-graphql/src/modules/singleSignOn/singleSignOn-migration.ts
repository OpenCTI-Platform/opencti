import { StrategyType, type SingleSignOnMigrationResult, type SingleSignOnAddInput, type ConfigurationTypeInput } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { now } from 'moment';
import { EnvStrategyType } from '../../config/providers-configuration';
import { nowTime } from '../../utils/format';
import { addSingleSignOn } from './singleSignOn-domain';
import type { AuthContext, AuthUser } from '../../types/user';
import { v4 as uuid } from 'uuid';

const computeConfiguration = (envConfiguration: any) => {
  const configuration: ConfigurationTypeInput[] = [];
  if (envConfiguration.config) {
    for (const configKey in envConfiguration.config) {
      const currentValue = envConfiguration.config[configKey];
      if (typeof currentValue === 'number') {
        const currentConfig: ConfigurationTypeInput = {
          key: configKey,
          type: 'number',
          value: `${envConfiguration.config[configKey]}`,
        };
        configuration.push(currentConfig);
      } else {
        const currentConfig: ConfigurationTypeInput = {
          key: configKey,
          type: 'string',
          value: `${envConfiguration.config[configKey]}`,
        };
        configuration.push(currentConfig);
      }
    }
  }
  return configuration;
};

const computeEnabled = (envConfiguration: any) => {
  return !(envConfiguration?.disabled === true);
};

const computeAuthenticationName = (ssoKey: string, envConfiguration: any) => {
  const providerName = envConfiguration?.config?.label || ssoKey;
  return `${providerName}-${nowTime()}`;
};

const parseLDAPStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.LdapStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.LdapStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseSAMLStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.SamlStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.SamlStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseOpenIdStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseLocalStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.LocalStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.LocalStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
  };
  return authEntity;
};

const parseGoogleStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nGoogle configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseGithubStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nGithub configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseFacebookStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nFacebook configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseAuth0StrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.OpenIdConnectStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.OpenIdConnectStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}.\nAuth0 configuration is no longer supported, configuration has been migrated to OpenID.`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseHeaderStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.HeaderStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.HeaderStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
  };
  return authEntity;
};

const parseCertStrategyConfiguration = (ssoKey: string, envConfiguration: any, dryRun: boolean) => {
  const authEntity: SingleSignOnAddInput = {
    strategy: StrategyType.ClientCertStrategy,
    name: computeAuthenticationName(ssoKey, envConfiguration),
    description: `${StrategyType.ClientCertStrategy} Automatically ${dryRun ? 'detected' : 'created'} from ${ssoKey} at ${now()}`,
    enabled: computeEnabled(envConfiguration),
    configuration: computeConfiguration(envConfiguration),
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
        strategy: authenticationStrategiesInput[i].strategy,
        description: authenticationStrategiesInput[i].description,
        id: uuid(),
        configuration: authenticationStrategiesInput[i].configuration,
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
