import { StrategyType } from '../../generated/graphql';
import LocalStrategy from 'passport-local';
import { login } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { decryptAuthValue, logAuthError, logAuthInfo, SECRET_TYPE } from './singleSignOn-domain';
import {
  AuthType,
  EnvStrategyType,
  getConfigurationAdminEmail,
  INTERNAL_SECURITY_PROVIDER,
  isAuthenticationActivatedByIdentifier,
  LOCAL_STRATEGY_IDENTIFIER,
  type ProviderConfiguration,
  PROVIDERS,
} from './providers-configuration';
import type { BasicStoreEntitySingleSignOn, ConfigurationType } from './singleSignOn-types';
import { AuthenticationFailure, ConfigurationError } from '../../config/errors';
import { isNotEmptyField } from '../../database/utils';
import { registerAuthenticationProvider, unregisterAuthenticationProvider } from './providers-initialization';
import { registerSAMLStrategy } from './singleSignOn-provider-saml';
import { registerLDAPStrategy } from './singleSignOn-provider-ldap';
import { GraphQLError } from 'graphql/index';
import { registerOpenIdStrategy } from './singleSignOn-provider-openid';
import { registerHeadertrategy } from './singleSignOn-provider-header';

export const parseValueAsType = async (config: ConfigurationType): Promise<string | number | any[] | boolean> => {
  if (isNotEmptyField(config.value) && isNotEmptyField(config.key) && isNotEmptyField(config.type)) {
    if (config.type.toLowerCase() === 'number') {
      return +config.value;
    } else if (config.type.toLowerCase() === 'boolean') {
      return config.value === 'true';
    } else if (config.type.toLowerCase() === 'array') {
      return JSON.parse(config.value);
    } else if (config.type.toLowerCase() === 'string') {
      return config.value;
    } else if (config.type.toLowerCase() === SECRET_TYPE) {
      const decryptedBuffer = await decryptAuthValue(config.value);
      return decryptedBuffer.toString();
    } else {
      throw ConfigurationError('Authentication configuration cannot be parsed, unknown type.', { key: config.key, type: config.type });
    }
  } else {
    throw ConfigurationError('Authentication configuration cannot be parsed, key, type or value is empty.', { key: config.key, type: config.type });
  }
};

export const convertKeyValueToJsConfiguration = async (ssoEntity: BasicStoreEntitySingleSignOn): Promise<any> => {
  if (ssoEntity.configuration) {
    const ssoConfiguration: any = {};
    for (let i = 0; i < ssoEntity.configuration.length; i++) {
      const currentConfig = ssoEntity.configuration[i];
      if (isNotEmptyField(currentConfig.value)) {
        try {
          ssoConfiguration[currentConfig.key] = await parseValueAsType(currentConfig);
        } catch (e) {
          logAuthError(`Configuration ${currentConfig?.key} cannot be read, is ignored. Please verify your configuration.`, ssoEntity.strategy, { cause: e });
        }
      }
    }
    return ssoConfiguration;
  } else {
    if (ssoEntity.strategy !== StrategyType.LocalStrategy) {
      throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
    }
  }
};

export const registerAdminLocalStrategy = async () => {
  logAuthInfo('Configuring internal local', EnvStrategyType.STRATEGY_LOCAL);
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  const adminLocalStrategy = new LocalStrategy({}, (username: string, password: string, done: any) => {
    if (username !== getConfigurationAdminEmail()) {
      return done(AuthenticationFailure());
    }
    return login(username, password)
      .then((info) => {
        addUserLoginCount();
        return done(null, info);
      })
      .catch((err) => {
        done(err);
      });
  });

  // Only one local, remove existing.
  const providerConfig: ProviderConfiguration
    = { name: INTERNAL_SECURITY_PROVIDER, type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LOCAL, provider: LOCAL_STRATEGY_IDENTIFIER };
  if (isAuthenticationActivatedByIdentifier('local')) {
    unregisterAuthenticationProvider('local');
  }
  registerAuthenticationProvider(INTERNAL_SECURITY_PROVIDER, adminLocalStrategy, providerConfig);
};

export const registerLocalStrategy = async () => {
  logAuthInfo('Configuring local', EnvStrategyType.STRATEGY_LOCAL);
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  const localStrategy = new LocalStrategy({}, (username: string, password: string, done: any) => {
    return login(username, password)
      .then((info) => {
        logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_LOCAL, { username });
        addUserLoginCount();
        return done(null, info);
      })
      .catch((err) => {
        done(err);
      });
  });

  // Only one local, remove existing.
  const providerConfig: ProviderConfiguration = {
    name: LOCAL_STRATEGY_IDENTIFIER,
    type: AuthType.AUTH_FORM,
    strategy: EnvStrategyType.STRATEGY_LOCAL,
    provider: LOCAL_STRATEGY_IDENTIFIER,
  };
  if (isAuthenticationActivatedByIdentifier(LOCAL_STRATEGY_IDENTIFIER)) {
    unregisterAuthenticationProvider(LOCAL_STRATEGY_IDENTIFIER);
  }
  registerAuthenticationProvider(LOCAL_STRATEGY_IDENTIFIER, localStrategy, providerConfig);
};

const registerCertStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = 'cert';

  logAuthInfo('Configuring Cert', EnvStrategyType.STRATEGY_CERT, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
  PROVIDERS.push({ name: providerRef, type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_CERT, provider: providerRef });
  logAuthInfo('Cert configured', EnvStrategyType.STRATEGY_CERT, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
};

export const refreshStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  await unregisterStrategy(authenticationStrategy);

  if (authenticationStrategy.enabled) {
    await registerStrategy(authenticationStrategy);
  }
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  if (authenticationStrategy.strategy === StrategyType.LocalStrategy) {
    if (authenticationStrategy.identifier === LOCAL_STRATEGY_IDENTIFIER) {
      unregisterAuthenticationProvider(LOCAL_STRATEGY_IDENTIFIER);
      await registerAdminLocalStrategy();
    } else if (authenticationStrategy.identifier === INTERNAL_SECURITY_PROVIDER) {
      unregisterAuthenticationProvider(INTERNAL_SECURITY_PROVIDER);
      await registerLocalStrategy();
    }
  } else {
    unregisterAuthenticationProvider(authenticationStrategy.identifier);
  }
};

export const registerStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  try {
    if (authenticationStrategy.strategy && authenticationStrategy.identifier) {
      const configuration = authenticationStrategy.configuration;
      if (configuration) {
        for (let i = 0; i < configuration.length; i++) {
          const currentConfig = configuration[i];
          if (currentConfig.type === SECRET_TYPE) {
            try {
              const decryptedBuffer = await decryptAuthValue(currentConfig.value);
              currentConfig.value = decryptedBuffer.toString();
              currentConfig.type = 'string';
            } catch (e) {
              logAuthError(`Configuration ${currentConfig?.key} cannot be read, is ignored. Please verify your configuration.`, EnvStrategyType.STRATEGY_SAML, { cause: e });
            }
          }
        }
      }

      if (authenticationStrategy.strategy === StrategyType.LocalStrategy) {
        logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_LOCAL);
        if (authenticationStrategy.enabled) {
          await registerLocalStrategy();
        } else {
          await registerAdminLocalStrategy();
        }
      } else {
        if (authenticationStrategy.enabled) {
          switch (authenticationStrategy.strategy) {
            case StrategyType.SamlStrategy:
              logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_SAML);
              if (authenticationStrategy.enabled) {
                await registerSAMLStrategy(authenticationStrategy);
              }
              break;
            case StrategyType.OpenIdConnectStrategy:
              logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_OPENID);
              if (authenticationStrategy.enabled) {
                await registerOpenIdStrategy(authenticationStrategy);
              }
              break;
            case StrategyType.LdapStrategy:
              logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_LDAP);
              if (authenticationStrategy.enabled) {
                await registerLDAPStrategy(authenticationStrategy);
              }
              break;
            case StrategyType.HeaderStrategy:
              logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_HEADER);
              await registerHeadertrategy(authenticationStrategy);
              break;
            case StrategyType.ClientCertStrategy:
              logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_CERT);
              await registerCertStrategy(authenticationStrategy);
              break;

            default:
              logAuthError('Unknown strategy should not be possible, skipping', undefined, {
                name: authenticationStrategy?.name,
                strategy: authenticationStrategy.strategy,
              });
              break;
          }
        }
      }
    } else {
      logAuthError('[SSO INIT] configuration without strategy or identifier should not be possible, skipping', undefined, { id: authenticationStrategy?.id, strategy: authenticationStrategy.strategy, identifier: authenticationStrategy.identifier });
    }
  } catch (e) {
    if (e instanceof GraphQLError) {
      logAuthError(
        `Error when initializing an authentication provider (id: ${authenticationStrategy?.id ?? 'no id'}, identifier: ${authenticationStrategy?.identifier ?? 'no identifier'}), cause: ${e.message}.`,
        undefined,
        { message: e.message, data: e.extensions.data },
      );
    } else {
      logAuthError(
        `Unknown error when initializing an authentication provider (id: ${authenticationStrategy?.id ?? 'no id'}, identifier: ${authenticationStrategy?.identifier ?? 'no identifier'})`,
        undefined,
        e,
      );
    }
  }
};
