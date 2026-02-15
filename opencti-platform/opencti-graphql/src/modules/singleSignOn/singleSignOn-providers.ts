import { StrategyType } from '../../generated/graphql';
import LocalStrategy from 'passport-local';
import { login } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { decryptAuthValue, logAuthError, logAuthInfo, SECRET_TYPE } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, LOCAL_STRATEGY_IDENTIFIER, type ProviderConfiguration } from './providers-configuration';
import type { BasicStoreEntitySingleSignOn, ConfigurationType } from './singleSignOn-types';
import { ConfigurationError } from '../../config/errors';
import { isNotEmptyField } from '../../database/utils';
import { unregisterAuthenticationProvider } from './providers-initialization';
import { registerSAMLStrategy } from './singleSignOn-provider-saml';
import { registerLDAPStrategy } from './singleSignOn-provider-ldap';
import { GraphQLError } from 'graphql/index';
import { registerOpenIdStrategy } from './singleSignOn-provider-openid';
import passport from 'passport';

export let LOCAL_PROVIDER: ProviderConfiguration | undefined = undefined;

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

export const registerLocalStrategy = async () => {
  logAuthInfo('Configuring local', EnvStrategyType.STRATEGY_LOCAL);
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  const localStrategy = new LocalStrategy({}, (username: string, password: string, done: any) => {
    return login(username, password).then((info) => {
      logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_LOCAL, { username });
      addUserLoginCount();
      // TODO JRI FIND A WAY FOR ROOT LOGIN
      return done(null, info);
    }).catch((err) => {
      done(err);
    });
  });
  const providerConfig: ProviderConfiguration = {
    name: LOCAL_STRATEGY_IDENTIFIER,
    type: AuthType.AUTH_FORM,
    strategy: EnvStrategyType.STRATEGY_LOCAL,
    provider: LOCAL_STRATEGY_IDENTIFIER,
  };
  passport.use(LOCAL_STRATEGY_IDENTIFIER, localStrategy);
  LOCAL_PROVIDER = providerConfig;
};

export const refreshStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  await unregisterStrategy(authenticationStrategy);
  if (authenticationStrategy.enabled) {
    await registerSSOStrategy(authenticationStrategy);
  }
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  unregisterAuthenticationProvider(authenticationStrategy.identifier);
};

export const registerSSOStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
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
          default:
            logAuthError('Unknown strategy should not be possible, skipping', undefined, {
              name: authenticationStrategy?.name,
              strategy: authenticationStrategy.strategy,
            });
            break;
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
