import { StrategyType } from '../../generated/graphql';
import conf, { logApp } from '../../config/conf';
import LocalStrategy from 'passport-local';
import { login } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { logAuthError, logAuthInfo } from './singleSignOn-domain';
import {
  AuthType,
  EnvStrategyType,
  INTERNAL_SECURITY_PROVIDER,
  isAuthenticationActivatedByIdentifier,
  LOCAL_STRATEGY_IDENTIFIER,
  type ProviderConfiguration,
} from './providers-configuration';
import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { AuthenticationFailure, ConfigurationError } from '../../config/errors';
import { isNotEmptyField } from '../../database/utils';
import { registerAuthenticationProvider, unregisterAuthenticationProvider } from './providers-initialization';
import { registerSAMLStrategy } from './singleSignOn-provider-saml';
import { registerLDAPStrategy } from './singleSignOn-provider-ldap';
import { GraphQLError } from 'graphql/index';
import { registerOpenIdStrategy } from './singleSignOn-provider-openid';

export const parseValueAsType = (value: string, type: string) => {
  if (type.toLowerCase() === 'number') {
    return +value;
  } else if (type.toLowerCase() === 'boolean') {
    return value === 'true';
  } else if (type.toLowerCase() === 'array') {
    return JSON.parse(value);
  } else {
    return value;
  }
};

export const convertKeyValueToJsConfiguration = (ssoEntity: BasicStoreEntitySingleSignOn) => {
  if (ssoEntity.configuration) {
    const ssoConfiguration: any = {};
    for (let i = 0; i < ssoEntity.configuration.length; i++) {
      const currentConfig = ssoEntity.configuration[i];
      if (isNotEmptyField(currentConfig.value)) {
        ssoConfiguration[currentConfig.key] = parseValueAsType(currentConfig.value, currentConfig.type);
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
    const adminEmail = conf.get('app:admin:email');
    if (username !== adminEmail) {
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
      switch (authenticationStrategy.strategy) {
        case StrategyType.LocalStrategy:
          logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_LOCAL);
          if (authenticationStrategy.enabled) {
            await registerLocalStrategy();
          } else {
            await registerAdminLocalStrategy();
          }
          break;
        case StrategyType.SamlStrategy:
          logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_SAML);
          await registerSAMLStrategy(authenticationStrategy);
          break;
        case StrategyType.OpenIdConnectStrategy:
          logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_OPENID);
          await registerOpenIdStrategy(authenticationStrategy);
          break;
        case StrategyType.LdapStrategy:
          logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_LDAP);
          await registerLDAPStrategy(authenticationStrategy);
          break;
        case StrategyType.HeaderStrategy:
        case StrategyType.ClientCertStrategy:
          logApp.warn(`[SSO] ${authenticationStrategy.strategy} not implemented in UI yet`);
          break;

        default:
          logAuthError('Unknown strategy should not be possible, skipping', undefined, {
            name: authenticationStrategy?.name,
            strategy: authenticationStrategy.strategy,
          });
          break;
      }
    } else {
      logAuthError('[SSO INIT] configuration without strategy or identifier should not be possible, skipping', undefined, { id: authenticationStrategy?.id, strategy: authenticationStrategy.strategy, identifier: authenticationStrategy.identifier });
    }
  } catch (e) {
    if (e instanceof GraphQLError) {
      logAuthError(
        `Error when initializing an authentication provider (id: ${authenticationStrategy?.id ?? 'no id'}, identifier: ${authenticationStrategy?.identifier ?? 'no identifier'}), cause: ${e.message}`,
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
