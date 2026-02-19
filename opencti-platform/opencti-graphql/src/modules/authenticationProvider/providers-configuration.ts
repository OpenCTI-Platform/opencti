import conf, { booleanConf, logApp } from '../../config/conf';
import { loginFromProvider } from '../../domain/user';
import * as R from 'ramda';
import type { AuthenticationProviderType } from '../../generated/graphql';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { logAuthError, logAuthInfo } from './providers-logger';

export const LOCAL_STRATEGY_IDENTIFIER = 'local';
export const HEADERS_STRATEGY_IDENTIFIER = 'headers';
export const CERT_STRATEGY_IDENTIFIER = 'cert';

export const IS_AUTHENTICATION_FORCE_LOCAL = booleanConf('app:authentication:force_local', false);
const IS_AUTHENTICATION_FORCE_FROM_ENV = booleanConf('app:authentication:force_env', false);
export const isAuthenticationForcedFromEnv = () => {
  return IS_AUTHENTICATION_FORCE_FROM_ENV;
};

export const getProvidersFromEnvironment = () => {
  return conf.get('providers');
};

export enum AuthType {
  AUTH_SSO = 'SSO',
  AUTH_REQ = 'REQ',
  AUTH_FORM = 'FORM',
}

export enum EnvStrategyType {
  STRATEGY_LOCAL = 'LocalStrategy',
  STRATEGY_CERT = 'ClientCertStrategy',
  STRATEGY_HEADER = 'HeaderStrategy',
  STRATEGY_OPENID = 'OpenIDConnectStrategy',
  STRATEGY_SAML = 'SamlStrategy',
  STRATEGY_LDAP = 'LdapStrategy',
  STRATEGY_AUTH0 = 'Auth0Strategy',
  STRATEGY_FACEBOOK = 'FacebookStrategy',
  STRATEGY_GITHUB = 'GithubStrategy',
  STRATEGY_GOOGLE = 'GoogleStrategy',
}

export const MIGRATED_STRATEGY = [
  EnvStrategyType.STRATEGY_OPENID,
  EnvStrategyType.STRATEGY_SAML,
  EnvStrategyType.STRATEGY_LDAP,
];

export interface ProviderConfiguration {
  name: string;
  type: AuthType;
  strategy: EnvStrategyType | AuthenticationProviderType;
  // provider is also named 'identifier' or 'providerRef' in code.
  provider: string;
  reqLoginHandler?: (req: any, res?: any) => Promise<unknown>;
  logout_uri?: string;
  logout_remote?: boolean;
  internal_id?: string;
}
export const PROVIDERS: ProviderConfiguration[] = [];

export interface ProviderUserInfo {
  email?: string;
  name?: string;
  firstname?: string;
  lastname?: string;
  provider_metadata?: any;
}

export const providerLoginHandler = async (userInfo: ProviderUserInfo, done: (error: any, user?: any) => void, opts: any = {}) => {
  if (!userInfo.email) {
    logAuthError('Login has no resolved user email', opts.strategy ?? 'unknown', { userInfo, name: opts.name, identifier: opts.identifier });
    done(Error('No user email found, please verify provider configuration and server response'));
    return;
  }

  logAuthInfo('Login with resolved user info groups and organizations', opts.strategy ?? 'unknown', { userInfo, name: opts.name, identifier: opts.identifier });
  try {
    const user = await loginFromProvider(userInfo, opts);
    addUserLoginCount();
    logApp.info('[AUTH] providerLoginHandler user:', { userId: user.id });
    done(null, user);
  } catch (err) {
    logApp.info('[AUTH] providerLoginHandler error:', err as Error);
    done(err);
  }
};

export const genConfigMapper = (elements: string[]) => {
  return R.mergeAll(
    elements.map((r) => {
      const data = r.split(':');
      if (data.length !== 2) return {};
      const [remote, octi] = data;
      return { [remote]: octi };
    }),
  );
};

export const isStrategyActivated = (strategy: EnvStrategyType) => PROVIDERS.map((p) => p.strategy).includes(strategy);
export const isAuthenticationActivatedByIdentifier = (identifier: string) => PROVIDERS.some((p) => p.provider === identifier);

export const isProviderRegisteredByInternalId = (internalId: string) => PROVIDERS.some((p) => p.internal_id === internalId);

export const isAuthenticationProviderMigrated = (migratedIdentifiers: string[], authIdentifier: string) => {
  return migratedIdentifiers.some((strategyIdentifier) => strategyIdentifier === authIdentifier);
};

// Region Admin user initialization
const CONFIGURATION_ADMIN_EMAIL = conf.get('app:admin:email');
export const getConfigurationAdminEmail = () => {
  return CONFIGURATION_ADMIN_EMAIL;
};

const CONFIGURATION_ADMIN_PASSWORD = conf.get('app:admin:password');
export const getConfigurationAdminPassword = () => {
  return CONFIGURATION_ADMIN_PASSWORD;
};

const CONFIGURATION_ADMIN_TOKEN = conf.get('app:admin:token');
export const getConfigurationAdminToken = () => {
  return CONFIGURATION_ADMIN_TOKEN;
};

const CONFIGURATION_ADMIN_EXT = booleanConf('app:admin:externally_managed', false);
export const isAdminExternallyManaged = () => {
  return CONFIGURATION_ADMIN_EXT;
};
