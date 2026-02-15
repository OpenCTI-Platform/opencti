import conf, { booleanConf, logApp } from '../../config/conf';
import { loginFromProvider } from '../../domain/user';
import * as R from 'ramda';

export const LOCAL_STRATEGY_IDENTIFIER = 'local';
export const HEADER_STRATEGY_IDENTIFIER = 'headers';

const IS_AUTHENTICATION_FORCE_FROM_ENV = booleanConf('app:authentication:force_env', false);
export const isAuthenticationForcedFromEnv = () => {
  return IS_AUTHENTICATION_FORCE_FROM_ENV;
};

const IS_AUTHENTICATION_EDITION_LOCKED = booleanConf('app:authentication:edition_locked', false);
export const isAuthenticationEditionLocked = () => {
  return IS_AUTHENTICATION_EDITION_LOCKED;
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
  STRATEGY_LDAP = 'LdapStrategy',
  STRATEGY_OPENID = 'OpenIDConnectStrategy',
  STRATEGY_FACEBOOK = 'FacebookStrategy',
  STRATEGY_SAML = 'SamlStrategy',
  STRATEGY_GOOGLE = 'GoogleStrategy',
  STRATEGY_GITHUB = 'GithubStrategy',
  STRATEGY_AUTH0 = 'Auth0Strategy',
}

export const MIGRATED_STRATEGY = [
  EnvStrategyType.STRATEGY_LOCAL,
  EnvStrategyType.STRATEGY_SAML,
  EnvStrategyType.STRATEGY_OPENID,
  EnvStrategyType.STRATEGY_LDAP,
  EnvStrategyType.STRATEGY_CERT,
  EnvStrategyType.STRATEGY_HEADER,
];

export interface ProviderConfiguration {
  name: string;
  type: AuthType;
  strategy: EnvStrategyType;
  // provider is also named 'identifier' or 'providerRef' in code.
  provider: string;
  reqLoginHandler?: (req: any) => Promise<unknown>;
  logout_uri?: string;
  logout_remote?: boolean;
}
export const PROVIDERS: ProviderConfiguration[] = [];

export interface ProviderUserInfo {
  email: string;
  name: string;
  firstname?: string;
  lastname?: string;
  provider_metadata?: any;
}

export const providerLoginHandler = (userInfo: ProviderUserInfo, done: any, opts = {}) => {
  loginFromProvider(userInfo, opts)
    .then((user: any) => {
      logApp.info('[SSO] providerLoginHandler user', { userId: user.id });
      done(null, user);
    })
    .catch((err: any) => {
      logApp.info('[SSO] providerLoginHandler error', err);
      done(err);
    });
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
