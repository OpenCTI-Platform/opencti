// Providers definition
import type { StrategyType } from '../generated/graphql';
import type { BasicStoreSettings } from '../types/settings';

export const INTERNAL_SECURITY_PROVIDER = '__internal_security_local_provider__';
export const LOCAL_STRATEGY_IDENTIFIER = 'local';

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

export interface ProviderConfiguration {
  name: string;
  type: AuthType;
  strategy: EnvStrategyType;
  // provider is also named 'identifier' or 'providerRef' in code.
  provider: string;
  reqLoginHandler?: () => void;
  logout_uri?: string;
}

export const PROVIDERS: ProviderConfiguration[] = [];

export const isStrategyActivated = (strategy: EnvStrategyType) => PROVIDERS.map((p) => p.strategy).includes(strategy);
export const isAuthenticationActivatedByIdentifier = (identifier: string) => PROVIDERS.some((p) => p.provider === identifier);

export const isAuthenticationProviderMigrated = (settings: BasicStoreSettings, authIdentifier: string) => {
  if (!settings || !settings?.auth_strategy_migrated) {
    return false;
  }
  return settings.auth_strategy_migrated.some((strategyIdentifier) => strategyIdentifier === authIdentifier);
};
