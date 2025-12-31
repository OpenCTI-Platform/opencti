// Providers definition
import type { StrategyType } from '../generated/graphql';

export const INTERNAL_SECURITY_PROVIDER = '__internal_security_local_provider__';

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
  strategy: EnvStrategyType | StrategyType;
  provider: string;
  reqLoginHandler?: () => void;
  logout_uri?: string;
}

export const PROVIDERS: ProviderConfiguration[] = [];

export const isStrategyActivated = (strategy: EnvStrategyType) => PROVIDERS.map((p) => p.strategy).includes(strategy);
