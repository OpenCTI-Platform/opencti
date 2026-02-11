import { ConfigurationTypeInput } from '../__generated__/SSODefinitionCreationMutation.graphql';

const samlConfigKeys = [
  'privateKey',
  'issuer',
  'idpCert',
  'callbackUrl',
  'wantAssertionsSigned',
  'wantAuthnResponseSigned',
  'loginIdpDirectly',
  'logoutRemote',
  'providerMethod',
  'signingCert',
  'ssoBindingType',
  'forceReauthentication',
  'enableDebugMode',
  'entryPoint',
];

const openIDConfigKeys = [
  'client_id',
  'client_secret',
  'redirect_uris',
  'issuer',
];

const ldapConfigKeys = [
  'url',
  'bindDN',
  'bindCredentials',
  'searchBase',
  'searchFilter',
  'groupSearchBase',
  'groupSearchFilter',
  'allow_self_signed',
];

export type Config = {
  key: string;
  value: string;
  type: string;
};

export type ConfigTypeArray = ReadonlyArray<Config>;

export const getSSOConfigList = (strategy: string) => {
  switch (strategy) {
    case 'SAML':
    case 'SamlStrategy': return samlConfigKeys;
    case 'OpenID':
    case 'OpenIDConnectStrategy': return openIDConfigKeys;
    case 'LDAP':
    case 'LdapStrategy': return ldapConfigKeys;
    default: return [];
  }
};

export const getAdvancedConfigFromData = (config: ConfigTypeArray, strategy: string): ConfigurationTypeInput[] => {
  const configKeys = getSSOConfigList(strategy);

  return config
    .filter((item) => !configKeys.includes(item.key))
    .map((item) => (item.type === 'encrypted' ? { key: item.key, value: '******', type: 'secret' } : item));
};

export const getConfigFromData = (config: ConfigTypeArray, strategy: string): ConfigurationTypeInput[] => {
  const configKeys = getSSOConfigList(strategy);
  return config.filter((item) => configKeys.includes(item.key));
};
