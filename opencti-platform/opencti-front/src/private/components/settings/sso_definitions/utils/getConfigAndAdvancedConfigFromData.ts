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
  'redirect_uri',
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

const headerConfigKeys = [
  'email',
  'firstname',
  'lastname',
  'logout_uri',
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
    case 'Header':
    case 'HeaderStrategy': return headerConfigKeys;
    default: return [];
  }
};

export const getBaseAndAdvancedConfigFromData = (config: ConfigTypeArray, strategy: string): { baseConfig: ConfigurationTypeInput[]; advancedConfig: ConfigurationTypeInput[] } => {
  const configKeys = getSSOConfigList(strategy);
  return {
    baseConfig: config.filter((item) => configKeys.includes(item.key)),
    advancedConfig: config.filter((item) => !configKeys.includes(item.key)),
  };
};
