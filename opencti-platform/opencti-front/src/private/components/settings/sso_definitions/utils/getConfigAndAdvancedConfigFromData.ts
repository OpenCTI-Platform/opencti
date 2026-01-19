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
  'issuer'
];

type configType = ReadonlyArray<{
  key: string;
  value: string;
  type: string;
}>;


export const getSSOConfigList = (strategy: string) => {
  switch (strategy) {
    case 'SAML':
    case 'SamlStrategy': return samlConfigKeys;
    case 'OpenID':
    case 'OpenIDConnectStrategy': return openIDConfigKeys;
    default: return [];
  }
}

export const getAdvancedConfigFromData = (config: configType, strategy: string): ConfigurationTypeInput[] => {
  const configKeys = getSSOConfigList(strategy);
  return config.filter((item) => !configKeys.includes(item.key));
};

export const getConfigFromData = (config: configType, strategy: string): ConfigurationTypeInput[] => {
  const configKeys = getSSOConfigList(strategy);
  return config.filter((item) => configKeys.includes(item.key));
};
