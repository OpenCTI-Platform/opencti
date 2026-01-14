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

type configType = ReadonlyArray<{
  key: string;
  value: string;
  type: string;
}>;

export const getAdvancedConfigFromData = (config: configType): ConfigurationTypeInput[] => {
  return config.filter((item) => !samlConfigKeys.includes(item.key));
};

export const getConfigFromData = (config: configType): ConfigurationTypeInput[] => {
  return config.filter((item) => samlConfigKeys.includes(item.key));
};
