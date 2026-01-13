import {
  ConfigurationTypeInput
} from '@components/settings/sso_definitions/__generated__/SSODefinitionCreationMutation.graphql';

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

export const getAdvancedConfigFromData = (config: ConfigurationTypeInput[]) => {
  return config.filter((item) => !samlConfigKeys.includes(item.key))
}

export const getConfigFromData = (config: ConfigurationTypeInput[]) => {
  return config.filter((item) => samlConfigKeys.includes(item.key))
}