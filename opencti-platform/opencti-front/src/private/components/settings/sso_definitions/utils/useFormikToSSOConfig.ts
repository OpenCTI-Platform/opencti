import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';

const useFormikToSSOConfig = () => {
  const formikToSamlConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'privateKey',
        value: values.privateKey,
        type: 'String',
      },
      {
        key: 'issuer',
        value: values.issuer,
        type: 'String',
      },
      {
        key: 'idpCert',
        value: values.idpCert,
        type: 'String',
      },
      {
        key: 'callbackUrl',
        value: values.callbackUrl,
        type: 'String',
      },
      {
        key: 'wantAssertionsSigned',
        value: values.wantAssertionsSigned ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'wantAuthnResponseSigned',
        value: values.wantAuthnResponseSigned ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'loginIdpDirectly',
        value: values.loginIdpDirectly ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'logoutRemote',
        value: values.logoutRemote ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'providerMethod',
        value: values.providerMethod,
        type: 'String',
      },
      {
        key: 'signingCert',
        value: values.signingCert,
        type: 'String',
      },
      {
        key: 'ssoBindingType',
        value: values.ssoBindingType,
        type: 'String',
      },
      {
        key: 'forceReauthentication',
        value: values.forceReauthentication ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'enableDebugMode',
        value: values.enableDebugMode ? 'true' : 'false',
        type: 'Boolean',
      },
    ];
  };
  return { formikToSamlConfig };
};

export default useFormikToSSOConfig;
