import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';

const useFormikToSSOConfig = (selectedStrategy: string) => {
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
      {
        key: 'entryPoint',
        value: values.entryPoint,
        type: 'String',
      },
    ];
  };

  const formikToOpenIDConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'client_id',
        value: values.client_id,
        type: 'String',
      },
      {
        key: 'client_secret',
        value: values.client_secret,
        type: 'String',
      },
      {
        key: 'issuer',
        value: values.issuer,
        type: 'String',
      },
      {
        key: 'redirect_uris',
        value: JSON.stringify(values.redirect_uris),
        type: 'Array',
      },
    ];
  };

  const formikToLdapConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'url',
        value: values.url,
        type: 'String',
      },
      {
        key: 'bindDN',
        value: values.bindDN,
        type: 'String',
      },
      {
        key: 'searchBase',
        value: values.searchBase,
        type: 'String',
      },
      {
        key: 'searchFilter',
        value: values.searchFilter,
        type: 'String',
      },
      {
        key: 'groupSearchBase',
        value: values.groupSearchBase,
        type: 'String',
      },
      {
        key: 'groupSearchFilter',
        value: values.groupSearchFilter,
        type: 'String',
      },
      {
        key: 'allow_self_signed',
        value: values.allow_self_signed ? 'true' : 'false',
        type: 'Boolean',
      },
    ];
  };
  const getConfigFromStrategy = () => {
    switch (selectedStrategy) {
      case 'SAML': return formikToSamlConfig;
      case 'OpenID': return formikToOpenIDConfig;
      case 'LDAP': return formikToLdapConfig;
      default: return () => [];
    }
  };

  return getConfigFromStrategy();
};

export default useFormikToSSOConfig;
