import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';

const useFormikToSSOConfig = (selectedStrategy: string) => {
  const formikToSamlConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'privateKey',
        value: values.privateKey,
        type: 'secret',
      },
      {
        key: 'issuer',
        value: values.issuer,
        type: 'string',
      },
      {
        key: 'idpCert',
        value: values.idpCert,
        type: 'string',
      },
      {
        key: 'callbackUrl',
        value: values.callbackUrl,
        type: 'string',
      },
      {
        key: 'wantAssertionsSigned',
        value: values.wantAssertionsSigned ? 'true' : 'false',
        type: 'boolean',
      },
      {
        key: 'wantAuthnResponseSigned',
        value: values.wantAuthnResponseSigned ? 'true' : 'false',
        type: 'boolean',
      },
      {
        key: 'loginIdpDirectly',
        value: values.loginIdpDirectly ? 'true' : 'false',
        type: 'boolean',
      },
      {
        key: 'logoutRemote',
        value: values.logoutRemote ? 'true' : 'false',
        type: 'boolean',
      },
      {
        key: 'providerMethod',
        value: values.providerMethod,
        type: 'string',
      },
      {
        key: 'signingCert',
        value: values.signingCert,
        type: 'string',
      },
      {
        key: 'ssoBindingType',
        value: values.ssoBindingType,
        type: 'string',
      },
      {
        key: 'forceReauthentication',
        value: values.forceReauthentication ? 'true' : 'false',
        type: 'boolean',
      },
      {
        key: 'enableDebugMode',
        value: values.enableDebugMode ? 'true' : 'false',
        type: 'boolean',
      },
      {
        key: 'entryPoint',
        value: values.entryPoint,
        type: 'string',
      },
    ];
  };

  const formikToOpenIDConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'client_id',
        value: values.client_id,
        type: 'string',
      },
      {
        key: 'client_secret',
        value: values.client_secret,
        type: 'secret',
      },
      {
        key: 'issuer',
        value: values.issuer,
        type: 'string',
      },
      {
        key: 'redirect_uri',
        value: values.redirect_uri,
        type: 'string',
      },
    ];
  };

  const formikToLdapConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'url',
        value: values.url,
        type: 'string',
      },
      {
        key: 'bindDN',
        value: values.bindDN,
        type: 'string',
      },
      {
        key: 'bindCredentials',
        value: values.bindCredentials,
        type: 'secret',
      },
      {
        key: 'searchBase',
        value: values.searchBase,
        type: 'string',
      },
      {
        key: 'searchFilter',
        value: values.searchFilter,
        type: 'string',
      },
      {
        key: 'groupSearchBase',
        value: values.groupSearchBase,
        type: 'string',
      },
      {
        key: 'groupSearchFilter',
        value: values.groupSearchFilter,
        type: 'string',
      },
      {
        key: 'allow_self_signed',
        value: values.allow_self_signed ? 'true' : 'false',
        type: 'boolean',
      },
    ];
  };

  const formikToHeaderConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'email',
        value: values.email,
        type: 'string',
      },
      {
        key: 'firstname',
        value: values.firstname,
        type: 'string',
      },
      {
        key: 'lastname',
        value: values.lastname,
        type: 'string',
      },
    ];
  };
  const getConfigFromStrategy = () => {
    switch (selectedStrategy) {
      case 'SAML': return formikToSamlConfig;
      case 'OpenID': return formikToOpenIDConfig;
      case 'LDAP': return formikToLdapConfig;
      case 'Header': return formikToHeaderConfig;
      default: return () => [];
    }
  };

  return getConfigFromStrategy();
};

export default useFormikToSSOConfig;
