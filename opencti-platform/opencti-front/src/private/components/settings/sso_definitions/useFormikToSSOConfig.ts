import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionCreation';

const useFormikToSSOConfig = () => {
  const formikToSamlConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'privateKey',
        value: values.private_key,
        type: 'String',
      },
      {
        key: 'issuer',
        value: values.issuer,
        type: 'String',
      },
      {
        key: 'idpCert',
        value: values.idp_cert,
        type: 'String',
      },
      {
        key: 'callbackUrl',
        value: values.saml_callback_url,
        type: 'String',
      },
      {
        key: 'assertionSigned',
        value: values.want_assertions_signed ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'authResponseSigned',
        value: values.want_auth_response_signed ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'loginIdpDirectly',
        value: values.login_idp_directly ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'logoutRemote',
        value: values.logout_remote ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'providerMethod',
        value: values.provider_method,
        type: 'String',
      },
      {
        key: 'idpSigningCertificate',
        value: values.idp_signing_certificate,
        type: 'String',
      },
      {
        key: 'ssoBindingType',
        value: values.sso_binding_type,
        type: 'String',
      },
      {
        key: 'forceReauthentication',
        value: values.force_reauthentication ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'enableDebugMode',
        value: values.enable_debug_mode ? 'true' : 'false',
        type: 'Boolean',
      },
    ];
  };
  return { formikToSamlConfig };
};

export default useFormikToSSOConfig;
