import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';

const useFormikToSSOConfig = () => {
  const formikToSamlConfig = (values: SSODefinitionFormValues) => {
    return [
      {
        key: 'private_key',
        value: values.private_key,
        type: 'String',
      },
      {
        key: 'issuer',
        value: values.issuer,
        type: 'String',
      },
      {
        key: 'idp_cert',
        value: values.idp_cert,
        type: 'String',
      },
      {
        key: 'saml_callback_url',
        value: values.saml_callback_url,
        type: 'String',
      },
      {
        key: 'want_assertions_signed',
        value: values.want_assertions_signed ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'want_auth_response_signed',
        value: values.want_auth_response_signed ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'login_idp_directly',
        value: values.login_idp_directly ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'logout_remote',
        value: values.logout_remote ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'provider_method',
        value: values.provider_method,
        type: 'String',
      },
      {
        key: 'idp_signing_certificate',
        value: values.idp_signing_certificate,
        type: 'String',
      },
      {
        key: 'sso_binding_type',
        value: values.sso_binding_type,
        type: 'String',
      },
      {
        key: 'force_reauthentication',
        value: values.force_reauthentication ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'enable_debug_mode',
        value: values.enable_debug_mode ? 'true' : 'false',
        type: 'Boolean',
      },
    ];
  };
  return { formikToSamlConfig };
};

export default useFormikToSSOConfig;
