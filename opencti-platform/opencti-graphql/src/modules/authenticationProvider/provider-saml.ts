import type { SamlProviderConfiguration } from './authenticationProvider-types';
import { logAuthInfo } from './providers-logger';
import { AuthType, type ProviderConfiguration, providerLoginHandler } from './providers-configuration';
import { registerAuthenticationProvider } from './providers-initialization';
import { ConfigurationError } from '../../config/errors';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { AuthenticationProviderType } from '../../generated/graphql';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import { resolveGroups, resolveOrganizations, resolvePath, resolveUserInfo } from './mappings-utils';

// TODO migration  conf.mail_attribute -> conf.user_info_mapping.email_expr
// TODO migration  conf.account_attribute -> conf.user_info_mapping.name_expr
// TODO migration  conf.firstname_attribute -> conf.user_info_mapping.firstname_expr
// TODO migration  conf.lastname_attribute -> conf.user_info_mapping.lastname_expr
// TODO migration  groupsManagement?.group_attributes || ['groups']  -> conf.groups_mapping.groups_expr
// TODO migration  orgsManagement?.organizations_path || ['organizations']; -> conf.organizations_mapping.organizations_expr

export const buildSAMLOptions = (conf: SamlProviderConfiguration): PassportSamlConfig => ({
  name: conf.name,
  issuer: conf.issuer,
  idpCert: conf.idp_certificate,
  privateKey: conf.private_key,
  callbackUrl: conf.callback_url,
  wantAssertionsSigned: conf.want_assertions_signed,
  wantAuthnResponseSigned: conf.want_authn_response_signed,
  publicCert: conf.signing_cert, // TODO check if public cert is the correct field for passport-saml
  authnRequestBinding: conf.sso_binding_type, // TODO check if sso_binding_type is the correct field for passport-saml
  forceAuthn: conf.force_reauthentication, // TODO check if force_reauthentication is the correct field for passport-saml
  ...conf.extra_conf,
});

export const registerSAMLStrategy = async (conf: SamlProviderConfiguration) => {
  logAuthInfo('Configuring SAML', AuthenticationProviderType.Saml, { conf });

  const samlOptions = buildSAMLOptions(conf);

  const samlLoginCallback: VerifyWithoutRequest = async (profile, done) => {
    if (!profile) {
      throw ConfigurationError('No profile in SAML response, please verify SAML server configuration');
    }
    logAuthInfo('Successfully logged from provider, computing groups and organizations', AuthenticationProviderType.Saml, { profile });

    const attributes = profile.attribute ?? profile;
    const userInfo = await resolveUserInfo(conf.user_info_mapping, (expr) => resolvePath(attributes, expr.split('.')));
    const groups = await resolveGroups(conf.groups_mapping, (expr) => resolvePath(attributes, expr.split('.')));
    const organizations = await resolveOrganizations(conf.organizations_mapping, (expr) => resolvePath(attributes, expr.split('.')));

    const opts = {
      strategy: AuthenticationProviderType.Saml,
      name: conf.name,
      identifier: conf.identifier,
      providerGroups: groups,
      providerOrganizations: organizations,
      autoCreateGroup: conf.groups_mapping.auto_create_groups,
    };
    const userInfoWithMeta = {
      ...userInfo,
      email: userInfo.email || profile.nameID,
      provider_metadata: {
        nameID: profile.nameID,
        nameIDFormat: profile.nameIDFormat,
      },
    };
    await providerLoginHandler(userInfoWithMeta, done, opts);
  };

  const samlLogoutCallback: VerifyWithoutRequest = (profile) => {
    // SAML Logout function
    logAuthInfo(`Logout done for ${profile}`, AuthenticationProviderType.Saml);
  };

  const samlStrategy = new SamlStrategy(samlOptions, samlLoginCallback, samlLogoutCallback);

  const providerConfig: ProviderConfiguration = {
    name: conf.name,
    type: AuthType.AUTH_SSO,
    strategy: AuthenticationProviderType.Saml,
    provider: conf.identifier,
    logout_remote: conf.logout_remote,
  };
  registerAuthenticationProvider(conf.identifier, samlStrategy, providerConfig);
};
