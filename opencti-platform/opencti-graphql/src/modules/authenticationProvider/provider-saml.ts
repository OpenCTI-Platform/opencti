import type { ProviderMeta, SamlStoreConfiguration } from './authenticationProvider-types';
import { type AuthenticationProviderLogger } from './providers-logger';
import { AuthType, providerLoginHandler } from './providers-configuration';
import { registerAuthenticationProvider } from './providers-initialization';
import { ConfigurationError } from '../../config/errors';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { AuthenticationProviderType } from '../../generated/graphql';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import { createMappers, resolveDotPath } from './mappings-utils';
import { decryptAuthValue, flatExtraConf } from './authenticationProvider-domain';
import { getBaseUrl } from '../../config/conf';

export const buildSAMLOptions = async (meta: ProviderMeta, conf: SamlStoreConfiguration): Promise<PassportSamlConfig> => ({
  name: meta.name,
  issuer: conf.issuer,
  idpCert: conf.idp_certificate,
  privateKey: await decryptAuthValue(conf.private_key_encrypted),
  callbackUrl: conf.callback_url ?? `${getBaseUrl()}/auth/${meta.identifier}/callback`,
  wantAssertionsSigned: conf.want_assertions_signed,
  wantAuthnResponseSigned: conf.want_authn_response_signed,
  publicCert: conf.signing_cert,
  authnRequestBinding: conf.sso_binding_type,
  forceAuthn: conf.force_reauthentication,
  identifierFormat: conf.identifier_format,
  signatureAlgorithm: conf.signature_algorithm,
  digestAlgorithm: conf.digest_algorithm,
  authnContext: conf.authn_context,
  disableRequestedAuthnContext: conf.disable_requested_authn_context,
  disableRequestAcsUrl: conf.disable_request_acs_url,
  skipRequestCompression: conf.skip_request_compression,
  decryptionPvk: conf.decryption_pvk_encrypted ? await decryptAuthValue(conf.decryption_pvk_encrypted) : undefined,
  ...flatExtraConf(conf.extra_conf),
});

export const registerSAMLStrategy = async (logger: AuthenticationProviderLogger, meta: ProviderMeta, conf: SamlStoreConfiguration) => {
  const samlOptions = await buildSAMLOptions(meta, conf);
  const { resolveUserInfo, resolveGroups, resolveOrganizations } = createMappers(conf);

  const samlLoginCallback: VerifyWithoutRequest = async (profile, done) => {
    if (!profile) {
      throw ConfigurationError('No profile in SAML response, please verify SAML server configuration');
    }
    logger.info('Successfully logged on IdP', { profile });

    const attributes = profile.attribute ?? profile;
    const userInfo = await resolveUserInfo((expr) => resolveDotPath(attributes, expr));
    const groups = await resolveGroups((expr) => resolveDotPath(attributes, expr));
    const organizations = await resolveOrganizations((expr) => resolveDotPath(attributes, expr));

    logger.info('User info resolved', { userInfo, groups, organizations });

    const opts = {
      strategy: AuthenticationProviderType.Saml,
      name: meta.name,
      identifier: meta.identifier,
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
    logger.info('Logout done', { profile });
  };

  const samlStrategy = new SamlStrategy(samlOptions, samlLoginCallback, samlLogoutCallback);

  registerAuthenticationProvider(
    meta.identifier,
    samlStrategy,
    {
      name: meta.name,
      type: AuthType.AUTH_SSO,
      strategy: AuthenticationProviderType.Saml,
      provider: meta.identifier,
      logout_remote: conf.logout_remote,
    },
  );
};
