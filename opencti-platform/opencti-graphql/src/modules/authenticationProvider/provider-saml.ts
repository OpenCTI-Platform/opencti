import type { ProviderMeta, SamlStoreConfiguration } from './authenticationProvider-types';
import { AuthenticationProviderError, type AuthenticationProviderLogger } from './providers-logger';
import { AuthType } from './providers-configuration';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import { createMapper } from './mappings-utils';
import { decryptAuthValue, flatExtraConf } from './authenticationProvider-domain';
import { getBaseUrl } from '../../config/conf';
import { handleProviderLogin } from './providers';
import { isNotEmptyField } from '../../database/utils';

export const buildSAMLOptions = async (meta: ProviderMeta, conf: SamlStoreConfiguration): Promise<PassportSamlConfig> => ({
  name: meta.name,
  entryPoint: conf.entry_point,
  issuer: conf.issuer,
  idpCert: conf.idp_certificate,
  privateKey: conf.private_key_encrypted ? await decryptAuthValue(conf.private_key_encrypted) : undefined,
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
  decryptionPvk: conf.decryption_pvk_encrypted && isNotEmptyField(conf.decryption_pvk_encrypted)
    ? await decryptAuthValue(conf.decryption_pvk_encrypted) : undefined,
  ...flatExtraConf(conf.extra_conf),
});

export const createSAMLStrategy = async (logger: AuthenticationProviderLogger, meta: ProviderMeta, conf: SamlStoreConfiguration) => {
  const samlOptions = await buildSAMLOptions(meta, conf);
  const mapper = createMapper(conf);

  const samlLoginCallback: VerifyWithoutRequest = async (profile, done) => {
    logger.info('Successfully logged on IdP', { profile });
    if (!profile) {
      return done(new AuthenticationProviderError('No profile in SAML response'));
    }

    try {
      const attributes = profile.attributes ?? profile;
      const loginInfo = await mapper(attributes);
      const loginInfoWithMeta = {
        ...loginInfo,
        userMapping: {
          ...loginInfo.userMapping,
          nameID: profile.nameID,
          nameIDFormat: profile.nameIDFormat,
        },
      };
      const user = await handleProviderLogin(logger, loginInfoWithMeta);
      return done(null, user);
    } catch (e) {
      const err = e instanceof Error ? e : Error(String(e));
      return done(err);
    }
  };

  const samlLogoutCallback: VerifyWithoutRequest = (profile) => {
    logger.info('Logout done', { profile });
  };

  const samlStrategy = new SamlStrategy(samlOptions, samlLoginCallback, samlLogoutCallback);

  return {
    strategy: samlStrategy,
    auth_type: AuthType.AUTH_SSO,
    logout_remote: conf.logout_remote,
  };
};
