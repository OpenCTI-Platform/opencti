import { v4 as uuidv4 } from 'uuid';
import { type JWK, type JWTHeaderParameters, SignJWT } from 'jose';
import { type createCryptoKeyFactory, getPlatformCrypto } from '../../../utils/platformCrypto';
import { memoizeAsync } from '../../../utils/memoize';
import { UnsupportedError } from '../../../config/errors';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../../../utils/access';
import type { BasicStoreSettings } from '../../../types/settings';
import { HUB_OPENCTI_IDENTIFIER } from './xtm-hub-identifier';

// The instance key that signs the assertions this platform sends to XTM Hub.
// It is derived from the platform encryption key, never generated nor stored:
// every node of a cluster derives the same key, and a restart keeps it.
// The private part never leaves this module: only the public JWK and signed
// assertions do.

type CryptoKeyFactory = ReturnType<typeof createCryptoKeyFactory>;

const XTM_HUB_KEY_DERIVATION_PATH = ['xtm-hub', 'platform-assertion'];
const XTM_HUB_KEY_DEFAULT_VERSION = 1;

export const XTM_HUB_ASSERTION_TYPE = 'xtm-hub-platform+jwt';
export const XTM_HUB_ASSERTION_AUDIENCE = 'xtm-hub';
export const XTM_HUB_ASSERTION_LIFETIME_SECONDS = 60;

export type XtmHubPublicJwk = Required<Pick<JWK, 'kty' | 'crv' | 'alg' | 'use' | 'kid' | 'x'>>;

export interface XtmHubAssertionInput {
  // The platform id XTM Hub knows this instance by (the `iss` claim).
  platformId: string;
  // The path the assertion is for (the `htu` claim), when it opens one resource only, such as a download.
  htu?: string;
}

export interface XtmHubKey {
  version: number;
  publicJwk: XtmHubPublicJwk;
  signAssertion: (input: XtmHubAssertionInput) => Promise<string>;
}

// platformCrypto's signJwt sets `typ: JWT` through setProtectedHeader; XTM Hub expects its own type.
// If signJwt stops calling setProtectedHeader on the JWT it receives, this override no longer applies.
class XtmHubAssertionJWT extends SignJWT {
  setProtectedHeader(protectedHeader: JWTHeaderParameters) {
    return super.setProtectedHeader({ ...protectedHeader, typ: XTM_HUB_ASSERTION_TYPE });
  }
}

const assertXtmHubKeyVersion = (version: unknown): number => {
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) {
    throw UnsupportedError('Invalid XTM Hub key version', { version });
  }
  return version;
};

// The stored version, or the first one when none is stored yet.
// A malformed value is refused rather than replaced: a key other than the one
// XTM Hub holds would fail every call.
export const resolveXtmHubKeyVersion = (settings: Pick<BasicStoreSettings, 'xtm_hub_key_version'>): number => {
  const stored = settings.xtm_hub_key_version;
  if (stored === undefined || stored === null) {
    return XTM_HUB_KEY_DEFAULT_VERSION;
  }
  return assertXtmHubKeyVersion(stored);
};

export const deriveXtmHubKey = async (factory: CryptoKeyFactory, version: number): Promise<XtmHubKey> => {
  const keyVersion = assertXtmHubKeyVersion(version);
  const keyPair = await factory.deriveEd25519KeyPair(XTM_HUB_KEY_DERIVATION_PATH, keyVersion);
  const [jwk] = keyPair.jwks.keys;
  const publicJwk: XtmHubPublicJwk = { kty: jwk.kty, crv: jwk.crv, alg: jwk.alg, use: jwk.use, kid: jwk.kid, x: jwk.x };

  const signAssertion = async ({ platformId, htu }: XtmHubAssertionInput) => {
    if (!platformId) {
      throw UnsupportedError('An XTM Hub assertion needs the platform id');
    }
    const issuedAt = Math.floor(Date.now() / 1000);
    const claims: Record<string, string> = { identifier: HUB_OPENCTI_IDENTIFIER };
    if (htu) {
      claims.htu = htu;
    }
    const jwt = new XtmHubAssertionJWT(claims)
      .setIssuer(platformId)
      .setAudience(XTM_HUB_ASSERTION_AUDIENCE)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + XTM_HUB_ASSERTION_LIFETIME_SECONDS)
      .setJti(uuidv4());
    return keyPair.signJwt(jwt);
  };

  return { version: keyVersion, publicJwk, signAssertion };
};

const getXtmHubKeyOfVersion = memoizeAsync(
  async (version: number) => deriveXtmHubKey(await getPlatformCrypto(), version),
  (version) => String(version),
);

// The key of the version stored in the platform settings.
export const getXtmHubKey = async (): Promise<XtmHubKey> => {
  const context = executionContext('xtm_hub_key');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return getXtmHubKeyOfVersion(resolveXtmHubKeyVersion(settings));
};

// The public key as a JWK Set, served without authentication on /xtm/hub/jwks.
export const getXtmHubJwks = async (): Promise<{ keys: XtmHubPublicJwk[] }> => {
  const { publicJwk } = await getXtmHubKey();
  return { keys: [publicJwk] };
};
