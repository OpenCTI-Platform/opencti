import { v4 as uuidv4 } from 'uuid';
import { createRemoteJWKSet, type FlattenedJWSInput, type JWTHeaderParameters, jwtVerify, SignJWT } from 'jose';
import conf, { getBaseUrl, logApp } from '../config/conf';
import { getPlatformCrypto } from '../utils/platformCrypto';
import { memoize } from '../utils/memoize';
import { AuthenticationFailure } from '../config/errors';

const getJWTKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveEd25519KeyPair(['authentication', 'xtm'], 1);
});

export const getXtmJwks = async () => {
  const keyPair = await getJWTKeyPair();
  return keyPair.jwks;
};

// -- Trusted issuers ---------------------------------------------------------

const normaliseUrl = (url: string) => (url.endsWith('/') ? url.slice(0, -1) : url);

const platformIssuer = normaliseUrl(getBaseUrl());
export const isOwnIssuer = (issuer: string): boolean => issuer === platformIssuer;

const trustedIssuers: Set<string> = new Set(
  [conf.get('xtm:xtm_one_url')]
    .filter((url): url is string => typeof url === 'string' && url.length > 0)
    .map(normaliseUrl),
);

export const isTrustedIssuer = (issuer: string): boolean => {
  return trustedIssuers.has(issuer);
};

// -- JWKS cache for remote issuers -------------------------------------------

const JWKS_CACHE_MAX_AGE = 3_600_000;

const issuerCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

const getRemoteJwks = (issuerBaseUrl: string) => {
  let getKey = issuerCache.get(issuerBaseUrl);
  if (!getKey) {
    const jwksUrl = `${issuerBaseUrl}/xtm/auth/jwks`;
    logApp.debug('[XTM_AUTH] Creating remote JWKS set', { issuer: issuerBaseUrl, jwksUrl });
    getKey = createRemoteJWKSet(new URL(jwksUrl), { cacheMaxAge: JWKS_CACHE_MAX_AGE });
    issuerCache.set(issuerBaseUrl, getKey);
  }
  return getKey;
};

// -- Single key resolver for jwtVerify ---------------------------------------

const resolveKey = async (header: JWTHeaderParameters, token: FlattenedJWSInput) => {
  // Decode iss from the flattened token payload (base64url-encoded)
  const raw = typeof token.payload === 'string'
    ? token.payload
    : Buffer.from(token.payload).toString('base64url');
  const { iss } = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  if (!iss) {
    throw AuthenticationFailure('JWT missing iss claim');
  }
  if (isOwnIssuer(iss)) {
    const keyPair = await getJWTKeyPair();
    const { kid } = header;
    const publicKey = kid && keyPair.publicKeys[kid];
    if (!publicKey) {
      throw AuthenticationFailure('JWT kid does not match any platform key', { kid });
    }
    return publicKey;
  }
  if (!isTrustedIssuer(iss)) {
    throw AuthenticationFailure('JWT issuer is not trusted', { issuer: iss });
  }
  // Delegate to jose's remote JWKS resolver (handles kid matching + auto-refresh)
  return getRemoteJwks(iss)(header, token);
};

// -- JWT issue and verify -------------------------------------------

const tokenTtl = Math.min(Number(conf.get('xtm:auth:token_ttl') ?? 600), 600);

export const issueXtmJwt = async (user: { id: string; user_email: string }, audience: string): Promise<string> => {
  const now = new Date();
  const exp = new Date(now.getTime() + (tokenTtl * 1000));
  const jwt = new SignJWT({ email: user.user_email })
    .setSubject(user.id)
    .setIssuer(platformIssuer)
    .setAudience(audience)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(exp)
    .setJti(uuidv4());
  const keyPair = await getJWTKeyPair();
  const token = await keyPair.signJwt(jwt);
  logApp.debug('[XTM_AUTH] Issued cross-platform JWT', { issuer: platformIssuer, subject: user.id, audience, ttl: tokenTtl });
  return token;
};

export const verifyXtmJwt = async (token: string) => {
  try {
    return await jwtVerify(token, resolveKey, { algorithms: ['EdDSA'] });
  } catch (err: any) {
    if (err?.name === 'AuthenticationFailure' || err?.attributes?.reason) {
      throw err;
    }
    throw AuthenticationFailure('JWT signature verification failed');
  }
};
