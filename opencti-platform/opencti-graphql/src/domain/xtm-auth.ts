import { v4 as uuidv4 } from 'uuid';
import { createRemoteJWKSet, type FlattenedJWSInput, type JWTHeaderParameters, jwtVerify, SignJWT } from 'jose';
import conf, { getBaseUrl, logApp } from '../config/conf';
import { getPlatformCrypto } from '../utils/platformCrypto';
import { memoize } from '../utils/memoize';
import { AuthenticationFailure } from '../config/errors';
import { getHttpClient } from '../utils/http-client';

const getJWTKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveEd25519KeyPair(['authentication', 'xtm'], 1);
});

export const getXtmJwks = async () => {
  const keyPair = await getJWTKeyPair();
  return keyPair.jwks;
};

// -- URLs --------------------------------------------------------------------

const normaliseUrl = (url: string) => (url.endsWith('/') ? url.slice(0, -1) : url);

// Two spellings of one URL (case, default port, trailing slash) are the same issuer.
const canonicalUrl = (url: string): string | undefined => {
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return undefined;
    }
    // User info, a query or a fragment would make two different identities compare equal.
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      return undefined;
    }
    return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, '')}`;
  } catch {
    return undefined;
  }
};

const platformIssuer = normaliseUrl(getBaseUrl());
export const isOwnIssuer = (issuer: string): boolean => issuer === platformIssuer;

// The URL this platform reaches XTM One on. In Docker or Kubernetes it is an
// internal address (http://xtm-one:4000), while XTM One signs its tokens with,
// and expects on the tokens sent to it, its public BASE_URL: the issuer it
// publishes at /xtm/auth/metadata. Keys are always fetched on the configured URL.
const configuredXtmOneUrl = conf.get('xtm:xtm_one_url');
const xtmOneUrl = typeof configuredXtmOneUrl === 'string' && configuredXtmOneUrl.length > 0
  ? normaliseUrl(configuredXtmOneUrl)
  : undefined;
const xtmOneCanonicalUrl = xtmOneUrl ? canonicalUrl(xtmOneUrl) : undefined;

// -- XTM One identity --------------------------------------------------------

const XTM_ONE_IDENTITY_TTL = 3_600_000;
const XTM_ONE_IDENTITY_RETRY = 60_000;

let xtmOneIdentity: { issuer: string | undefined; expiresAt: number } | undefined;
let xtmOneIdentityFetch: Promise<string | undefined> | undefined;

const fetchXtmOneIssuer = async (): Promise<string | undefined> => {
  const previous = xtmOneIdentity?.issuer;
  try {
    const httpClient = getHttpClient({ baseURL: xtmOneUrl, responseType: 'json' });
    // Only the configured URL may answer: a redirect is a failed read, never
    // another origin supplying XTM One's identity.
    const response = await httpClient.get('/xtm/auth/metadata', { timeout: 10000, maxRedirects: 0 });
    const published = response.data?.issuer;
    const issuer = typeof published === 'string' ? canonicalUrl(published) : undefined;
    if (!issuer) {
      // Only a 404 says XTM One publishes no identity: a document without one is a failed read.
      throw new Error('XTM One metadata names no usable issuer');
    }
    if (issuer !== previous && issuer !== xtmOneCanonicalUrl) {
      logApp.info('[XTM_AUTH] XTM One publishes an identity other than its configured URL', { url: xtmOneUrl, issuer });
    }
    xtmOneIdentity = { issuer, expiresAt: Date.now() + XTM_ONE_IDENTITY_TTL };
    return issuer;
  } catch (err: any) {
    // A 404 says XTM One publishes no identity (it predates the document or no
    // longer serves it): its tokens carry the configured URL again. Any other
    // failure is transient and keeps the last identity it published.
    const notPublished = err?.response?.status === 404;
    const issuer = notPublished ? undefined : previous;
    if (notPublished && previous) {
      logApp.info('[XTM_AUTH] XTM One no longer publishes an identity, using its configured URL', { url: xtmOneUrl });
    } else {
      logApp.debug('[XTM_AUTH] XTM One identity unavailable', { url: xtmOneUrl, message: err?.message });
    }
    xtmOneIdentity = { issuer, expiresAt: Date.now() + XTM_ONE_IDENTITY_RETRY };
    return issuer;
  }
};

export const getXtmOneIssuer = async (): Promise<string | undefined> => {
  if (!xtmOneUrl) {
    return undefined;
  }
  if (xtmOneIdentity && xtmOneIdentity.expiresAt > Date.now()) {
    return xtmOneIdentity.issuer;
  }
  if (!xtmOneIdentityFetch) {
    xtmOneIdentityFetch = fetchXtmOneIssuer().finally(() => {
      xtmOneIdentityFetch = undefined;
    });
  }
  // Past its expiry the last answer is served while it is read again: only the
  // first call ever waits for XTM One.
  return xtmOneIdentity ? xtmOneIdentity.issuer : xtmOneIdentityFetch;
};

// Where a browser opens XTM One: the identity it publishes, else the
// configured URL, which may be an address only this backend reaches.
export const getXtmOneIdentity = async (): Promise<string | undefined> => {
  if (!xtmOneUrl) {
    return undefined;
  }
  return (await getXtmOneIssuer()) ?? xtmOneUrl;
};

// -- Trusted issuers ---------------------------------------------------------

export const isTrustedIssuer = async (issuer: string): Promise<boolean> => {
  const candidate = canonicalUrl(issuer);
  if (!candidate || !xtmOneCanonicalUrl) {
    return false;
  }
  return candidate === xtmOneCanonicalUrl || candidate === await getXtmOneIssuer();
};

// -- JWKS cache for XTM One ----------------------------------------------------

const JWKS_CACHE_MAX_AGE = 3_600_000;

let xtmOneJwks: ReturnType<typeof createRemoteJWKSet> | undefined;

const getXtmOneJwks = () => {
  if (!xtmOneJwks) {
    const jwksUrl = `${xtmOneUrl}/xtm/auth/jwks`;
    logApp.debug('[XTM_AUTH] Creating remote JWKS set', { jwksUrl });
    xtmOneJwks = createRemoteJWKSet(new URL(jwksUrl), { cacheMaxAge: JWKS_CACHE_MAX_AGE });
  }
  return xtmOneJwks;
};

// A token addressed to the configured XTM One URL is addressed to XTM One's
// identity, the only audience XTM One accepts by default.
const resolveAudience = async (audience: string): Promise<string> => {
  if (xtmOneCanonicalUrl && canonicalUrl(audience) === xtmOneCanonicalUrl) {
    return (await getXtmOneIssuer()) ?? audience;
  }
  return audience;
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
  if (!(await isTrustedIssuer(iss))) {
    throw AuthenticationFailure('JWT issuer is not trusted', { issuer: iss });
  }
  // Delegate to jose's remote JWKS resolver (handles kid matching + auto-refresh)
  return getXtmOneJwks()(header, token);
};

// -- JWT issue and verify -------------------------------------------

const tokenTtl = Math.min(Number(conf.get('xtm:auth:token_ttl') ?? 600), 600);

export const issueXtmJwt = async (user: { id: string; user_email: string }, target: string): Promise<string> => {
  const now = new Date();
  const exp = new Date(now.getTime() + (tokenTtl * 1000));
  const audience = await resolveAudience(target);
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
    logApp.warn('[XTM_AUTH] JWT verification failed', {
      code: err?.code,
      message: err?.message,
      name: err?.name,
    });
    throw AuthenticationFailure('JWT signature verification failed');
  }
};
