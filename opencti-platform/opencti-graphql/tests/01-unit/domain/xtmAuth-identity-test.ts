import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, SignJWT } from 'jose';

// OpenCTI reaches XTM One on an internal URL while XTM One signs with, and
// expects as audience, its public BASE_URL, published at /xtm/auth/metadata.
const XTM_ONE_URL = 'http://xtm-one:4000';
const XTM_ONE_ISSUER = 'http://localhost:8090';

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  createRemoteJWKSet: vi.fn(),
  xtmOneUrl: '',
}));

vi.mock('../../../src/config/conf', () => ({
  default: {
    get: (key: string) => ({ 'xtm:xtm_one_url': mocks.xtmOneUrl, 'xtm:auth:token_ttl': 300 } as Record<string, any>)[key],
  },
  getBaseUrl: () => 'http://localhost:8080',
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../../src/utils/platformCrypto', () => ({
  getPlatformCrypto: vi.fn(async () => {
    const { privateKey } = await generateKeyPair('EdDSA');
    return {
      deriveEd25519KeyPair: async () => ({
        jwks: { keys: [] },
        publicKeys: {},
        signJwt: (builder: SignJWT) => builder.setProtectedHeader({ alg: 'EdDSA', kid: 'opencti' }).sign(privateKey),
      }),
    };
  }),
}));

vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: ({ baseURL }: { baseURL: string }) => ({ get: (url: string, opts: unknown) => mocks.get(`${baseURL}${url}`, opts) }),
}));

vi.mock('jose', async (importOriginal) => ({
  ...(await importOriginal<typeof import('jose')>()),
  createRemoteJWKSet: mocks.createRemoteJWKSet,
}));

const loadXtmAuth = async () => {
  vi.resetModules();
  return import('../../../src/domain/xtm-auth');
};

const payloadOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

const signAsXtmOne = async (issuer: string) => {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA');
  mocks.createRemoteJWKSet.mockReturnValue(async () => publicKey);
  return new SignJWT({ email: 'analyst@example.com' })
    .setSubject('xtm-user')
    .setIssuer(issuer)
    .setAudience('http://localhost:8080')
    .setIssuedAt()
    .setExpirationTime('5m')
    .setProtectedHeader({ alg: 'EdDSA', kid: 'xtm-one' })
    .sign(privateKey);
};

beforeEach(() => {
  mocks.get.mockReset();
  mocks.createRemoteJWKSet.mockReset();
  mocks.xtmOneUrl = `${XTM_ONE_URL}/`;
});

describe('XTM One reached on its public URL (SaaS)', () => {
  const PUBLIC_URL = 'https://acme.one.filigran.io';

  it('trusts it and fetches its keys there without reading the metadata document', async () => {
    mocks.xtmOneUrl = PUBLIC_URL;
    const { verifyXtmJwt } = await loadXtmAuth();
    const { payload } = await verifyXtmJwt(await signAsXtmOne(PUBLIC_URL));
    expect(payload.email).toBe('analyst@example.com');
    expect(String(mocks.createRemoteJWKSet.mock.calls[0][0])).toBe(`${PUBLIC_URL}/xtm/auth/jwks`);
    expect(mocks.get).not.toHaveBeenCalled();
  });

  it('addresses the tokens sent to it exactly as before', async () => {
    mocks.xtmOneUrl = PUBLIC_URL;
    mocks.get.mockResolvedValue({ data: { issuer: PUBLIC_URL } });
    const { issueXtmJwt } = await loadXtmAuth();
    const token = await issueXtmJwt({ id: 'user-1', user_email: 'analyst@example.com' }, PUBLIC_URL);
    expect(payloadOf(token).aud).toBe(PUBLIC_URL);
  });
});

describe('XTM One reached on an internal URL', () => {
  it('trusts the issuer XTM One publishes and the configured URL, nothing else', async () => {
    mocks.get.mockResolvedValue({ data: { issuer: `${XTM_ONE_ISSUER}/` } });
    const { isTrustedIssuer } = await loadXtmAuth();
    expect(await isTrustedIssuer(XTM_ONE_ISSUER)).toBe(true);
    expect(await isTrustedIssuer(XTM_ONE_URL)).toBe(true);
    expect(await isTrustedIssuer('http://evil.example.com')).toBe(false);
    expect(mocks.get).toHaveBeenCalledTimes(1);
    expect(mocks.get).toHaveBeenCalledWith(`${XTM_ONE_URL}/xtm/auth/metadata`, expect.anything());
  });

  it.each([
    `http://user@${XTM_ONE_ISSUER.slice('http://'.length)}`,
    `${XTM_ONE_ISSUER}/?target=other`,
    `${XTM_ONE_ISSUER}/#fragment`,
  ])('never reads %s as the issuer it spells', async (issuer) => {
    mocks.get.mockResolvedValue({ data: { issuer: XTM_ONE_ISSUER } });
    const { isTrustedIssuer } = await loadXtmAuth();
    expect(await isTrustedIssuer(XTM_ONE_ISSUER)).toBe(true);
    expect(await isTrustedIssuer(issuer)).toBe(false);
  });

  it('addresses the tokens sent to XTM One to its published identity', async () => {
    mocks.get.mockResolvedValue({ data: { issuer: XTM_ONE_ISSUER } });
    const { issueXtmJwt } = await loadXtmAuth();
    const user = { id: 'user-1', user_email: 'analyst@example.com' };
    expect(payloadOf(await issueXtmJwt(user, `${XTM_ONE_URL}/`)).aud).toBe(XTM_ONE_ISSUER);
    expect(payloadOf(await issueXtmJwt(user, 'https://other.example.com')).aud).toBe('https://other.example.com');
  });

  it('is opened in the browser on the identity XTM One publishes', async () => {
    mocks.get.mockResolvedValue({ data: { issuer: `${XTM_ONE_ISSUER}/` } });
    const { getXtmOneIdentity } = await loadXtmAuth();
    expect(await getXtmOneIdentity()).toBe(XTM_ONE_ISSUER);
  });

  it('is opened in the browser on its configured URL when it publishes no identity', async () => {
    mocks.get.mockRejectedValue(Object.assign(new Error('Request failed with status code 404'), { response: { status: 404 } }));
    const { getXtmOneIdentity } = await loadXtmAuth();
    expect(await getXtmOneIdentity()).toBe(XTM_ONE_URL);
  });

  it('has no browser URL when XTM One is not configured', async () => {
    mocks.xtmOneUrl = '';
    const { getXtmOneIdentity } = await loadXtmAuth();
    expect(await getXtmOneIdentity()).toBeUndefined();
    expect(mocks.get).not.toHaveBeenCalled();
  });

  it('verifies an XTM One token with the keys served on the configured URL', async () => {
    mocks.get.mockResolvedValue({ data: { issuer: XTM_ONE_ISSUER } });
    const { verifyXtmJwt } = await loadXtmAuth();
    const token = await signAsXtmOne(XTM_ONE_ISSUER);
    const { payload } = await verifyXtmJwt(token);
    expect(payload.email).toBe('analyst@example.com');
    expect(mocks.createRemoteJWKSet).toHaveBeenCalledTimes(1);
    expect(String(mocks.createRemoteJWKSet.mock.calls[0][0])).toBe(`${XTM_ONE_URL}/xtm/auth/jwks`);
  });

  it('falls back to the configured URL when XTM One publishes no identity', async () => {
    mocks.get.mockRejectedValue(new Error('Request failed with status code 404'));
    const { isTrustedIssuer, issueXtmJwt } = await loadXtmAuth();
    expect(await isTrustedIssuer(XTM_ONE_ISSUER)).toBe(false);
    expect(await isTrustedIssuer(XTM_ONE_URL)).toBe(true);
    const token = await issueXtmJwt({ id: 'user-1', user_email: 'analyst@example.com' }, XTM_ONE_URL);
    expect(payloadOf(token).aud).toBe(XTM_ONE_URL);
  });

  it('keeps the last identity XTM One published while it cannot be reached', async () => {
    vi.useFakeTimers();
    try {
      mocks.get.mockResolvedValueOnce({ data: { issuer: XTM_ONE_ISSUER } });
      const { getXtmOneIssuer } = await loadXtmAuth();
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      vi.advanceTimersByTime(3_600_001);
      mocks.get.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      await vi.waitFor(() => expect(mocks.get).toHaveBeenCalledTimes(2));
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ['no issuer', {}],
    ['a null issuer', { issuer: null }],
    ['a non-textual issuer', { issuer: 42 }],
    ['a non-http issuer', { issuer: 'ftp://xtm.example.com' }],
    ['an issuer with user info', { issuer: 'https://user@xtm.example.com' }],
    ['a body that is not JSON', '<html>'],
  ])('a 200 with %s is a failed read: the last identity is kept', async (_, data) => {
    vi.useFakeTimers();
    try {
      mocks.get.mockResolvedValueOnce({ data: { issuer: XTM_ONE_ISSUER } });
      const { getXtmOneIssuer, isTrustedIssuer } = await loadXtmAuth();
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      vi.advanceTimersByTime(3_600_001);
      mocks.get.mockResolvedValueOnce({ data });
      await getXtmOneIssuer();
      await vi.waitFor(() => expect(mocks.get).toHaveBeenCalledTimes(2));
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      expect(await isTrustedIssuer(XTM_ONE_ISSUER)).toBe(true);
      expect(mocks.get).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('never follows a redirect: another origin cannot supply the identity', async () => {
    vi.useFakeTimers();
    try {
      mocks.get.mockResolvedValueOnce({ data: { issuer: XTM_ONE_ISSUER } });
      const { getXtmOneIssuer } = await loadXtmAuth();
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      expect(mocks.get).toHaveBeenCalledWith(`${XTM_ONE_URL}/xtm/auth/metadata`, expect.objectContaining({ maxRedirects: 0 }));
      vi.advanceTimersByTime(3_600_001);
      mocks.get.mockRejectedValueOnce(Object.assign(new Error('Request failed with status code 302'), { response: { status: 302 } }));
      await getXtmOneIssuer();
      await vi.waitFor(() => expect(mocks.get).toHaveBeenCalledTimes(2));
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
    } finally {
      vi.useRealTimers();
    }
  });

  it('drops the published identity once XTM One answers 404, and falls back to the configured URL', async () => {
    vi.useFakeTimers();
    try {
      mocks.get.mockResolvedValueOnce({ data: { issuer: XTM_ONE_ISSUER } });
      const { getXtmOneIssuer, isTrustedIssuer, issueXtmJwt } = await loadXtmAuth();
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      vi.advanceTimersByTime(3_600_001);
      mocks.get.mockRejectedValueOnce(Object.assign(new Error('Request failed with status code 404'), { response: { status: 404 } }));
      await getXtmOneIssuer();
      await vi.waitFor(() => expect(mocks.get).toHaveBeenCalledTimes(2));
      await vi.waitFor(async () => expect(await getXtmOneIssuer()).toBeUndefined());
      expect(await isTrustedIssuer(XTM_ONE_ISSUER)).toBe(false);
      const token = await issueXtmJwt({ id: 'user-1', user_email: 'analyst@example.com' }, XTM_ONE_URL);
      expect(payloadOf(token).aud).toBe(XTM_ONE_URL);
    } finally {
      vi.useRealTimers();
    }
  });

  it('only the first call waits for XTM One: an expired identity is served while it is read again', async () => {
    vi.useFakeTimers();
    try {
      mocks.get.mockResolvedValueOnce({ data: { issuer: XTM_ONE_ISSUER } });
      const { getXtmOneIssuer } = await loadXtmAuth();
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      vi.advanceTimersByTime(3_600_001);
      mocks.get.mockReturnValueOnce(new Promise(() => {}));
      expect(await getXtmOneIssuer()).toBe(XTM_ONE_ISSUER);
      expect(mocks.get).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
