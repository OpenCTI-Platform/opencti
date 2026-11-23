import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import passport from 'passport';
import archiver from 'archiver';
import * as conf from '../../../src/config/conf';
import createApp, { handleStorageGet, handleStorageView, handleStorageViewEmbedded, handleStorageHtml, handleStorageEncrypted } from '../../../src/http/httpPlatform';
import { sanitizeReferer } from '../../../src/http/httpUtils';
import { getBaseUrl, logApp } from '../../../src/config/conf';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { sessionAuthenticateUser } from '../../../src/domain/user';
import { AuthType, EnvStrategyType, PROVIDERS, type ProviderConfiguration } from '../../../src/modules/authenticationProvider/providers-configuration';

vi.mock('../../../src/domain/user', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, sessionAuthenticateUser: vi.fn() };
});

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));
vi.mock('../../../src/http/httpServer-draft', () => ({
  checkDraftInContext: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual:object = await importOriginal();
  return {
    ...actual,
    logApp: {
      info: vi.fn(),
      error: vi.fn(),
    }, };
});

const baseUrl = getBaseUrl();

describe('httpPlatform: sanitizeReferer function', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  describe('When refererToSanitize is undefined', () => {
    it('should return /', () => {
      const result = sanitizeReferer(undefined);
      expect(result).toBe('/');
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize has same origin as baseUrl', () => {
    it('should return expected referer', () => {
      const refererToSanitize = `${baseUrl}/some/path`;
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(refererToSanitize);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is a relative url', () => {
    it('should return expected referer', () => {
      const refererToSanitize = '/some-relative/path';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe('/some-relative/path');
      expect(logApp.info).not.toHaveBeenCalled();
    });

    it('should return expected referer', () => {
      const refererToSanitize = '//my.wrong';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe('/');
      expect(logApp.info).toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is correct and has hash and search params', () => {
    it('should return expected referer', () => {
      const refererToSanitize = `${baseUrl}/some/path?param=value#section`;
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(refererToSanitize);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is not a correct value', () => {
    it('should return /', () => {
      const refererToSanitize = 'http://www.wrong.com';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe('/');
      expect(logApp.info).toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is not a domain name', () => {
    it('should return baseUrl', () => {
      const refererToSanitize = 'www.wrong.com';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/www.wrong.com`);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When refererToSanitize is an IP', () => {
    it('should return baseUrl', () => {
      const refererToSanitize = '22.0.0.1';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/22.0.0.1`);
      expect(logApp.info).not.toHaveBeenCalled();
    });

    it('should return baseUrl', () => {
      const refererToSanitize = '22.0.0.1/path/one';
      const result = sanitizeReferer(refererToSanitize);
      expect(result).toBe(`${baseUrl}/22.0.0.1/path/one`);
      expect(logApp.info).not.toHaveBeenCalled();
    });
  });

  describe('When base url is not configured', () => {
    const req = { protocol: 'https', hostname: 'cti.example.com', headers: { host: 'cti.example.com' } } as any;

    beforeEach(() => {
      vi.spyOn(conf, 'getBaseUrl').mockImplementation((request?: any) => (request ? 'https://cti.example.com' : ''));
    });

    it('should infer the platform origin from the request', () => {
      expect(sanitizeReferer('/some/path', req)).toBe('/some/path');
    });

    it('should reject a double slash referer', () => {
      expect(sanitizeReferer('//evil.example/phish', req)).toBe('/');
    });

    it('should return / instead of throwing without request', () => {
      expect(sanitizeReferer('/some/path')).toBe('/');
    });
  });

  describe('When base url is set without scheme', () => {
    it('should return / instead of throwing', () => {
      vi.spyOn(conf, 'getBaseUrl').mockReturnValue('cti.example.com');
      expect(sanitizeReferer('/some/path')).toBe('/');
    });
  });

  describe('When base url has an uppercase host and a default port', () => {
    it('should accept a referer on the same origin', () => {
      vi.spyOn(conf, 'getBaseUrl').mockReturnValue('https://CTI.example.com:443');
      expect(sanitizeReferer('https://cti.example.com/some/path')).toBe('https://cti.example.com/some/path');
    });
  });

  describe('When base url has a base path', () => {
    beforeEach(() => {
      vi.spyOn(conf, 'getBaseUrl').mockReturnValue('https://cti.example.com/opencti');
    });

    it('should keep the query string of a referer on the base path root', () => {
      expect(sanitizeReferer('/opencti?tab=1')).toBe('/opencti?tab=1');
    });

    it('should keep the hash of a referer on the base path root', () => {
      expect(sanitizeReferer('/opencti#section')).toBe('/opencti#section');
    });

    it('should reject a referer outside the base path that shares its prefix', () => {
      expect(sanitizeReferer('https://cti.example.com/opencti-evil')).toBe('/');
    });
  });
});

describe('httpPlatform: /logout redirect', () => {
  const setupLogoutHandler = async () => {
    const routes = new Map<string, (req: any, res: any) => Promise<void>>();
    const app: any = {
      set: vi.fn(),
      use: vi.fn(),
      get: vi.fn((path: unknown, handler: any) => {
        if (typeof path === 'string' && typeof handler === 'function') {
          routes.set(path, handler);
        }
      }),
      post: vi.fn(),
      delete: vi.fn(),
      put: vi.fn(),
      patch: vi.fn(),
      all: vi.fn(),
    };
    await createApp(app, {} as any);
    const logoutRoute = Array.from(routes.entries()).find(([path]) => path.endsWith('/logout'));
    return logoutRoute?.[1];
  };

  it('should keep logout redirect on the platform origin when referer path starts with a double slash', async () => {
    const logoutHandler = await setupLogoutHandler();
    const res: any = { redirect: vi.fn(), cookie: vi.fn() };

    await logoutHandler?.({ headers: { referer: 'https://attacker.com//evil.example/phish' }, session: {} }, res);

    expect(res.redirect).toHaveBeenCalledTimes(1);
    const target = res.redirect.mock.calls[0][0];
    expect(new URL(target, baseUrl).origin).toBe(new URL(baseUrl).origin);
  });
});

// ─── storage route draft-context authorization regression ───────────────────
// These routes read `context.draft_context` (set from the `opencti-draft-id`
// header) via `loadFile`, but historically only the GraphQL context enforced
// draft membership via `checkDraftInContext`. Each handler must call it and
// must abort before ever reaching `loadFile`/`downloadFile` when it rejects,
// so a caller cannot use a forged header to read a draft-scoped file they
// don't have access to.

const makeStorageReq = (params: Record<string, unknown> = {}) => ({ params, headers: {} } as any);
const makeStorageRes = () => ({
  sendStatus: vi.fn(),
  status: vi.fn().mockReturnThis(),
  send: vi.fn(),
  attachment: vi.fn(),
  set: vi.fn(),
  cookie: vi.fn(),
}) as any;

describe('storage routes: draft authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const DENIED_CONTEXT = {
    user: { id: 'user-b' },
    draft_context: 'restricted-draft',
  };
  const DRAFT_ERROR = new Error('Draft restricted-draft cannot be found');

  it('handleStorageGet refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.txt'] });
    const res = makeStorageRes();

    await handleStorageGet(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.attachment).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageView refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.txt'] });
    const res = makeStorageRes();

    await handleStorageView(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageViewEmbedded refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ 0: 'x', 1: 'entity-id', 2: 'y', 3: 'file.txt' });
    const res = makeStorageRes();

    await handleStorageViewEmbedded(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageHtml refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.md'] });
    const res = makeStorageRes();

    await handleStorageHtml(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('handleStorageEncrypted refuses to serve the file when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue(DENIED_CONTEXT as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(DRAFT_ERROR);

    const req = makeStorageReq({ file: ['some', 'file.txt'] });
    const res = makeStorageRes();

    await handleStorageEncrypted(req, res);

    expect(checkDraftInContext).toHaveBeenCalledWith(DENIED_CONTEXT);
    expect(res.status).toHaveBeenCalledWith(503);
  });
});

// One SSO provider and the two form providers, as registered at startup
const AUTH_PROVIDERS: ProviderConfiguration[] = [
  { name: 'oidc', type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_OPENID, provider: 'oidc' },
  { name: 'local', type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LOCAL, provider: 'local' },
  { name: 'ldap', type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LDAP, provider: 'ldap' },
];
const registerAuthProviders = () => PROVIDERS.splice(0, PROVIDERS.length, ...AUTH_PROVIDERS);
const clearAuthProviders = () => PROVIDERS.splice(0, PROVIDERS.length);

const setupAuthRoutes = async () => {
  const routes = new Map<string, (req: any, res: any, next: any) => any>();
  // The routes are registered with their middlewares before the handler
  const register = vi.fn((path: unknown, ...handlers: any[]) => {
    if (typeof path === 'string') {
      routes.set(path, handlers[handlers.length - 1]);
    }
  });
  const app: any = { set: vi.fn(), use: vi.fn(), get: register, post: vi.fn(), delete: vi.fn(), put: vi.fn(), patch: vi.fn(), all: register };
  // createApp registers the archive format each time it is called: only the first registration is allowed
  vi.spyOn(archiver, 'registerFormat').mockImplementation((() => undefined) as any);
  await createApp(app, {} as any);
  const find = (suffix: string) => Array.from(routes.entries()).find(([path]) => path.endsWith(suffix))?.[1];
  return { login: find('/auth/:provider'), callback: find('/auth/:provider/callback') };
};

describe('httpPlatform: /auth/:provider/callback', () => {
  const loggedUser = { id: 'user-id', user_email: 'user@example.com' };
  const buildRequest = (provider: string) => ({ params: { provider }, query: {}, body: {}, session: { destroy: vi.fn() }, headers: {}, ip: '10.0.0.1' }) as any;
  const buildResponse = () => ({ redirect: vi.fn(), cookie: vi.fn() }) as any;

  beforeEach(() => {
    vi.clearAllMocks();
    registerAuthProviders();
    vi.mocked(sessionAuthenticateUser).mockResolvedValue(undefined as any);
    vi.spyOn(passport, '_strategy' as any).mockReturnValue({ logger: { error: vi.fn() } });
    vi.spyOn(passport, 'authenticate').mockImplementation(((_provider: string, _options: unknown, callback: any) => () => callback(null, loggedUser)) as any);
  });

  afterEach(() => {
    clearAuthProviders();
  });

  it('should authenticate the session of an SSO provider', async () => {
    const { callback } = await setupAuthRoutes();
    const req = buildRequest('oidc');
    const res = buildResponse();

    await callback?.(req, res, vi.fn());

    expect(sessionAuthenticateUser).toHaveBeenCalledWith(expect.anything(), req, loggedUser, 'oidc');
    expect(res.cookie).not.toHaveBeenCalled();
    expect(res.redirect).toHaveBeenCalledTimes(1);
  });

  // The form providers are served by the login form only
  it.each(['local', 'ldap', 'unknown'])('should refuse the %s provider', async (provider) => {
    const { callback } = await setupAuthRoutes();
    const res = buildResponse();

    await callback?.(buildRequest(provider), res, vi.fn());

    expect(passport.authenticate).not.toHaveBeenCalled();
    expect(sessionAuthenticateUser).not.toHaveBeenCalled();
    expect(res.cookie).toHaveBeenCalledWith('opencti_flash', 'Invalid authentication, please ask your administrator', expect.anything());
    expect(res.redirect).toHaveBeenCalledTimes(1);
  });
});

describe('httpPlatform: /auth/:provider', () => {
  const buildRequest = (provider: string) => ({ params: { provider }, query: {}, body: {}, session: {}, headers: {} }) as any;
  const buildResponse = () => ({ status: vi.fn().mockReturnThis(), send: vi.fn(), cookie: vi.fn() }) as any;

  beforeEach(() => {
    vi.clearAllMocks();
    registerAuthProviders();
    vi.spyOn(passport, '_strategy' as any).mockReturnValue({});
    vi.spyOn(passport, 'authenticate').mockImplementation((() => vi.fn()) as any);
  });

  afterEach(() => {
    clearAuthProviders();
  });

  it('should start the login of an SSO provider', async () => {
    const { login } = await setupAuthRoutes();
    const res = buildResponse();

    login?.(buildRequest('oidc'), res, vi.fn());

    expect(passport.authenticate).toHaveBeenCalledWith('oidc', expect.anything(), expect.any(Function));
    expect(res.status).not.toHaveBeenCalled();
  });

  // The form providers are served by the login form only
  it.each(['local', 'ldap', 'unknown'])('should refuse the %s provider', async (provider) => {
    const { login } = await setupAuthRoutes();
    const res = buildResponse();

    login?.(buildRequest(provider), res, vi.fn());

    expect(passport.authenticate).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });
});
