import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import createApp from '../../../src/http/httpPlatform';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));
vi.mock('../../../src/http/httpServer-draft', () => ({
  checkDraftInContext: vi.fn(),
}));
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual: object = await importOriginal();
  return {
    ...actual,
    logApp: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  };
});

const TEST_PROVIDER = 'http-auth-provider-test';

type RouteHandler = (req: any, res: any, next: any) => unknown;

const setupAuthHandlers = async () => {
  const routes = new Map<string, RouteHandler>();
  const register = vi.fn((path: unknown, ...handlers: unknown[]) => {
    const handler = handlers[handlers.length - 1];
    if (typeof path === 'string' && typeof handler === 'function') {
      routes.set(path, handler as RouteHandler);
    }
  });
  const app: any = { set: vi.fn(), use: vi.fn(), get: register, all: register, post: vi.fn(), delete: vi.fn(), put: vi.fn(), patch: vi.fn() };
  await createApp(app, {} as any);
  const entries = Array.from(routes.entries());
  return {
    login: entries.find(([path]) => path.endsWith('/auth/:provider'))?.[1] as RouteHandler,
    callback: entries.find(([path]) => path.endsWith('/auth/:provider/callback'))?.[1] as RouteHandler,
  };
};

const buildResponse = () => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  res.cookie = vi.fn().mockReturnValue(res);
  res.redirect = vi.fn().mockReturnValue(res);
  return res;
};

const buildRequest = (provider: string, overrides: Record<string, unknown> = {}) => ({
  params: { provider },
  headers: { referer: 'http://localhost:4000/dashboard/search?term=abc' },
  query: {},
  body: {},
  session: {},
  ...overrides,
});

describe('httpPlatform: SSO login and callback routes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // @ts-expect-error _strategy is an undocumented passport API
    if (passport._strategy(TEST_PROVIDER)) {
      passport.unuse(TEST_PROVIDER);
    }
  });

  it('answers 404 with a warn log on the login route for an unknown provider', async () => {
    const { login } = await setupAuthHandlers();
    const res = buildResponse();
    const next = vi.fn();

    await login(buildRequest('unknown-provider'), res, next);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error' });
    expect(res.cookie).toHaveBeenCalledWith('opencti_flash', 'AUTH_ERROR', expect.any(Object));
    expect(logApp.warn).toHaveBeenCalledWith('Unknown authentication provider', { provider: 'unknown-provider' });
    expect(logApp.error).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('answers 404 with a warn log on the callback route for an unknown provider', async () => {
    const { callback } = await setupAuthHandlers();
    const res = buildResponse();
    const next = vi.fn();

    await callback(buildRequest('unknown-provider'), res, next);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ status: 'error' });
    expect(res.redirect).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledWith('Unknown authentication provider', { provider: 'unknown-provider' });
    expect(logApp.error).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('logs the provider and the cause when the login route fails', async () => {
    const failure = new TypeError('strategy failure');
    const strategy = new LocalStrategy(() => {});
    vi.spyOn(strategy, 'authenticate').mockImplementation(() => {
      throw failure;
    });
    passport.use(TEST_PROVIDER, strategy);
    const { login } = await setupAuthHandlers();
    const res = buildResponse();

    await login(buildRequest(TEST_PROVIDER), res, vi.fn());

    expect(logApp.error).toHaveBeenCalledWith('Error auth provider', { cause: failure, provider: TEST_PROVIDER });
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('relays the referer through RelayState for a SAML provider', async () => {
    const strategy = new SamlStrategy(
      {
        name: TEST_PROVIDER,
        callbackUrl: 'http://localhost:4000/auth/saml/callback',
        entryPoint: 'https://idp.example.com/sso',
        issuer: 'opencti-test',
        idpCert: 'not-a-real-certificate',
      },
      () => {},
      () => {},
    );
    const authenticate = vi.spyOn(strategy, 'authenticate').mockImplementation(() => {});
    // passport-saml declares its own Strategy type, not the @types/passport one
    passport.use(TEST_PROVIDER, strategy as unknown as passport.Strategy);
    const { login } = await setupAuthHandlers();
    const req = buildRequest(TEST_PROVIDER);

    await login(req, buildResponse(), vi.fn());

    expect(authenticate).toHaveBeenCalledTimes(1);
    expect(authenticate.mock.calls[0][1]).toMatchObject({ additionalParams: { RelayState: '/dashboard/search?term=abc' } });
    expect(req.session).not.toHaveProperty('referer');
  });

  it('keeps the referer in the session for a non SAML provider', async () => {
    const strategy = new LocalStrategy(() => {});
    const authenticate = vi.spyOn(strategy, 'authenticate').mockImplementation(() => {});
    passport.use(TEST_PROVIDER, strategy);
    const { login } = await setupAuthHandlers();
    const req = buildRequest(TEST_PROVIDER);

    await login(req, buildResponse(), vi.fn());

    expect(authenticate).toHaveBeenCalledTimes(1);
    expect(authenticate.mock.calls[0][1]).not.toHaveProperty('additionalParams');
    expect(req.session).toHaveProperty('referer', '/dashboard/search?term=abc');
  });
});
