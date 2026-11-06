import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';
import { getBaseUrl } from '../../../../src/config/conf';
import * as settingsDomain from '../../../../src/domain/settings';
import { CERT_PROVIDER, registerCertStrategy } from '../../../../src/modules/authenticationProvider/provider-cert';
import { HEADERS_PROVIDER, registerHeadersStrategy } from '../../../../src/modules/authenticationProvider/provider-headers';
import type { AuthContext } from '../../../../src/types/user';

const MALICIOUS_REFERER = 'https://attacker.com//evil.example/phish';

const buildRequest = (referer: string) => ({ headers: { referer } }) as unknown as Request;

const buildResponse = () => {
  const res: any = {};
  res.cookie = vi.fn().mockReturnValue(res);
  res.redirect = vi.fn().mockReturnValue(res);
  return res as Response & { redirect: ReturnType<typeof vi.fn> };
};

const expectSameOriginRedirect = (res: { redirect: ReturnType<typeof vi.fn> }) => {
  expect(res.redirect).toHaveBeenCalledTimes(1);
  const target = res.redirect.mock.calls[0][0];
  const baseUrl = getBaseUrl();
  expect(new URL(target, baseUrl).origin).toBe(new URL(baseUrl).origin);
};

describe('Authentication providers: redirect after login', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(settingsDomain, 'getSettings').mockResolvedValue({
      cert_auth: { enabled: false },
      headers_auth: { enabled: false },
    } as any);
  });

  it('should keep cert login redirect on the platform origin when referer path starts with a double slash', async () => {
    await registerCertStrategy();
    const res = buildResponse();

    await CERT_PROVIDER?.reqLoginHandler?.(buildRequest(MALICIOUS_REFERER), res);

    expectSameOriginRedirect(res);
  });

  it('should keep headers login redirect on the platform origin when referer path starts with a double slash', async () => {
    await registerHeadersStrategy({} as AuthContext);
    const res = buildResponse();

    await HEADERS_PROVIDER?.reqLoginHandler?.(buildRequest(MALICIOUS_REFERER), res);

    expectSameOriginRedirect(res);
  });

  it('should redirect to the referer path when referer is on the platform', async () => {
    await registerCertStrategy();
    const res = buildResponse();

    await CERT_PROVIDER?.reqLoginHandler?.(buildRequest(`${getBaseUrl()}/dashboard?tab=1`), res);

    expect(res.redirect).toHaveBeenCalledWith('/dashboard?tab=1');
  });

  it('should redirect to the platform root when no referer is sent', async () => {
    await registerHeadersStrategy({} as AuthContext);
    const res = buildResponse();

    await HEADERS_PROVIDER?.reqLoginHandler?.({ headers: {} } as unknown as Request, res);

    expect(res.redirect).toHaveBeenCalledTimes(1);
    expect(new URL(res.redirect.mock.calls[0][0], getBaseUrl()).toString()).toBe(new URL('/', getBaseUrl()).toString());
  });
});
