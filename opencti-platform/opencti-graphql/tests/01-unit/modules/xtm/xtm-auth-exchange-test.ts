import { describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  // The default configuration: an XTM One URL without a token (config/default.json).
  settings: { 'xtm:xtm_one_url': 'https://common.xtm1.filigran.io' } as Record<string, string | undefined>,
  getHttpClient: vi.fn(),
}));

vi.mock('../../../../src/config/conf', () => ({
  default: { get: (key: string) => mocks.settings[key] },
  getBaseUrl: () => 'https://opencti.example.com',
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../../../src/utils/http-client', () => ({ getHttpClient: mocks.getHttpClient }));
vi.mock('../../../../src/utils/platformCrypto', () => ({ getPlatformCrypto: vi.fn() }));
vi.mock('../../../../src/config/errors', () => ({ AuthenticationFailure: (message: string) => new Error(message) }));

import { exchangeXtmOneUserToken } from '../../../../src/domain/xtm-auth';

describe('exchangeXtmOneUserToken', () => {
  it('sends nothing to XTM One when the URL is set without xtm:xtm_one_token (the admin never opted in)', async () => {
    const token = await exchangeXtmOneUserToken({ id: 'alice', user_email: 'alice@example.com' }, 'https://crq.example.com');
    expect(token).toBeUndefined();
    expect(mocks.getHttpClient).not.toHaveBeenCalled();
  });
});
