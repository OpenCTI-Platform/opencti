import { beforeEach, describe, expect, it, vi } from 'vitest';

const { config, mockGet } = vi.hoisted(() => ({ config: {} as Record<string, unknown>, mockGet: vi.fn() }));

vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => ({ get: mockGet })),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    TLS_REJECT_UNAUTHORIZED: true,
    default: { ...actual.default, get: (key: string) => (key in config ? config[key] : actual.default.get(key)) },
    booleanConf: (key: string, defaultValue: boolean) => {
      if (!(key in config)) return actual.booleanConf(key, defaultValue);
      return config[key] === true || config[key] === 'true';
    },
  };
});

import { getHttpClient } from '../../../src/utils/http-client';
import { enrichWithRemoteCredentials } from '../../../src/config/credentials';

const setCyberArkConfig = (extraConfig: Record<string, unknown> = {}) => {
  Object.keys(config).forEach((key) => delete config[key]);
  Object.assign(config, {
    'redis:credentials_provider:selector': 'cyberark',
    'redis:credentials_provider:cyberark:uri': 'https://cyberark.internal/api',
    'redis:credentials_provider:cyberark:field_targets': ['username', 'password'],
    ...extraConfig,
  });
};

describe('enrichWithRemoteCredentials TLS certificate verification', () => {
  beforeEach(() => {
    vi.mocked(getHttpClient).mockClear();
    mockGet.mockResolvedValue({ status: 200, data: { Content: 'user:secret' } });
  });

  it('should verify the CyberArk certificate when enabled globally', async () => {
    setCyberArkConfig();

    const result = await enrichWithRemoteCredentials('redis', {});

    expect(result).toEqual({ username: 'user', password: 'secret' });
    expect(getHttpClient).toHaveBeenCalledWith(expect.objectContaining({ rejectUnauthorized: true }));
  });

  it.each([false, 'false'])('should skip the certificate verification when reject_unauthorized is %s', async (rejectUnauthorized) => {
    setCyberArkConfig({ 'redis:credentials_provider:https_cert:reject_unauthorized': rejectUnauthorized });

    await enrichWithRemoteCredentials('redis', {});

    expect(getHttpClient).toHaveBeenCalledWith(expect.objectContaining({ rejectUnauthorized: false }));
  });
});
