import { afterEach, describe, expect, it, vi } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import xtmOneClient from '../../../../src/modules/xtm/one/xtm-one-client';
import { logApp } from '../../../../src/config/conf';
import { getHttpClient } from '../../../../src/utils/http-client';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  const settings: Record<string, string> = { 'xtm:xtm_one_url': 'http://xtm-one.test', 'xtm:xtm_one_token': 'platform-token' };
  return {
    ...actual,
    default: { ...actual.default, get: (key: string) => settings[key] ?? actual.default.get(key) },
    logApp: { ...actual.logApp, info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
});

vi.mock('../../../../src/domain/xtm-auth', () => ({
  issueXtmJwt: vi.fn(async () => 'jwt'),
}));

vi.mock('../../../../src/utils/http-client', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/utils/http-client')>(),
  getHttpClient: vi.fn(),
}));

describe('XTM One intent catalog', () => {
  afterEach(() => {
    vi.mocked(logApp.warn).mockClear();
  });

  it('should log a failed lookup as a warning with its sanitized failure, and report the failure to the caller', async () => {
    const failure = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    vi.mocked(getHttpClient).mockReturnValue({ get: vi.fn().mockRejectedValue(failure) } as never);
    const onFailure = vi.fn();
    const agents = await xtmOneClient.listAgentsForIntent({ user: { id: 'user-1' } } as AuthContext, 'cti.hunt_hypothesis', onFailure);
    expect(agents).toEqual([]);
    const sanitized = { status: null, code: 'ECONNREFUSED', detail: 'connect ECONNREFUSED' };
    expect(logApp.warn).toHaveBeenCalledWith('[XTM One] listAgentsForIntent failed', { failure: sanitized, intent: 'cti.hunt_hypothesis' });
    expect(logApp.error).not.toHaveBeenCalled();
    expect(onFailure).toHaveBeenCalledWith(sanitized);
  });

  it('should never log the bearer token the request of an HTTP error carries', async () => {
    const config = { headers: new AxiosHeaders({ Authorization: 'Bearer jwt-secret' }) };
    const failure = new AxiosError('Request failed with status code 503', 'ERR_BAD_RESPONSE', config as never, {}, {
      status: 503, statusText: 'Service Unavailable', headers: {}, config, data: { detail: 'catalog unavailable' },
    } as never);
    vi.mocked(getHttpClient).mockReturnValue({ get: vi.fn().mockRejectedValue(failure) } as never);
    await xtmOneClient.listAgentsForIntent({ user: { id: 'user-1' } } as AuthContext, 'cti.hunt_hypothesis');
    expect(logApp.warn).toHaveBeenCalledWith('[XTM One] listAgentsForIntent failed', {
      failure: { status: 503, code: 'ERR_BAD_RESPONSE', detail: 'catalog unavailable' },
      intent: 'cti.hunt_hypothesis',
    });
    expect(JSON.stringify(vi.mocked(logApp.warn).mock.calls)).not.toContain('jwt-secret');
  });
});
