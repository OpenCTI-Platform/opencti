import { describe, expect, it, vi } from 'vitest';
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
  it('should log a failed lookup as a warning with its cause, and report the failure to the caller', async () => {
    const failure = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    vi.mocked(getHttpClient).mockReturnValue({ get: vi.fn().mockRejectedValue(failure) } as never);
    const onFailure = vi.fn();
    const agents = await xtmOneClient.listAgentsForIntent({ user: { id: 'user-1' } } as AuthContext, 'cti.hunt_hypothesis', onFailure);
    expect(agents).toEqual([]);
    expect(logApp.warn).toHaveBeenCalledWith('[XTM One] listAgentsForIntent failed', { cause: failure, intent: 'cti.hunt_hypothesis' });
    expect(logApp.error).not.toHaveBeenCalled();
    expect(onFailure).toHaveBeenCalledWith({ status: null, code: 'ECONNREFUSED', detail: 'connect ECONNREFUSED' });
  });
});
