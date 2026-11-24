import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Engine from '../../../../src/database/engine';
import { checkApiBasicAuthAllowed, isApiBasicAuthEnabled } from '../../../../src/modules/user/user-basic-auth';
import { authenticateUserByBasicAuth } from '../../../../src/modules/user/user-domain';
import { BYPASS, SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';
import type { BasicStoreSettings } from '../../../../src/types/settings';

vi.mock('../../../../src/database/cache');
vi.mock('../../../../src/database/redis'); // to prevent connection attempts
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elLoadBy: vi.fn(),
}));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

type BasicAuthSettings = Pick<BasicStoreSettings, 'api_basic_auth_enabled'>;

const USE_API_TOKEN = /use an API token/;

describe('API Basic authentication setting', () => {
  it('should refuse Basic auth when the setting is disabled', () => {
    expect(() => checkApiBasicAuthAllowed({ api_basic_auth_enabled: false })).toThrow(USE_API_TOKEN);
  });

  it('should accept Basic auth when the setting is enabled', () => {
    expect(() => checkApiBasicAuthAllowed({ api_basic_auth_enabled: true })).not.toThrow();
  });

  it('should read a missing setting as enabled, as on the platforms created before it', () => {
    const settings: BasicAuthSettings = {};
    expect(isApiBasicAuthEnabled(settings)).toBe(true);
    expect(() => checkApiBasicAuthAllowed(settings)).not.toThrow();
  });
});

describe('authenticateUserByBasicAuth with the setting', () => {
  const context = { user: SYSTEM_USER, req: {} } as unknown as AuthContext;
  const req = { headers: {}, ip: '127.0.0.1' } as Parameters<typeof authenticateUserByBasicAuth>[1];
  const BYPASS_USER = { id: 'bypass-user-id', user_email: 'bypass@opencti.io', capabilities: [{ name: BYPASS }] };
  const credentials = { username: BYPASS_USER.user_email, password: 'right-password' };

  const mockSettings = (settings: BasicAuthSettings) => {
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue(settings as never);
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[BYPASS_USER.id, BYPASS_USER]]) as never);
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // The refusal does not depend on the account: it comes before the account is even loaded, so BYPASS cannot get through
  it('should refuse a BYPASS user before loading the account or checking the password', async () => {
    mockSettings({ api_basic_auth_enabled: false });
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow(USE_API_TOKEN);
    // login() loads the user first: it was never reached, so the attempt is not counted either
    expect(Engine.elLoadBy).not.toHaveBeenCalled();
    expect(Cache.getEntitiesMapFromCache).not.toHaveBeenCalled();
  });

  it('should check the password when the setting is enabled', async () => {
    mockSettings({ api_basic_auth_enabled: true });
    // No user is found, so login() refuses the credentials
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow('Bad login or password');
    expect(Engine.elLoadBy).toHaveBeenCalled();
  });
});
