import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  fullEntitiesOrRelationsList: vi.fn(),
  loadEntity: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  getRedisVersion: vi.fn(),
  notify: vi.fn(),
  setEditContext: vi.fn(),
}));
vi.mock('../../../src/database/cluster-module', () => ({ getClusterInformation: vi.fn() }));
vi.mock('../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../src/modules/theme/theme-domain', () => ({ findById: vi.fn() }));
vi.mock('../../../src/modules/xtm/one/xtm-one', () => ({
  getXtmOneRegistrationVersion: vi.fn(),
  refreshXtmLicenseProof: vi.fn(),
}));

const { patchAttribute, updateAttribute } = await import('../../../src/database/middleware');
const { settingsEditField } = await import('../../../src/domain/settings');

const context = { source: 'test' } as AuthContext;
const bypassUser = { id: 'user-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;

describe('settingsEditField, API Basic authentication', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  // Removing the value would read as enabled: only updateLocalAuth changes it
  it.each([
    ['enable it', [true]],
    ['remove it', []],
  ])('refuses to %s, even for BYPASS', async (_, value) => {
    await expect(settingsEditField(context, bypassUser, 'settings-id', [{ key: 'api_basic_auth_enabled', value }]))
      .rejects.toThrow('The API Basic authentication can only be changed with the local authentication settings');
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });
});
