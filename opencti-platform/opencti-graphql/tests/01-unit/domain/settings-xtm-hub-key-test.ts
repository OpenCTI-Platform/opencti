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

describe('settingsEditField, XTM Hub key', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  // Only the XTM Hub enrollment writes them: another version would sign with a key XTM Hub does not hold
  it.each([
    ['xtm_hub_key_version', [2]],
    ['xtm_hub_key_enrolled_at', ['2026-01-01T00:00:00.000Z']],
  ])('refuses to edit %s, even for BYPASS', async (key, value) => {
    await expect(settingsEditField(context, bypassUser, 'settings-id', [{ key, value }]))
      .rejects.toThrow('The XTM Hub key settings cannot be edited');
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('refuses the whole patch when it mixes a key setting with an allowed one', async () => {
    await expect(settingsEditField(context, bypassUser, 'settings-id', [
      { key: 'platform_title', value: ['OpenCTI'] },
      { key: 'xtm_hub_key_version', value: [2] },
    ])).rejects.toThrow('The XTM Hub key settings cannot be edited');
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });
});
