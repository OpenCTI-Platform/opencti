import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const { mockStoreLoadById, mockUpdateAttribute } = vi.hoisted(() => ({
  mockStoreLoadById: vi.fn(),
  mockUpdateAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({ storeLoadById: mockStoreLoadById, fullEntitiesList: vi.fn() }));
vi.mock('../../../../src/database/middleware', () => ({ updateAttribute: mockUpdateAttribute, createEntity: vi.fn(), loadEntity: vi.fn(), patchAttribute: vi.fn() }));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  notify: vi.fn(async (_topic: string, element: unknown) => element),
}));

const { managerConfigurationEditField } = await import('../../../../src/modules/managerConfiguration/managerConfiguration-domain');

describe('managerConfigurationEditField', () => {
  const context = {} as AuthContext;
  const user = { id: 'user-1' } as AuthUser;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should refuse to edit the Source Intelligence configuration, edited through its own settings only', async () => {
    mockStoreLoadById.mockResolvedValue({ id: 'configuration-1', manager_id: 'SOURCE_INTELLIGENCE_MANAGER' });

    await expect(managerConfigurationEditField(context, user, 'configuration-1', [{ key: 'manager_setting', value: [{ autonomy: { enabled: true } }] }]))
      .rejects.toThrow('This manager configuration is edited through the settings of its module');
    expect(mockUpdateAttribute).not.toHaveBeenCalled();
  });

  it('should keep editing the configuration of the file indexing manager', async () => {
    mockStoreLoadById.mockResolvedValue({ id: 'configuration-2', manager_id: 'FILE_INDEX_MANAGER' });
    mockUpdateAttribute.mockResolvedValue({ element: { id: 'configuration-2', manager_id: 'FILE_INDEX_MANAGER' } });

    await expect(managerConfigurationEditField(context, user, 'configuration-2', [{ key: 'manager_running', value: [true] }]))
      .resolves.toMatchObject({ id: 'configuration-2' });
    expect(mockUpdateAttribute).toHaveBeenCalledTimes(1);
  });
});
