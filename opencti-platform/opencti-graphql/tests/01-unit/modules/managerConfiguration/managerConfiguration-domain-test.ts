import { describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { isGenericallyEditable, managerConfigurationEditField } from '../../../../src/modules/managerConfiguration/managerConfiguration-domain';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { CURATION_MANAGER_ID } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));

describe('generic edition of a manager configuration', () => {
  it('is authorized for the file indexing configuration only', () => {
    expect(isGenericallyEditable({ manager_id: 'FILE_INDEX_MANAGER' })).toBe(true);
    expect(isGenericallyEditable({ manager_id: CURATION_MANAGER_ID })).toBe(false);
    expect(isGenericallyEditable(undefined)).toBe(false);
  });

  it('refuses the configuration of another manager, written through the API of its manager', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'configuration-id', manager_id: CURATION_MANAGER_ID } as never);
    const input = [{ key: 'manager_setting', value: [{ field_authority_enabled: true }] }];
    await expect(managerConfigurationEditField({} as AuthContext, { id: 'user-id' } as AuthUser, 'configuration-id', input)).rejects.toThrow('not edited through this API');
  });
});
