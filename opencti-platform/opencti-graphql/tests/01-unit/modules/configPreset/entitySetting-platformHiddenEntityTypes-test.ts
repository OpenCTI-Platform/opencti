import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
}));

import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { getPlatformHiddenEntityTypes } from '../../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../../src/modules/entitySetting/entitySetting-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id' } as AuthUser;

describe('getPlatformHiddenEntityTypes', () => {
  beforeEach(() => {
    vi.mocked(fullEntitiesList).mockReset();
  });

  it('returns the sorted target types hidden for the whole platform, read with the given user', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([
      { target_type: 'Malware', platform_hidden_type: true },
      { target_type: 'Report', platform_hidden_type: false },
      { target_type: 'Indicator' },
      { target_type: 'Channel', platform_hidden_type: true },
    ] as never);
    expect(await getPlatformHiddenEntityTypes(context, user)).toEqual(['Channel', 'Malware']);
    expect(fullEntitiesList).toHaveBeenCalledWith(context, user, [ENTITY_TYPE_ENTITY_SETTING]);
  });

  it('returns an empty list when no entity type is hidden', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([{ target_type: 'Report', platform_hidden_type: false }] as never);
    expect(await getPlatformHiddenEntityTypes(context, user)).toEqual([]);
  });
});
