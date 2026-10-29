import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../../../src/domain/settings', () => ({ getSettingsFromDatabase: vi.fn() }));

import { getEntityFromCache } from '../../../../../src/database/cache';
import { getSettingsFromDatabase } from '../../../../../src/domain/settings';
import { getConfigPresetPlatformId } from '../../../../../src/modules/configPreset/import/configPreset-import-utils';
import { ENTITY_TYPE_SETTINGS } from '../../../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../../../src/utils/access';
import type { AuthContext } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;

describe('getConfigPresetPlatformId', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('is the id of the settings from the cache: the polling of the wizard does not query the database', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ internal_id: 'platform-id' } as never);
    expect(await getConfigPresetPlatformId(context)).toEqual('platform-id');
    expect(getEntityFromCache).toHaveBeenCalledWith(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    expect(getSettingsFromDatabase).not.toHaveBeenCalled();
  });
});
