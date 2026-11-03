import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../../../src/domain/settings', () => ({ getSettingsFromDatabase: vi.fn() }));

import { getEntityFromCache } from '../../../../../src/database/cache';
import { getSettingsFromDatabase } from '../../../../../src/domain/settings';
import { checkConfigPresetImportAccess, getConfigPresetPlatformId } from '../../../../../src/modules/configPreset/import/configPreset-import-utils';
import { ENTITY_TYPE_SETTINGS } from '../../../../../src/schema/internalObject';
import { BYPASS, SYSTEM_USER } from '../../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

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

describe('checkConfigPresetImportAccess', () => {
  const bypassUser = { capabilities: [{ name: BYPASS }] } as unknown as AuthUser;

  it('lets a user with BYPASS through', () => {
    expect(() => checkConfigPresetImportAccess(context, bypassUser)).not.toThrow();
  });

  it('refuses a user without BYPASS', () => {
    const editor = { capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as unknown as AuthUser;
    expect(() => checkConfigPresetImportAccess(context, editor)).toThrow('You are not allowed to do this.');
  });

  it('refuses a draft context, set on the context or on the user', () => {
    expect(() => checkConfigPresetImportAccess({ ...context, draft_context: 'draft-id' }, bypassUser)).toThrow('Cannot import configuration presets in draft');
    expect(() => checkConfigPresetImportAccess(context, { ...bypassUser, draft_context: 'draft-id' })).toThrow('Cannot import configuration presets in draft');
  });
});
