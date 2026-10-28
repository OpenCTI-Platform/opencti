import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', () => ({ fullEntitiesList: vi.fn() }));
vi.mock('../../../../src/modules/entitySetting/entitySetting-domain', () => ({ entitySettingsEditField: vi.fn() }));
vi.mock('../../../../src/modules/entitySetting/entitySetting-utils', () => ({
  getAvailableSettings: (type: string) => {
    if (type === 'Broken') {
      throw new Error('This entity type is not support for entity settings');
    }
    return type === 'Unhideable' ? ['attributes_configuration'] : ['platform_hidden_type', 'attributes_configuration'];
  },
}));

import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { entitySettingsEditField } from '../../../../src/modules/entitySetting/entitySetting-domain';
import { importHiddenEntityTypes } from '../../../../src/modules/entitySetting/entitySetting-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };
const dryRun = { mode: ConfigImportMode.Overwrite, dryRun: true };

// Malware is visible, Report and Channel are hidden
const entitySettings = [
  { id: 'malware-id', target_type: 'Malware', platform_hidden_type: false },
  { id: 'report-id', target_type: 'Report', platform_hidden_type: true },
  { id: 'channel-id', target_type: 'Channel', platform_hidden_type: true },
  { id: 'unhideable-id', target_type: 'Unhideable', platform_hidden_type: false },
  { id: 'broken-id', target_type: 'Broken', platform_hidden_type: false },
];
const configuration = (...types: string[]) => ({ hidden_entity_types: types });

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(fullEntitiesList).mockResolvedValue(entitySettings as never);
});

describe('importHiddenEntityTypes', () => {
  it('hides the listed types and shows again the hidden ones that are not listed', async () => {
    const result = await importHiddenEntityTypes(context, user, configuration('Malware', 'Report'), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true, configuration: configuration('Malware', 'Report') });
    expect(entitySettingsEditField).toHaveBeenCalledTimes(2);
    expect(entitySettingsEditField).toHaveBeenCalledWith(context, user, ['malware-id'], [{ key: 'platform_hidden_type', value: [true] }]);
    expect(entitySettingsEditField).toHaveBeenCalledWith(context, user, ['channel-id'], [{ key: 'platform_hidden_type', value: [false] }]);
  });

  it('shows every hidden type again with an empty list, as the export of a platform that hides nothing', async () => {
    expect(await importHiddenEntityTypes(context, user, configuration(), overwrite)).toMatchObject({ status: 'overwritten' });
    expect(entitySettingsEditField).toHaveBeenCalledTimes(1);
    expect(entitySettingsEditField).toHaveBeenCalledWith(context, user, ['report-id', 'channel-id'], [{ key: 'platform_hidden_type', value: [false] }]);
  });

  it('decides the same on a dry run, and writes nothing', async () => {
    const real = await importHiddenEntityTypes(context, user, configuration('Malware'), overwrite);
    vi.mocked(entitySettingsEditField).mockClear();
    const dry = await importHiddenEntityTypes(context, user, configuration('Malware'), dryRun);
    expect(dry).toEqual(real);
    expect(entitySettingsEditField).not.toHaveBeenCalled();
  });

  it('skips a configuration that is the state of the platform, whatever the order and the repetitions of the list', async () => {
    expect(await importHiddenEntityTypes(context, user, configuration('Report', 'Channel', 'Report'), overwrite))
      .toMatchObject({ status: 'skipped', code: 'nothing_to_import', reason: 'Nothing to import' });
    expect(entitySettingsEditField).not.toHaveBeenCalled();
  });

  it('refuses all of it, writing nothing, when a type is unknown, has no hiding or is not supported', async () => {
    const result = await importHiddenEntityTypes(context, user, configuration('Malware', 'Missing', 'Unhideable', 'Broken'), overwrite);
    expect(result).toMatchObject({
      status: 'failed',
      code: 'cannot_be_hidden',
      reason: 'Entity types that cannot be hidden: Broken, Missing, Unhideable',
      configuration: configuration('Malware', 'Missing', 'Unhideable', 'Broken'),
    });
    expect(entitySettingsEditField).not.toHaveBeenCalled();
    // The same decision on a dry run
    expect(await importHiddenEntityTypes(context, user, configuration('Missing'), dryRun)).toMatchObject({ status: 'failed', code: 'cannot_be_hidden' });
  });

  it.each([
    ['a missing list', {}],
    ['a list that is not an array', { hidden_entity_types: 'Malware' }],
    ['a type that is not text', { hidden_entity_types: [1] }],
    ['an empty type name', { hidden_entity_types: [''] }],
    ['an unknown key', { hidden_entity_types: [], extra: true }],
  ])('refuses %s without reading the platform', async (_, invalid) => {
    expect(await importHiddenEntityTypes(context, user, invalid, overwrite)).toMatchObject({ status: 'failed', code: 'invalid', configuration: undefined });
    expect(fullEntitiesList).not.toHaveBeenCalled();
    expect(entitySettingsEditField).not.toHaveBeenCalled();
  });

  it('has no copy and no add: any mode but overwrite leaves it as it is', async () => {
    const results = await Promise.all([ConfigImportMode.Copy, ConfigImportMode.Add].map((mode) => importHiddenEntityTypes(context, user, configuration('Malware'), { mode })));
    results.forEach((result) => expect(result).toMatchObject({ status: 'skipped', code: 'not_overwrite', reason: 'Already exists' }));
    expect(entitySettingsEditField).not.toHaveBeenCalled();
  });
});
