import { beforeEach, describe, expect, it, vi } from 'vitest';

// The Settings entity is read through topEntitiesList (loadEntity), the entity settings through fullEntitiesList
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
}));

import { fullEntitiesList, topEntitiesList } from '../../../../src/database/middleware-loader';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import { CONFIG_PRESET_FAMILIES, configPresetItemFilePath, exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id' } as AuthUser;

// A Settings entity carrying, next to the exportable fields, values that must never be exported
const storedSettings = {
  id: 'settings-id',
  internal_id: 'settings-id',
  entity_type: 'Settings',
  platform_title: 'My platform',
  platform_favicon: 'https://example.com/favicon.ico',
  platform_language: 'fr-fr',
  platform_banner_text: 'Banner',
  platform_banner_level: 'RED',
  platform_login_message: 'Welcome',
  platform_consent_message: 'Consent',
  platform_consent_confirm_text: 'I agree',
  platform_no_access_message: 'No access',
  platform_theme: 'theme-id',
  platform_whitemark: true,
  enterprise_license: '-----BEGIN CERTIFICATE----- secret',
  platform_email: 'admin@example.com',
  otp_mandatory: true,
  cert_auth: { enabled: true },
  local_auth: { enabled: true },
};

const entitySettings = [
  { target_type: 'Malware', platform_hidden_type: true, enforce_reference: true, attributes_configuration: '[]' },
  { target_type: 'Report', platform_hidden_type: false },
  { target_type: 'Channel', platform_hidden_type: true },
];

const findFamily = (id: string) => CONFIG_PRESET_FAMILIES.find((family) => family.id === id)!;
const findItem = async (familyId: string, itemId: string) => (await findFamily(familyId).listItems(context, user)).find((item) => item.id === itemId)!;
const listAllItems = async () => (await Promise.all(CONFIG_PRESET_FAMILIES.map((family) => family.listItems(context, user)))).flat();

describe('Config preset registry', () => {
  beforeEach(() => {
    vi.mocked(topEntitiesList).mockResolvedValue([storedSettings] as never);
    vi.mocked(fullEntitiesList).mockResolvedValue(entitySettings as never);
  });

  it('lists the singleton categories in registry order, each in its export group, without theme and branding', async () => {
    const families = await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => ({
      id: family.id,
      label: family.label,
      group: family.group,
      itemIds: (await family.listItems(context, user)).map((item) => item.id),
    })));
    expect(families).toEqual([
      { id: 'platform', label: 'Platform configuration', group: { id: 'platformSettings', label: 'Platform settings' }, itemIds: ['platform'] },
      { id: 'messages', label: 'Messages', group: { id: 'platformSettings', label: 'Platform settings' }, itemIds: ['messages'] },
      { id: 'hiddenEntityTypes', label: 'Hidden entity types', group: { id: 'dataModel', label: 'Data model' }, itemIds: ['hiddenEntityTypes'] },
    ]);
    const allIds = [...CONFIG_PRESET_FAMILIES.map((family) => family.id), ...(await listAllItems()).map((item) => item.id)];
    expect(allIds.filter((id) => /theme|branding/i.test(id))).toEqual([]);
  });

  it('has translatable labels for every item', async () => {
    const items = await listAllItems();
    items.forEach((item) => {
      expect(item.translatable).toBe(true);
    });
  });

  it('writes one distinct JSON file per item, in the folder of its export group', async () => {
    const paths = (await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
      const items = await family.listItems(context, user);
      return items.map((item) => configPresetItemFilePath(family, item));
    }))).flat();
    expect(paths).toEqual([
      'platform_settings/platform.json',
      'platform_settings/messages.json',
      'data_model/hidden_entity_types.json',
    ]);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it('uses the file name of the item when it has one', async () => {
    const family = findFamily('platform');
    const item = await findItem('platform', 'platform');
    expect(configPresetItemFilePath(family, { ...item, fileName: 'custom-name.json' })).toBe('platform_settings/custom-name.json');
  });

  it('exports only the allowlisted platform fields', async () => {
    const file = await exportConfigPresetItem(context, user, findFamily('platform'), await findItem('platform', 'platform'));
    expect(file).toEqual({
      openCTI_version: PLATFORM_VERSION,
      type: 'platformSettings.platform',
      id: 'platform',
      configuration: {
        platform_title: 'My platform',
        platform_favicon: 'https://example.com/favicon.ico',
        platform_language: 'fr-fr',
      },
    });
  });

  it('exports only the allowlisted message fields', async () => {
    const file = await exportConfigPresetItem(context, user, findFamily('messages'), await findItem('messages', 'messages'));
    expect(file.type).toBe('platformSettings.messages');
    expect(file.id).toBe('messages');
    expect(file.configuration).toEqual({
      platform_banner_text: 'Banner',
      platform_banner_level: 'RED',
      platform_login_message: 'Welcome',
      platform_consent_message: 'Consent',
      platform_consent_confirm_text: 'I agree',
      platform_no_access_message: 'No access',
    });
  });

  it('exports missing settings fields as null to keep a stable file shape', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_title: 'Only title' }] as never);
    const item = await findItem('platform', 'platform');
    expect(await item.exporter(context, user)).toEqual({ platform_title: 'Only title', platform_favicon: null, platform_language: null });
  });

  it('exports the sorted list of hidden entity types only', async () => {
    const file = await exportConfigPresetItem(context, user, findFamily('hiddenEntityTypes'), await findItem('hiddenEntityTypes', 'hiddenEntityTypes'));
    expect(file.type).toBe('dataModel.hiddenEntityTypes');
    expect(file.id).toBe('hiddenEntityTypes');
    expect(file.configuration).toEqual({ hidden_entity_types: ['Channel', 'Malware'] });
  });

  it('never exports secret or license values', async () => {
    const files = await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
      const items = await family.listItems(context, user);
      return Promise.all(items.map((item) => exportConfigPresetItem(context, user, family, item)));
    }));
    const serialized = JSON.stringify(files);
    ['secret', 'enterprise_license', 'admin@example.com', 'cert_auth', 'local_auth', 'otp_mandatory', 'platform_theme', 'platform_whitemark'].forEach((forbidden) => {
      expect(serialized).not.toContain(forbidden);
    });
  });
});
