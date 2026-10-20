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
const findItem = async (familyId: string, itemId: string) => (await findFamily(familyId).resolveItems(context, user, [itemId], []))[0];
const resolveAllItems = async () => (await Promise.all(CONFIG_PRESET_FAMILIES.map((family) => family.resolveItems(context, user, null, [])))).flat();
const withSettings = (settings: Record<string, unknown>) => vi.mocked(topEntitiesList).mockResolvedValue([{ ...storedSettings, ...settings }] as never);

describe('Config preset registry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    withSettings({});
    vi.mocked(fullEntitiesList).mockResolvedValue(entitySettings as never);
  });

  it('lists the categories of the spec table in registry order, each in its export group', async () => {
    const families = await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => ({
      id: family.id,
      label: family.label,
      description: family.description,
      group: family.group.id,
      itemIds: (await family.resolveItems(context, user, null, [])).map((item) => item.id),
    })));
    expect(families).toEqual([
      { id: 'platform', label: 'Platform configuration', description: 'Title, favicon, language', group: 'platformSettings', itemIds: ['platform'] },
      { id: 'messages', label: 'Messages', description: 'Banner, login and consent messages', group: 'platformSettings', itemIds: ['banner', 'login', 'consent', 'noAccess'] },
      { id: 'hiddenEntityTypes', label: 'Hidden entity types', description: 'Entity types hidden in the platform', group: 'dataModel', itemIds: ['hiddenEntityTypes'] },
    ]);
  });

  it('translates the labels of every item', async () => {
    const items = await resolveAllItems();
    expect(items.map((item) => [item.label, item.translatable])).toEqual([
      ['Platform configuration', true],
      ['Banner', true],
      ['Login message', true],
      ['Consent message', true],
      ['No access message', true],
      ['Hidden entity types', true],
    ]);
  });

  it('writes one distinct JSON file per item, in the folder of its category', async () => {
    const paths = (await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
      const items = await family.resolveItems(context, user, null, []);
      return items.map((item) => configPresetItemFilePath(family, item));
    }))).flat();
    expect(paths).toEqual([
      'platform_settings/platform.json',
      'platform_settings/messages/banner.json',
      'platform_settings/messages/login.json',
      'platform_settings/messages/consent.json',
      'platform_settings/messages/noAccess.json',
      'data_model/hidden_entity_types.json',
    ]);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it('uses the file name of the item when it has one', async () => {
    const family = findFamily('platform');
    const item = await findItem('platform', 'platform');
    expect(configPresetItemFilePath(family, { ...item, fileName: 'custom-name.json' })).toBe('platform_settings/custom-name.json');
  });

  describe('platform configuration', () => {
    it('exports the allowlisted platform fields only', async () => {
      expect(await exportConfigPresetItem(context, user, findFamily('platform'), await findItem('platform', 'platform'))).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'platformSettings.platform',
        id: 'platform',
        configuration: { platform_title: 'My platform', platform_favicon: 'https://example.com/favicon.ico', platform_language: 'fr-fr' },
      });
    });

    it('exports missing fields as null, to keep a stable file shape', async () => {
      vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_title: 'Only title' }] as never);
      const item = await findItem('platform', 'platform');
      expect(await item.exporter(context, user)).toEqual({ platform_title: 'Only title', platform_favicon: null, platform_language: null });
    });
  });

  describe('messages', () => {
    it('exports each message with its allowlisted fields only', async () => {
      const family = findFamily('messages');
      const files = await Promise.all((await family.resolveItems(context, user, null, [])).map((item) => exportConfigPresetItem(context, user, family, item)));
      expect(files.map(({ type, id, configuration }) => ({ type, id, configuration }))).toEqual([
        { type: 'platformSettings.messages', id: 'banner', configuration: { platform_banner_text: 'Banner', platform_banner_level: 'RED' } },
        { type: 'platformSettings.messages', id: 'login', configuration: { platform_login_message: 'Welcome' } },
        { type: 'platformSettings.messages', id: 'consent', configuration: { platform_consent_message: 'Consent', platform_consent_confirm_text: 'I agree' } },
        { type: 'platformSettings.messages', id: 'noAccess', configuration: { platform_no_access_message: 'No access' } },
      ]);
    });

    it('neither lists nor exports a message that is not set, and keeps the ones that are', async () => {
      withSettings({ platform_banner_text: '', platform_banner_level: null, platform_no_access_message: null, platform_consent_message: null, platform_consent_confirm_text: 'I agree' });
      const messages = findFamily('messages');
      expect((await messages.resolveItems(context, user, null, [])).map((item) => item.id)).toEqual(['login', 'consent']);
      const page = await messages.listItems(context, user, { first: 10 });
      expect(page.edges.map(({ node }) => node.id)).toEqual(['login', 'consent']);
      expect(page.pageInfo.globalCount).toBe(2);
      // A message partly set is exported with its empty field
      const consent = (await messages.resolveItems(context, user, ['consent'], []))[0];
      expect(await consent.exporter(context, user)).toEqual({ platform_consent_message: null, platform_consent_confirm_text: 'I agree' });
      expect(await messages.resolveItems(context, user, ['banner'], [])).toEqual([]);
    });

    it('has no item when no message is set', async () => {
      withSettings({
        platform_banner_text: null,
        platform_banner_level: null,
        platform_login_message: '',
        platform_consent_message: null,
        platform_consent_confirm_text: null,
        platform_no_access_message: null,
      });
      const page = await findFamily('messages').listItems(context, user, { first: 10 });
      expect(page.edges).toEqual([]);
      expect(page.pageInfo.globalCount).toBe(0);
    });
  });

  it('exports the sorted list of hidden entity types only', async () => {
    const file = await exportConfigPresetItem(context, user, findFamily('hiddenEntityTypes'), await findItem('hiddenEntityTypes', 'hiddenEntityTypes'));
    expect(file).toMatchObject({ type: 'dataModel.hiddenEntityTypes', id: 'hiddenEntityTypes' });
    expect(file.configuration).toEqual({ hidden_entity_types: ['Channel', 'Malware'] });
  });

  it('pages a singleton category, filtered by ids, excluded ids and search', async () => {
    const platform = findFamily('platform');
    const ids = async (args: Parameters<typeof platform.listItems>[2]) => (await platform.listItems(context, user, args)).edges.map(({ node }) => node.id);
    expect((await platform.listItems(context, user, { first: 10 })).pageInfo).toMatchObject({ hasNextPage: false, globalCount: 1 });
    expect(await ids({ search: 'CONFIG' })).toEqual(['platform']);
    expect(await ids({ search: 'messages' })).toEqual([]);
    expect(await ids({ ids: ['platform'] })).toEqual(['platform']);
    expect(await ids({ ids: [] })).toEqual([]);
    expect(await ids({ excludedIds: ['platform'] })).toEqual([]);
  });

  it('never exports secret or license values', async () => {
    const files = await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
      const items = await family.resolveItems(context, user, null, []);
      return Promise.all(items.map((item) => exportConfigPresetItem(context, user, family, item)));
    }));
    const serialized = JSON.stringify(files);
    ['secret', 'enterprise_license', 'admin@example.com', 'cert_auth', 'local_auth', 'otp_mandatory', 'platform_theme', 'creator_id'].forEach((forbidden) => {
      expect(serialized).not.toContain(forbidden);
    });
  });
});
