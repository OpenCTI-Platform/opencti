import { beforeEach, describe, expect, it, vi } from 'vitest';

// The Settings entity is read through topEntitiesList (loadEntity), the entity settings and the themes through
// fullEntitiesList, a page of themes through pageEntitiesConnection, a theme through storeLoadById
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));
// The capabilities of a role are read through its relations
vi.mock('../../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/user/user-domain')>()),
  roleCapabilities: vi.fn(),
}));

import { fullEntitiesList, pageEntitiesConnection, topEntitiesList } from '../../../../src/database/middleware-loader';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import { CONFIG_PRESET_FAMILIES, configPresetItemFilePath, exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { builtInTheme, customTheme, otherCustomTheme, THEME_FILE_FIELDS } from './configPreset-themes-fixtures';
import { mockConfigPresetLoaders } from './configPreset-loaders-fixtures';
import { administratorRole, analystRole, ROLE_CAPABILITIES } from './configPreset-roles-fixtures';
import { roleCapabilities } from '../../../../src/modules/user/user-domain';

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
  platform_theme: customTheme.id,
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
    mockConfigPresetLoaders(entitySettings);
    vi.mocked(roleCapabilities).mockImplementation(async (_ctx, _user, roleId, type = 'has-capability') => {
      return ROLE_CAPABILITIES[roleId][type].map((name) => ({ id: `${name}-id`, name })) as never;
    });
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
      { id: 'platform', label: 'Platform configuration', description: 'Title, favicon, default theme, language', group: 'platformSettings', itemIds: ['platform'] },
      // The themes by name, without the built-in ones
      {
        id: 'branding',
        label: 'Branding',
        description: 'Themes, colors, logos',
        group: 'platformSettings',
        itemIds: [otherCustomTheme.standard_id, customTheme.standard_id],
      },
      { id: 'messages', label: 'Messages', description: 'Banner, login and consent messages', group: 'platformSettings', itemIds: ['banner', 'login', 'consent', 'noAccess'] },
      { id: 'hiddenEntityTypes', label: 'Hidden entity types', description: 'Entity types hidden in the platform', group: 'dataModel', itemIds: ['hiddenEntityTypes'] },
      // The roles by name, built-in ones included
      {
        id: 'roles',
        label: 'Roles',
        description: 'Roles and their capabilities',
        group: 'securityAccess',
        itemIds: [administratorRole.standard_id, analystRole.standard_id],
      },
    ]);
  });

  it('translates the static labels only, never a theme name', async () => {
    const items = await resolveAllItems();
    expect(items.map((item) => [item.label, item.translatable])).toEqual([
      ['Platform configuration', true],
      ['Customer ACME', false],
      ['SOC night', false],
      ['Banner', true],
      ['Login message', true],
      ['Consent message', true],
      ['No access message', true],
      ['Hidden entity types', true],
      ['Administrator', false],
      ['Analyst', false],
    ]);
  });

  it('writes one distinct JSON file per item, in the folder of its category, a theme by its standard id', async () => {
    const paths = (await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
      const items = await family.resolveItems(context, user, null, []);
      return items.map((item) => configPresetItemFilePath(family, item));
    }))).flat();
    expect(paths).toEqual([
      'platform_settings/platform.json',
      `platform_settings/branding/${otherCustomTheme.standard_id}.json`,
      `platform_settings/branding/${customTheme.standard_id}.json`,
      'platform_settings/messages/banner.json',
      'platform_settings/messages/login.json',
      'platform_settings/messages/consent.json',
      'platform_settings/messages/noAccess.json',
      'data_model/hidden_entity_types.json',
      `security_access/roles/${administratorRole.standard_id}.json`,
      `security_access/roles/${analystRole.standard_id}.json`,
    ]);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it('uses the file name of the item when it has one', async () => {
    const family = findFamily('platform');
    const item = await findItem('platform', 'platform');
    expect(configPresetItemFilePath(family, { ...item, fileName: 'custom-name.json' })).toBe('platform_settings/custom-name.json');
  });

  describe('platform configuration', () => {
    it('exports the allowlisted platform fields and the custom default theme it depends on', async () => {
      const item = await findItem('platform', 'platform');
      expect(item.dependsOn).toEqual([{ type: 'branding', id: customTheme.standard_id }]);
      expect(await exportConfigPresetItem(context, user, findFamily('platform'), item)).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'platformSettings.platform',
        id: 'platform',
        configuration: {
          platform_title: 'My platform',
          platform_favicon: 'https://example.com/favicon.ico',
          platform_language: 'fr-fr',
          default_theme: { standard_id: customTheme.standard_id, name: 'SOC night' },
        },
      });
    });

    it('references the default theme the dependency was computed with, even if the default changes afterwards', async () => {
      const [item] = await findFamily('platform').resolveItems(context, user, ['platform'], []);
      expect(item.dependsOn).toEqual([{ type: 'branding', id: customTheme.standard_id }]);
      withSettings({ platform_theme: otherCustomTheme.id });
      expect((await item.exporter(context, user)).default_theme).toEqual({ standard_id: customTheme.standard_id, name: 'SOC night' });
    });

    it('references a built-in default theme without depending on it', async () => {
      withSettings({ platform_theme: builtInTheme.id });
      const item = await findItem('platform', 'platform');
      expect(item.dependsOn).toEqual([]);
      expect((await item.exporter(context, user)).default_theme).toEqual({ standard_id: builtInTheme.standard_id, name: 'Filigran Dark' });
    });

    it('exports missing fields as null, no default theme included, to keep a stable file shape', async () => {
      for (const platformTheme of [undefined, 'deleted-theme-id']) {
        vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_title: 'Only title', platform_theme: platformTheme }] as never);
        const item = await findItem('platform', 'platform');
        expect(item.dependsOn).toEqual([]);
        expect(await item.exporter(context, user)).toEqual({ platform_title: 'Only title', platform_favicon: null, platform_language: null, default_theme: null });
      }
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
      withSettings({ platform_banner_text: '', platform_banner_level: null, platform_no_access_message: null, platform_consent_message: null, platform_consent_confirm_text: null });
      const messages = findFamily('messages');
      expect((await messages.resolveItems(context, user, null, [])).map((item) => item.id)).toEqual(['login']);
      const page = await messages.listItems(context, user, { first: 10 });
      expect(page.edges.map(({ node }) => node.id)).toEqual(['login']);
      expect(page.pageInfo.globalCount).toBe(1);
      expect(await messages.resolveItems(context, user, ['banner'], [])).toEqual([]);
    });

    it('does not count a level or a confirm text alone as a message', async () => {
      withSettings({ platform_login_message: null, platform_banner_text: null, platform_banner_level: 'GREEN', platform_consent_message: null, platform_consent_confirm_text: 'I agree', platform_no_access_message: '' });
      const messages = findFamily('messages');
      expect(await messages.resolveItems(context, user, null, [])).toEqual([]);
      expect((await messages.listItems(context, user, { first: 10 })).edges).toEqual([]);
      // The qualifier is exported with its message
      withSettings({ platform_banner_text: 'Maintenance', platform_banner_level: 'GREEN' });
      const [banner] = await messages.resolveItems(context, user, ['banner'], []);
      expect(await banner.exporter(context, user)).toEqual({ platform_banner_text: 'Maintenance', platform_banner_level: 'GREEN' });
    });

    it('pages the messages with the cursor of the last one', async () => {
      withSettings({ platform_banner_text: 'b', platform_login_message: 'l', platform_consent_message: 'c', platform_no_access_message: 'n' });
      const messages = findFamily('messages');
      const first = await messages.listItems(context, user, { first: 3 });
      expect(first.edges.map(({ node }) => node.id)).toEqual(['banner', 'login', 'consent']);
      expect(first.pageInfo).toMatchObject({ hasNextPage: true, endCursor: 'consent', globalCount: 4 });
      const next = await messages.listItems(context, user, { first: 3, after: first.pageInfo.endCursor });
      expect(next.edges.map(({ node }) => node.id)).toEqual(['noAccess']);
      expect(next.pageInfo).toMatchObject({ hasNextPage: false, globalCount: 4 });
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

  describe('branding', () => {
    const branding = findFamily('branding');
    const pageIds = async (args: Parameters<typeof branding.listItems>[2]) => (await branding.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a theme in the theme import format, with its standard id', async () => {
      const fullTheme = { ...customTheme, theme_login_aside_gradient_start: '#111111', theme_login_aside_gradient_end: '#222222', theme_login_aside_image: 'https://example.com/aside.png' };
      vi.mocked(fullEntitiesList).mockResolvedValueOnce([fullTheme] as never);
      const file = await exportConfigPresetItem(context, user, branding, await findItem('branding', customTheme.standard_id));
      expect(file).toMatchObject({ type: 'platformSettings.branding', id: customTheme.standard_id });
      expect(Object.keys(file.configuration).sort()).toEqual([...THEME_FILE_FIELDS].sort());
      expect(file.configuration).toMatchObject({ standard_id: customTheme.standard_id, name: 'SOC night', theme_logo: 'data:image/png;base64,AAAA', theme_logo_collapsed: '' });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|built_in|custom-theme-id/);
    });

    it('leaves the missing values of a theme out, so the import gives them their default', async () => {
      const file = await exportConfigPresetItem(context, user, branding, await findItem('branding', customTheme.standard_id));
      const emptyFields = ['theme_login_aside_gradient_start', 'theme_login_aside_gradient_end', 'theme_login_aside_image'];
      expect(Object.keys(file.configuration).sort()).toEqual(THEME_FILE_FIELDS.filter((field) => !emptyFields.includes(field)).sort());
    });

    it('opens the first page with the themes by name, and counts them', async () => {
      const page = await branding.listItems(context, user, { first: 1 });
      // The built-in themes are filtered out by the query, so the count and the pages do not include them
      const notBuiltIn = { mode: 'and', filters: [{ key: ['built_in'], values: ['true'], operator: 'not_eq' }], filterGroups: [] };
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['Theme'], { first: 1, after: undefined, search: undefined, orderBy: 'name', orderMode: 'asc', filters: notBuiltIn });
      expect(page.edges.map(({ node }) => node.id)).toEqual([otherCustomTheme.standard_id]);
      // The next page and its cursor come from the themes
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[0].cursor, globalCount: 2 });
      const all = await branding.listItems(context, user, { first: 10 });
      expect(all.pageInfo).toMatchObject({ hasNextPage: false, globalCount: 2 });
      expect(all.edges.map(({ node }) => [node.id, node.isDefault ?? false])).toEqual([[otherCustomTheme.standard_id, false], [customTheme.standard_id, true]]);
    });

    it('lists the themes after a cursor, still counting all of them', async () => {
      const page = await branding.listItems(context, user, { first: 2, after: 'cursor' });
      expect(vi.mocked(pageEntitiesConnection).mock.calls[0][3]).toMatchObject({ first: 2, after: 'cursor' });
      expect(page.pageInfo.globalCount).toBe(2);
    });

    it('applies search, ids and excluded ids to the themes', async () => {
      expect(await pageIds({ search: 'soc' })).toEqual([customTheme.standard_id]);
      expect((await branding.listItems(context, user, { search: 'soc' })).pageInfo.globalCount).toBe(1);
      // The built-in themes are not found by their name
      expect(await pageIds({ search: 'filigran' })).toEqual([]);
      expect(await pageIds({ ids: [customTheme.standard_id] })).toEqual([customTheme.standard_id]);
      expect(await pageIds({ excludedIds: [customTheme.standard_id] })).toEqual([otherCustomTheme.standard_id]);
      // A built-in theme is not an item, even when it is asked for
      expect(await pageIds({ ids: [builtInTheme.standard_id] })).toEqual([]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no theme query, whose empty filter would match every theme
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('marks the default theme', async () => {
      const page = await branding.listItems(context, user, {});
      expect(page.edges.filter(({ node }) => node.isDefault).map(({ node }) => node.id)).toEqual([customTheme.standard_id]);
    });

    it('resolves the themes to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await branding.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([otherCustomTheme.standard_id, customTheme.standard_id]);
      expect(await ids(null, [otherCustomTheme.standard_id])).toEqual([customTheme.standard_id]);
      // A built-in theme is not an item, even when it is asked for
      expect(await ids([customTheme.standard_id, builtInTheme.standard_id], [])).toEqual([customTheme.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  describe('roles', () => {
    const roles = findFamily('roles');
    const pageIds = async (args: Parameters<typeof roles.listItems>[2]) => (await roles.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a role in the role import format: its capabilities by name, sorted, and never its ids', async () => {
      const file = await exportConfigPresetItem(context, user, roles, await findItem('roles', analystRole.standard_id));
      expect(file).toMatchObject({ type: 'securityAccess.roles', id: analystRole.standard_id });
      expect(file.configuration).toEqual({
        name: 'Analyst',
        // A missing description or flag is written with its default, to keep a stable file shape
        description: '',
        can_manage_sensitive_config: false,
        capabilities: ['EXPLORE', 'KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'],
        capabilities_in_draft: ['KNOWLEDGE_KNUPDATE'],
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|analyst-role-id|-id"/);
    });

    it('exports a built-in role like any other', async () => {
      const file = await exportConfigPresetItem(context, user, roles, await findItem('roles', administratorRole.standard_id));
      expect(file.configuration).toMatchObject({ name: 'Administrator', capabilities: ['BYPASS'], capabilities_in_draft: [] });
    });

    it('opens the first page with the roles by name, and counts them', async () => {
      const page = await roles.listItems(context, user, { first: 1 });
      const noFilter = { mode: 'and', filters: [], filterGroups: [] };
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['Role'], { first: 1, after: undefined, search: undefined, orderBy: 'name', orderMode: 'asc', filters: noFilter });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[administratorRole.standard_id, 'Administrator', false]]);
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[0].cursor, globalCount: 2 });
    });

    it('applies search, ids and excluded ids to the roles', async () => {
      expect(await pageIds({ search: 'analy' })).toEqual([analystRole.standard_id]);
      expect(await pageIds({ ids: [analystRole.standard_id] })).toEqual([analystRole.standard_id]);
      expect(await pageIds({ excludedIds: [analystRole.standard_id] })).toEqual([administratorRole.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no role query, whose empty filter would match every role
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the roles to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await roles.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([administratorRole.standard_id, analystRole.standard_id]);
      expect(await ids(null, [administratorRole.standard_id])).toEqual([analystRole.standard_id]);
      expect(await ids([analystRole.standard_id], [])).toEqual([analystRole.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  it('pages a singleton category, filtered by ids, excluded ids and search', async () => {
    const platform = findFamily('platform');
    const ids = async (args: Parameters<typeof platform.listItems>[2]) => (await platform.listItems(context, user, args)).edges.map(({ node }) => node.id);
    expect((await platform.listItems(context, user, { first: 10 })).pageInfo).toMatchObject({ hasNextPage: false, globalCount: 1 });
    expect(await ids({ search: 'CONFIG' })).toEqual(['platform']);
    // The search does not apply to static items
    expect(await ids({ search: 'messages' })).toEqual(['platform']);
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
