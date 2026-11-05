import { beforeEach, describe, expect, it, vi } from 'vitest';

// The Settings entity is read through topEntitiesList (loadEntity), the entity settings and the themes through
// fullEntitiesList, a page of themes through pageEntitiesConnection, a theme through storeLoadById
// The values of an exclusion list are a file of the storage
vi.mock('../../../../src/database/raw-file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/raw-file-storage')>()),
  downloadFile: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
  fullRelationsList: vi.fn(),
  fullEntitiesThroughRelationsToList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));
// The markings of a group are read from the cache
vi.mock('../../../../src/database/cache', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/database/cache')>();
  const { ALL_MARKINGS } = await import('./configPreset-markings-fixtures');
  const markings = new Map(ALL_MARKINGS.flatMap((marking) => [[marking.id, marking], [marking.standard_id, marking]]));
  return {
    ...original,
    getEntitiesMapFromCache: vi.fn(async (ctx, usr, type) => (type === 'Marking-Definition' ? markings : original.getEntitiesMapFromCache(ctx, usr, type))),
  };
});
// The capabilities of a role are read through its relations
vi.mock('../../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/user/user-domain')>()),
  roleCapabilities: vi.fn(),
}));

import { fullEntitiesList, fullRelationsList, pageEntitiesConnection, storeLoadById, topEntitiesList } from '../../../../src/database/middleware-loader';
import { Readable } from 'node:stream';
import { downloadFile } from '../../../../src/database/raw-file-storage';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import { buildRefRelationKey } from '../../../../src/schema/general';
import { TEMPLATE_TASK_RELATION } from '../../../../src/modules/case/case-template/case-template-types';
import { CONFIG_PRESET_FAMILIES, configPresetItemFilePath, exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { builtInTheme, customTheme, otherCustomTheme, THEME_FILE_FIELDS } from './configPreset-themes-fixtures';
import { mockConfigPresetLoaders } from './configPreset-loaders-fixtures';
import { administratorRole, analystRole, ROLE_CAPABILITIES } from './configPreset-roles-fixtures';
import { administratorsGroup, analystsGroup } from './configPreset-groups-fixtures';
import { ALL_MARKINGS, customMarking, papRed, tlpAmber } from './configPreset-markings-fixtures';
import { BUILT_IN_MARKING_STANDARD_IDS } from '../../../../src/modules/markingDefinition/marking-import';
import { roleCapabilities } from '../../../../src/modules/user/user-domain';
import { customLabel, otherLabel } from './configPreset-labels-fixtures';
import { dnsExclusionList, retiredExclusionList } from './configPreset-exclusionLists-fixtures';
import { disarmKillChainPhase, killChainPhase, otherKillChainPhase } from './configPreset-killChainPhases-fixtures';
import { customVocabulary, modifiedVocabulary } from './configPreset-vocabularies-fixtures';
import { customStatusTemplate, defaultStatusTemplate } from './configPreset-statusTemplates-fixtures';
import { fraudCaseTemplate, phishingCaseTemplate } from './configPreset-caseTemplates-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id', capabilities: [{ name: 'BYPASS' }] } as AuthUser;

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
      { id: 'whitemark', label: 'Remove Filigran logos', description: '', group: 'platformSettings', itemIds: ['whitemark'] },
      { id: 'hiddenEntityTypes', label: 'Hidden entity types', description: 'Entity types hidden in the platform', group: 'dataModel', itemIds: ['hiddenEntityTypes'] },
      // The markings by definition, without the built-in ones
      {
        id: 'markings',
        label: 'Markings',
        description: 'Marking definitions, their colors and orders',
        group: 'securityAccess',
        itemIds: ALL_MARKINGS
          .filter(({ standard_id }) => !BUILT_IN_MARKING_STANDARD_IDS.includes(standard_id))
          .sort((a, b) => a.definition.localeCompare(b.definition))
          .map(({ standard_id }) => standard_id),
      },
      // The roles by name, built-in ones included
      {
        id: 'roles',
        label: 'Roles',
        description: 'Roles and their capabilities',
        group: 'securityAccess',
        itemIds: [administratorRole.standard_id, analystRole.standard_id],
      },
      // The groups by name, built-in ones included
      {
        id: 'groups',
        label: 'Groups',
        description: 'Groups with their roles, markings and confidence level',
        group: 'securityAccess',
        itemIds: [administratorsGroup.standard_id, analystsGroup.standard_id],
      },
      { id: 'policies', label: 'Policies', description: 'Password policy, users visibility and main organization', group: 'securityAccess', itemIds: ['policies'] },
      // The labels by value
      { id: 'labels', label: 'Labels', description: 'Labels and their colors', group: 'taxonomy', itemIds: [otherLabel.standard_id, customLabel.standard_id] },
      // The exclusion lists by name, in their own group
      {
        id: 'exclusionLists',
        label: 'Exclusion lists',
        description: 'Exclusion lists and their values',
        group: 'customization',
        itemIds: [dnsExclusionList.standard_id, retiredExclusionList.standard_id],
      },
      // By kill chain, then by order in the kill chain
      {
        id: 'killChainPhases',
        label: 'Kill chain phases',
        description: 'Kill chains, their phases and their order',
        group: 'taxonomy',
        itemIds: [disarmKillChainPhase.standard_id, otherKillChainPhase.standard_id, killChainPhase.standard_id],
      },
      // All the categories, by category
      {
        id: 'vocabularies',
        label: 'Vocabularies',
        description: 'Vocabulary categories and their entries',
        group: 'taxonomy',
        itemIds: ['case_severity_ov', 'incident_type_ov', 'integrity_level_ov', 'report_types_ov'],
      },
      // The status templates by name, the ones of the platform included
      {
        id: 'statusTemplates',
        label: 'Status templates',
        description: 'Status templates and their colors',
        group: 'taxonomy',
        itemIds: [customStatusTemplate.standard_id, defaultStatusTemplate.standard_id],
      },
      // The case templates by name
      {
        id: 'caseTemplates',
        label: 'Case templates',
        description: 'Case templates and their tasks',
        group: 'taxonomy',
        itemIds: [fraudCaseTemplate.standard_id, phishingCaseTemplate.standard_id],
      },
    ]);
  });

  it('marks as requiring the Enterprise Edition the families of an Enterprise Edition setting only', () => {
    expect(CONFIG_PRESET_FAMILIES.filter((family) => family.requiresEnterpriseEdition).map((family) => family.id)).toEqual(['whitemark']);
  });

  it('translates the static labels only, never a theme name, a label value, an exclusion list name, a phase name, a vocabulary entry, a status template or a case template name', async () => {
    const items = await resolveAllItems();
    expect(items.map((item) => [item.label, item.translatable])).toEqual([
      ['Platform configuration', true],
      ['Customer ACME', false],
      ['SOC night', false],
      ['Banner', true],
      ['Login message', true],
      ['Consent message', true],
      ['No access message', true],
      ['Remove Filigran logos', true],
      ['Hidden entity types', true],
      ['INTERNAL:SOC', false],
      ['PAP:RED', false],
      ['Administrator', false],
      ['Analyst', false],
      ['Administrators', false],
      ['Analysts', false],
      ['Policies', true],
      ['APT', false],
      ['tlp:amber', false],
      ['Public DNS resolvers', false],
      ['Retired partners', false],
      ['disarm: plan-strategy', false],
      ['mitre-attack: initial-access', false],
      ['mitre-attack: execution', false],
      ['case_severity_ov', false],
      ['incident_type_ov', false],
      ['integrity_level_ov', false],
      ['report_types_ov', false],
      ['Escalated', false],
      ['IN_PROGRESS', false],
      ['Fraud investigation', false],
      ['Phishing triage', false],
    ]);
  });

  it('writes one distinct JSON file per item, in the folder of its category, a theme, a label, an exclusion list, a phase, a status template or a case template by its standard id, a vocabulary category by its name', async () => {
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
      'platform_settings/whitemark.json',
      'data_model/hidden_entity_types.json',
      `security_access/markings/${customMarking.standard_id}.json`,
      `security_access/markings/${papRed.standard_id}.json`,
      `security_access/roles/${administratorRole.standard_id}.json`,
      `security_access/roles/${analystRole.standard_id}.json`,
      `security_access/groups/${administratorsGroup.standard_id}.json`,
      `security_access/groups/${analystsGroup.standard_id}.json`,
      'security_access/policies.json',
      `taxonomy/labels/${otherLabel.standard_id}.json`,
      `taxonomy/labels/${customLabel.standard_id}.json`,
      `customization/exclusion_lists/${dnsExclusionList.standard_id}.json`,
      `customization/exclusion_lists/${retiredExclusionList.standard_id}.json`,
      `taxonomy/kill_chain_phases/${disarmKillChainPhase.standard_id}.json`,
      `taxonomy/kill_chain_phases/${otherKillChainPhase.standard_id}.json`,
      `taxonomy/kill_chain_phases/${killChainPhase.standard_id}.json`,
      'taxonomy/vocabularies/case_severity_ov.json',
      'taxonomy/vocabularies/incident_type_ov.json',
      'taxonomy/vocabularies/integrity_level_ov.json',
      'taxonomy/vocabularies/report_types_ov.json',
      `taxonomy/status_templates/${customStatusTemplate.standard_id}.json`,
      `taxonomy/status_templates/${defaultStatusTemplate.standard_id}.json`,
      `taxonomy/case_templates/${fraudCaseTemplate.standard_id}.json`,
      `taxonomy/case_templates/${phishingCaseTemplate.standard_id}.json`,
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

  describe('whitemark', () => {
    it('exports the whitemark setting alone', async () => {
      const family = findFamily('whitemark');
      const item = await findItem('whitemark', 'whitemark');
      expect(await exportConfigPresetItem(context, user, family, item)).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'platformSettings.whitemark',
        id: 'whitemark',
        configuration: { platform_whitemark: true },
      });
    });

    it.each([[true, true], [false, false], [undefined, null], [null, null]])('lists the whitemark %s as enabled: %s, a setting that is not set being neither', async (platformWhitemark, isEnabled) => {
      withSettings({ platform_whitemark: platformWhitemark });
      expect((await findItem('whitemark', 'whitemark')).isEnabled).toBe(isEnabled);
    });

    it('exports a whitemark that is not set as null, to keep a stable file shape', async () => {
      withSettings({ platform_whitemark: undefined });
      expect(await (await findItem('whitemark', 'whitemark')).exporter(context, user)).toEqual({ platform_whitemark: null });
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

  describe('labels', () => {
    const labels = findFamily('labels');
    const pageIds = async (args: Parameters<typeof labels.listItems>[2]) => (await labels.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a label in the label import format only: its value and its color', async () => {
      const file = await exportConfigPresetItem(context, user, labels, await findItem('labels', customLabel.standard_id));
      expect(file).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'taxonomy.labels',
        id: customLabel.standard_id,
        configuration: { value: 'tlp:amber', color: '#ffc107' },
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|custom-label-id/);
    });

    it('leaves a missing color out, so the import gives the label its own', async () => {
      vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ ...customLabel, color: null }] as never);
      const file = await exportConfigPresetItem(context, user, labels, await findItem('labels', customLabel.standard_id));
      expect(file.configuration).toEqual({ value: 'tlp:amber' });
    });

    it('opens the first page with the labels by value, and counts them', async () => {
      const page = await labels.listItems(context, user, { first: 1 });
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['Label'], {
        first: 1,
        after: undefined,
        search: undefined,
        orderBy: 'value',
        orderMode: 'asc',
        filters: { mode: 'and', filters: [], filterGroups: [] },
      });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[otherLabel.standard_id, 'APT', false]]);
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[0].cursor, globalCount: 2 });
      const all = await labels.listItems(context, user, { first: 10 });
      expect(all.pageInfo).toMatchObject({ hasNextPage: false, globalCount: 2 });
    });

    it('applies search, ids and excluded ids to the labels', async () => {
      expect(await pageIds({ search: 'tlp' })).toEqual([customLabel.standard_id]);
      expect(await pageIds({ ids: [otherLabel.standard_id] })).toEqual([otherLabel.standard_id]);
      expect(await pageIds({ excludedIds: [otherLabel.standard_id] })).toEqual([customLabel.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no label query, whose empty filter would match every label
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the labels to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await labels.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([otherLabel.standard_id, customLabel.standard_id]);
      expect(await ids(null, [otherLabel.standard_id])).toEqual([customLabel.standard_id]);
      expect(await ids([customLabel.standard_id], [])).toEqual([customLabel.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  describe('exclusion lists', () => {
    const lists = findFamily('exclusionLists');
    const pageIds = async (args: Parameters<typeof lists.listItems>[2]) => (await lists.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports an exclusion list in the import format only, and points to its values file next to it', async () => {
      const file = await exportConfigPresetItem(context, user, lists, await findItem('exclusionLists', dnsExclusionList.standard_id));
      expect(file).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'customization.exclusionLists',
        id: dnsExclusionList.standard_id,
        configuration: { name: 'Public DNS resolvers', description: 'Well-known resolvers', enabled: true, exclusion_list_entity_types: ['IPv4-Addr'] },
        attachment: `customization/exclusion_lists/${dnsExclusionList.standard_id}.txt`,
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|dns-exclusion-list-id|exclusionLists\/|values_count|file_size/);
    });

    it('exports a disabled list without description with its state and its types', async () => {
      const file = await exportConfigPresetItem(context, user, lists, await findItem('exclusionLists', retiredExclusionList.standard_id));
      expect(file.configuration).toEqual({ name: 'Retired partners', enabled: false, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] });
    });

    it('reads the values of a list byte for byte from the storage, by the file of the list', async () => {
      const bytes = Buffer.from('8.8.8.8\r\n1.1.1.1\n\u00e9\n');
      vi.mocked(downloadFile).mockResolvedValue(Readable.from([bytes.subarray(0, 5), bytes.subarray(5)]) as never);
      const item = await findItem('exclusionLists', dnsExclusionList.standard_id);
      expect(item.attachment?.name).toBe(`${dnsExclusionList.standard_id}.txt`);
      expect(await item.attachment!.read(context, user)).toEqual(bytes);
      expect(downloadFile).toHaveBeenCalledWith(dnsExclusionList.file_id);
    });

    it('refuses to export a list whose file is missing from the storage, instead of exporting it without its values', async () => {
      vi.mocked(downloadFile).mockResolvedValue(null);
      const item = await findItem('exclusionLists', dnsExclusionList.standard_id);
      await expect(item.attachment!.read(context, user)).rejects.toThrow('The file of the values of an exclusion list is missing from the storage');
    });

    it('opens the first page with the exclusion lists by name, and counts them', async () => {
      const page = await lists.listItems(context, user, { first: 1 });
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['ExclusionList'], {
        first: 1,
        after: undefined,
        search: undefined,
        orderBy: 'name',
        orderMode: 'asc',
        filters: { mode: 'and', filters: [], filterGroups: [] },
      });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[dnsExclusionList.standard_id, 'Public DNS resolvers', false]]);
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[0].cursor, globalCount: 2 });
    });

    it('applies search, ids and excluded ids to the exclusion lists', async () => {
      expect(await pageIds({ search: 'retired' })).toEqual([retiredExclusionList.standard_id]);
      expect(await pageIds({ ids: [dnsExclusionList.standard_id] })).toEqual([dnsExclusionList.standard_id]);
      expect(await pageIds({ excludedIds: [dnsExclusionList.standard_id] })).toEqual([retiredExclusionList.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no query, whose empty filter would match every list
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the exclusion lists to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await lists.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([dnsExclusionList.standard_id, retiredExclusionList.standard_id]);
      expect(await ids(null, [dnsExclusionList.standard_id])).toEqual([retiredExclusionList.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  describe('kill chain phases', () => {
    const phases = findFamily('killChainPhases');
    const pageIds = async (args: Parameters<typeof phases.listItems>[2]) => (await phases.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a phase in the phase import format only: its names and its order', async () => {
      const file = await exportConfigPresetItem(context, user, phases, await findItem('killChainPhases', killChainPhase.standard_id));
      expect(file).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'taxonomy.killChainPhases',
        id: killChainPhase.standard_id,
        configuration: { kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 2 },
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|phase-id"/);
    });

    it('exports an order of 0, which is an order, and leaves a missing one out', async () => {
      const [first] = await phases.resolveItems(context, user, [disarmKillChainPhase.standard_id], []);
      expect(await first.exporter(context, user)).toEqual({ kill_chain_name: 'disarm', phase_name: 'plan-strategy', x_opencti_order: 0 });
      vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ ...killChainPhase, x_opencti_order: null }] as never);
      const [second] = await phases.resolveItems(context, user, [killChainPhase.standard_id], []);
      expect(await second.exporter(context, user)).toEqual({ kill_chain_name: 'mitre-attack', phase_name: 'execution' });
    });

    it('opens the first page with the phases by kill chain then by order, and counts them', async () => {
      const page = await phases.listItems(context, user, { first: 2 });
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['Kill-Chain-Phase'], {
        first: 2,
        after: undefined,
        search: undefined,
        orderBy: ['kill_chain_name', 'x_opencti_order'],
        orderMode: 'asc',
        filters: { mode: 'and', filters: [], filterGroups: [] },
      });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([
        [disarmKillChainPhase.standard_id, 'disarm: plan-strategy', false],
        [otherKillChainPhase.standard_id, 'mitre-attack: initial-access', false],
      ]);
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[1].cursor, globalCount: 3 });
    });

    it('applies search, ids and excluded ids to the phases', async () => {
      expect(await pageIds({ search: 'execution' })).toEqual([killChainPhase.standard_id]);
      expect(await pageIds({ ids: [otherKillChainPhase.standard_id] })).toEqual([otherKillChainPhase.standard_id]);
      expect(await pageIds({ excludedIds: [disarmKillChainPhase.standard_id, killChainPhase.standard_id] })).toEqual([otherKillChainPhase.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no phase query, whose empty filter would match every phase
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the phases to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await phases.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([disarmKillChainPhase.standard_id, otherKillChainPhase.standard_id, killChainPhase.standard_id]);
      expect(await ids(null, [disarmKillChainPhase.standard_id])).toEqual([otherKillChainPhase.standard_id, killChainPhase.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  describe('vocabularies', () => {
    const vocabularies = findFamily('vocabularies');
    const pageIds = async (args: Parameters<typeof vocabularies.listItems>[2]) => (await vocabularies.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a category with all its entries, in the vocabulary import format only', async () => {
      const file = await exportConfigPresetItem(context, user, vocabularies, await findItem('vocabularies', 'report_types_ov'));
      // The entry of the platform nobody modified (threat-report) is in it, the category of the entries is the one of the file
      expect(file).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'taxonomy.vocabularies',
        id: 'report_types_ov',
        configuration: {
          category: 'report_types_ov',
          entries: [
            { name: 'threat-report', description: '', aliases: [], order: 0 },
            { name: 'fimi-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 },
          ],
        },
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|builtIn|custom-vocabulary-id|vocabulary--/);
    });

    it('exports an entry of the platform that was modified, with its values', async () => {
      const [category] = await vocabularies.resolveItems(context, user, ['integrity_level_ov'], []);
      expect(await category.exporter(context, user)).toEqual({
        category: 'integrity_level_ov',
        entries: [{ name: 'high', description: 'Our own description of a high integrity', aliases: ['elevated'], order: 3 }],
      });
    });

    it('exports an empty description, no aliases and an order of 0, which are values, and leaves a missing one out', async () => {
      const [category] = await vocabularies.resolveItems(context, user, ['case_severity_ov'], []);
      expect(await category.exporter(context, user)).toEqual({ category: 'case_severity_ov', entries: [{ name: 'sev-x', description: '', aliases: [], order: 0 }] });
      vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ ...customVocabulary, description: null, order: undefined }] as never);
      const [missing] = await vocabularies.resolveItems(context, user, ['report_types_ov'], []);
      expect(await missing.exporter(context, user)).toEqual({ category: 'report_types_ov', entries: [{ name: 'fimi-report', aliases: ['fimi'] }] });
    });

    it('lists all the categories, by name, and counts them', async () => {
      const page = await vocabularies.listItems(context, user, { first: 2 });
      expect(fullEntitiesList).toHaveBeenCalledWith(context, user, ['Vocabulary'], { orderBy: ['category', 'order', 'name'], orderMode: 'asc' });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([
        ['case_severity_ov', 'case_severity_ov', false],
        ['incident_type_ov', 'incident_type_ov', false],
      ]);
      // The category of the entry nobody modified (incident_type_ov) is listed and counted like the others
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: 'incident_type_ov', globalCount: 4 });
      const next = await vocabularies.listItems(context, user, { first: 2, after: page.pageInfo.endCursor });
      expect(next.edges.map(({ node }) => node.id)).toEqual(['integrity_level_ov', 'report_types_ov']);
      expect(next.pageInfo).toMatchObject({ hasNextPage: false, globalCount: 4 });
    });

    it('lists a category once, whatever its number of entries', async () => {
      vi.mocked(fullEntitiesList).mockResolvedValueOnce([modifiedVocabulary, customVocabulary, { ...customVocabulary, name: 'second-custom' }] as never);
      expect(await pageIds({})).toEqual(['integrity_level_ov', 'report_types_ov']);
    });

    it('applies search, ids and excluded ids to the categories', async () => {
      expect(await pageIds({ search: 'REPORT' })).toEqual(['report_types_ov']);
      expect(await pageIds({ search: 'integrity' })).toEqual(['integrity_level_ov']);
      // A category without entry is not an item, even when it is asked for
      expect(await pageIds({ ids: ['incident_type_ov', 'report_types_ov', 'opinion_ov'] })).toEqual(['incident_type_ov', 'report_types_ov']);
      expect(await pageIds({ excludedIds: ['report_types_ov', 'case_severity_ov'] })).toEqual(['incident_type_ov', 'integrity_level_ov']);
      expect(await pageIds({ ids: [] })).toEqual([]);
    });

    it('resolves the categories to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await vocabularies.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual(['case_severity_ov', 'incident_type_ov', 'integrity_level_ov', 'report_types_ov']);
      expect(await ids(null, ['integrity_level_ov'])).toEqual(['case_severity_ov', 'incident_type_ov', 'report_types_ov']);
      expect(await ids(['report_types_ov', 'incident_type_ov', 'opinion_ov'], [])).toEqual(['incident_type_ov', 'report_types_ov']);
      expect(await ids([], [])).toEqual([]);
    });
  });

  describe('status templates', () => {
    const templates = findFamily('statusTemplates');
    const pageIds = async (args: Parameters<typeof templates.listItems>[2]) => (await templates.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a status template in the import format only: its name and its color', async () => {
      const file = await exportConfigPresetItem(context, user, templates, await findItem('statusTemplates', customStatusTemplate.standard_id));
      expect(file).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'taxonomy.statusTemplates',
        id: customStatusTemplate.standard_id,
        configuration: { name: 'Escalated', color: '#e91e63' },
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|escalated-template-id/);
    });

    it('opens the first page with the status templates by name, the ones of the platform included, and counts them', async () => {
      const page = await templates.listItems(context, user, { first: 1 });
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['StatusTemplate'], {
        first: 1,
        after: undefined,
        search: undefined,
        orderBy: 'name',
        orderMode: 'asc',
        filters: { mode: 'and', filters: [], filterGroups: [] },
      });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[customStatusTemplate.standard_id, 'Escalated', false]]);
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[0].cursor, globalCount: 2 });
    });

    it('applies search, ids and excluded ids to the status templates', async () => {
      expect(await pageIds({ search: 'progress' })).toEqual([defaultStatusTemplate.standard_id]);
      expect(await pageIds({ ids: [customStatusTemplate.standard_id] })).toEqual([customStatusTemplate.standard_id]);
      expect(await pageIds({ excludedIds: [customStatusTemplate.standard_id] })).toEqual([defaultStatusTemplate.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no query, whose empty filter would match every template
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the status templates to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await templates.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([customStatusTemplate.standard_id, defaultStatusTemplate.standard_id]);
      expect(await ids(null, [customStatusTemplate.standard_id])).toEqual([defaultStatusTemplate.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  describe('case templates', () => {
    const templates = findFamily('caseTemplates');
    const pageIds = async (args: Parameters<typeof templates.listItems>[2]) => (await templates.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a case template with its tasks by name, in the import format only, and takes its random id as the id of the item', async () => {
      const file = await exportConfigPresetItem(context, user, templates, await findItem('caseTemplates', phishingCaseTemplate.standard_id));
      expect(file).toEqual({
        openCTI_version: PLATFORM_VERSION,
        type: 'taxonomy.caseTemplates',
        id: phishingCaseTemplate.standard_id,
        configuration: {
          name: 'Phishing triage',
          description: 'Triage of a phishing report',
          // By name, and a task without description has none
          tasks: [{ name: 'Block sender', description: 'Block the sender domain' }, { name: 'Notify users' }],
        },
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|case-template-id|task-id|task-template--/);
    });

    it('exports a case template without description and without task as a name and an empty list of tasks', async () => {
      const file = await exportConfigPresetItem(context, user, templates, await findItem('caseTemplates', fraudCaseTemplate.standard_id));
      expect(file.configuration).toEqual({ name: 'Fraud investigation', tasks: [] });
    });

    it('reads the tasks of the template the way the platform reads them to create the tasks of a case', async () => {
      await exportConfigPresetItem(context, user, templates, await findItem('caseTemplates', phishingCaseTemplate.standard_id));
      expect(fullEntitiesList).toHaveBeenCalledWith(context, user, ['Task-Template'], {
        filters: { mode: 'and', filters: [{ key: [buildRefRelationKey(TEMPLATE_TASK_RELATION)], values: [phishingCaseTemplate.id] }], filterGroups: [] },
      });
    });

    it('opens the first page with the case templates by name, and counts them', async () => {
      const page = await templates.listItems(context, user, { first: 1 });
      expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, ['Case-Template'], {
        first: 1,
        after: undefined,
        search: undefined,
        orderBy: 'name',
        orderMode: 'asc',
        filters: { mode: 'and', filters: [], filterGroups: [] },
      });
      expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[fraudCaseTemplate.standard_id, 'Fraud investigation', false]]);
      expect(page.pageInfo).toMatchObject({ hasNextPage: true, endCursor: page.edges[0].cursor, globalCount: 2 });
    });

    it('applies search, ids and excluded ids to the case templates', async () => {
      expect(await pageIds({ search: 'phishing' })).toEqual([phishingCaseTemplate.standard_id]);
      expect(await pageIds({ ids: [fraudCaseTemplate.standard_id] })).toEqual([fraudCaseTemplate.standard_id]);
      expect(await pageIds({ excludedIds: [fraudCaseTemplate.standard_id] })).toEqual([phishingCaseTemplate.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no query, whose empty filter would match every template
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the case templates to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await templates.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([fraudCaseTemplate.standard_id, phishingCaseTemplate.standard_id]);
      expect(await ids(null, [fraudCaseTemplate.standard_id])).toEqual([phishingCaseTemplate.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
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

  describe('markings', () => {
    const markings = findFamily('markings');

    it('exports a marking with its definition, color and order, never its ids nor its creator', async () => {
      const file = await exportConfigPresetItem(context, user, markings, await findItem('markings', customMarking.standard_id));
      expect(file).toMatchObject({ type: 'securityAccess.markings', id: customMarking.standard_id });
      expect(file.configuration).toEqual({ definition_type: 'INTERNAL', definition: 'INTERNAL:SOC', x_opencti_color: '#123456', x_opencti_order: 7 });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|custom-marking-id/);
    });

    it('never lists nor resolves a built-in marking', async () => {
      const listed = (await markings.listItems(context, user, { first: 10 })).edges.map(({ node }) => node.id);
      expect(listed).toContain(customMarking.standard_id);
      expect(listed).not.toContain(tlpAmber.standard_id);
      expect(await markings.resolveItems(context, user, [tlpAmber.standard_id], [])).toEqual([]);
    });
  });

  describe('groups', () => {
    const groups = findFamily('groups');
    const pageIds = async (args: Parameters<typeof groups.listItems>[2]) => (await groups.listItems(context, user, args)).edges.map(({ node }) => node.id);

    it('exports a group in the group import format: its roles and markings by standard id, never its ids nor its members', async () => {
      const file = await exportConfigPresetItem(context, user, groups, await findItem('groups', administratorsGroup.standard_id));
      expect(file).toMatchObject({ type: 'securityAccess.groups', id: administratorsGroup.standard_id });
      const amber = { standard_id: tlpAmber.standard_id, definition_type: 'TLP', definition: 'TLP:AMBER' };
      const red = { standard_id: papRed.standard_id, definition_type: 'PAP', definition: 'PAP:RED' };
      expect(file.configuration).toEqual({
        name: 'Administrators',
        description: 'Administrator group',
        default_assignation: false,
        auto_integration_assignation: [],
        no_creators: false,
        restrict_delete: true,
        auto_new_marking: true,
        group_confidence_level: { max_confidence: 100, overrides: [{ entity_type: 'Report', max_confidence: 80 }] },
        default_hidden_types: ['Channel', 'Malware'],
        default_dashboard: null,
        roles: [{ standard_id: administratorRole.standard_id, name: 'Administrator' }],
        allowed_markings: [amber, red].sort((a, b) => a.standard_id.localeCompare(b.standard_id)),
        // A default marking that no longer exists is left out
        default_marking: [{ entity_type: 'GLOBAL', values: [amber] }],
        max_shareable_markings: [{ type: 'TLP', value: amber }, { type: 'PAP', value: 'none' }, { type: 'Deleted', value: 'none' }],
      });
      expect(JSON.stringify(file)).not.toMatch(/creator-secret-id|created_at|-group-id|-role-id|tlp-amber-id|deleted-marking-id/);
    });

    it('exports a group with none of the optional values set with their defaults, to keep a stable file shape', async () => {
      const file = await exportConfigPresetItem(context, user, groups, await findItem('groups', analystsGroup.standard_id));
      expect(file.configuration).toMatchObject({
        description: '',
        default_assignation: false,
        auto_integration_assignation: [],
        group_confidence_level: null,
        default_hidden_types: [],
        default_dashboard: null,
        allowed_markings: [],
        default_marking: [],
        max_shareable_markings: [],
      });
    });

    it('depends on its roles, read once for the groups of a page, its markings too', async () => {
      const page = await groups.listItems(context, user, { first: 10 });
      expect(page.edges.map(({ node }) => [node.id, node.dependsOn])).toEqual([
        [administratorsGroup.standard_id, [{ type: 'roles', id: administratorRole.standard_id }]],
        [analystsGroup.standard_id, [{ type: 'roles', id: analystRole.standard_id }]],
      ]);
      expect(fullRelationsList).toHaveBeenCalledTimes(2);
      expect(fullEntitiesList).toHaveBeenCalledWith(context, user, ['Role'], { ids: [administratorRole.id, analystRole.id] });
    });

    it('depends on the markings it refers to that are not built-in', async () => {
      vi.mocked(fullRelationsList).mockImplementation(async (_ctx, _user, type) => {
        return (type === 'accesses-to' ? [{ fromId: analystsGroup.id, toId: customMarking.id }, { fromId: analystsGroup.id, toId: tlpAmber.id }] : []) as never;
      });
      const page = await groups.listItems(context, user, { first: 10 });
      const analysts = page.edges.find(({ node }) => node.id === analystsGroup.standard_id)!.node;
      expect(analysts.dependsOn).toEqual([{ type: 'markings', id: customMarking.standard_id }]);
    });

    it('applies search, ids and excluded ids to the groups', async () => {
      expect(await pageIds({ search: 'analy' })).toEqual([analystsGroup.standard_id]);
      expect(await pageIds({ ids: [analystsGroup.standard_id] })).toEqual([analystsGroup.standard_id]);
      expect(await pageIds({ excludedIds: [analystsGroup.standard_id] })).toEqual([administratorsGroup.standard_id]);
      vi.mocked(pageEntitiesConnection).mockClear();
      // No ids: no group query, whose empty filter would match every group
      expect(await pageIds({ ids: [] })).toEqual([]);
      expect(pageEntitiesConnection).not.toHaveBeenCalled();
    });

    it('resolves the groups to export, with the same rules as the listing', async () => {
      const ids = async (selected: string[] | null, excluded: string[]) => (await groups.resolveItems(context, user, selected, excluded)).map((item) => item.id);
      expect(await ids(null, [])).toEqual([administratorsGroup.standard_id, analystsGroup.standard_id]);
      expect(await ids(null, [administratorsGroup.standard_id])).toEqual([analystsGroup.standard_id]);
      vi.mocked(fullEntitiesList).mockClear();
      expect(await ids([], [])).toEqual([]);
      expect(fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  describe('policies', () => {
    const passwordPolicy = {
      password_policy_min_length: 12,
      password_policy_max_length: 64,
      password_policy_min_symbols: 1,
      password_policy_min_numbers: 2,
      password_policy_min_words: 0,
      password_policy_min_lowercase: 1,
      password_policy_min_uppercase: 1,
      password_policy_validity_days: 90,
    };

    it('exports the policies and the main organization by standard id, never the messages nor the authentication', async () => {
      withSettings({ ...passwordPolicy, view_all_users: false, platform_organization: 'organization-id' });
      const organization = { id: 'organization-id', standard_id: 'identity--11111111-2222-4333-8444-555555555555', name: 'Filigran' };
      vi.mocked(storeLoadById).mockResolvedValueOnce(organization as never);
      const file = await exportConfigPresetItem(context, user, findFamily('policies'), await findItem('policies', 'policies'));
      expect(file).toMatchObject({ type: 'securityAccess.policies', id: 'policies' });
      expect(file.configuration).toEqual({
        ...passwordPolicy,
        view_all_users: false,
        platform_organization: { standard_id: organization.standard_id, name: 'Filigran' },
      });
    });

    it('exports a policy that is not set with the value the platform applies, so that it replaces the policy of the target', async () => {
      const file = await exportConfigPresetItem(context, user, findFamily('policies'), await findItem('policies', 'policies'));
      expect(file.configuration).toEqual({
        ...Object.fromEntries(Object.keys(passwordPolicy).map((key) => [key, 0])),
        view_all_users: false,
        platform_organization: null,
      });
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
