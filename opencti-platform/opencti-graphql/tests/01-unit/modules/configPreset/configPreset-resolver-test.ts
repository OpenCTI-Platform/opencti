import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { graphql, type GraphQLObjectType } from 'graphql';
import type { IResolvers } from '@graphql-tools/utils';

const flags = vi.hoisted(() => ({ enabled: true }));
const enterpriseEdition = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => flags.enabled),
}));
vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>()),
  isEnterpriseEditionUpToDate: vi.fn(async () => enterpriseEdition.enabled),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
  fullRelationsList: vi.fn(),
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
vi.mock('../../../../src/modules/configPreset/export/configPreset-export-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/configPreset/export/configPreset-export-domain')>()),
  configPresetExport: vi.fn(),
}));

import { authDirectiveBuilder } from '../../../../src/graphql/authDirective';
import { makeFeatureFlagDirectiveTransformer } from '../../../../src/graphql/featureFlagDirective';
import configPresetResolvers from '../../../../src/modules/configPreset/configPreset-resolver';
import { configPresetExport, findConfigPresetExportableItems, findConfigPresetExportableTypes } from '../../../../src/modules/configPreset/export/configPreset-export-domain';
import { topEntitiesList } from '../../../../src/database/middleware-loader';
import { buildPaginationFromEdges } from '../../../../src/database/utils';
import { CONFIG_PRESET_FAMILIES } from '../../../../src/modules/configPreset/configPreset-registry';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { builtInTheme, customTheme, otherCustomTheme } from './configPreset-themes-fixtures';
import { mockConfigPresetLoaders } from './configPreset-loaders-fixtures';
import { administratorRole, analystRole } from './configPreset-roles-fixtures';
import { administratorsGroup, analystsGroup } from './configPreset-groups-fixtures';
import { customMarking, papRed } from './configPreset-markings-fixtures';
import { customLabel, otherLabel } from './configPreset-labels-fixtures';
import { dnsExclusionList, retiredExclusionList } from './configPreset-exclusionLists-fixtures';
import { disarmKillChainPhase, killChainPhase, otherKillChainPhase } from './configPreset-killChainPhases-fixtures';

const buildSchema = () => {
  const schema = makeExecutableSchema({
    typeDefs: [
      `
        enum Capabilities { BYPASS SETTINGS_SETPARAMETERS }
        directive @auth(for: [Capabilities!]!, forDraft: [Capabilities!], and: Boolean) on FIELD_DEFINITION | OBJECT
        directive @ff(flags: [String!]!, softFail: Boolean = false, defaultValue: String = null) on FIELD_DEFINITION
        directive @public on FIELD_DEFINITION
        type Query { health: Boolean @public }
        type Mutation { health: Boolean @public }
        scalar Upload
        scalar DateTime
        type Settings { id: ID! }
        type EntitySetting { id: ID! target_type: String! platform_hidden_type: Boolean }
        type File { id: ID! name: String! }
        type PageInfo { startCursor: String! endCursor: String! hasNextPage: Boolean! hasPreviousPage: Boolean! globalCount: Int! }
      `,
      readFileSync(new URL('../../../../src/modules/configPreset/configPreset.graphql', import.meta.url), 'utf8'),
    ],
    resolvers: configPresetResolvers as IResolvers,
  });
  return makeFeatureFlagDirectiveTransformer()(authDirectiveBuilder('auth').authDirectiveTransformer(schema));
};

const ITEM_FIELDS = 'key label translatable dependsOn { type key } isDefault';
const QUERY = `{ configPresetExportableTypes { key label description group { key label } items { ${ITEM_FIELDS} } itemsPageInfo { hasNextPage globalCount } } }`;
const bypassUser = { id: 'admin', capabilities: [{ name: 'BYPASS' }] };
const settingsUser = { id: 'settings-admin', capabilities: [{ name: 'SETTINGS_SETPARAMETERS' }] };

const staticItem = (key: string, label: string, dependsOn: unknown[] = []) => ({ key, label, translatable: true, dependsOn, isDefault: false });
const themeItem = (theme: { standard_id: string; name: string }, isDefault: boolean) => ({
  key: theme.standard_id,
  label: theme.name,
  translatable: false,
  dependsOn: [],
  isDefault,
});
const labelItem = (label: { standard_id: string; value: string }) => ({ key: label.standard_id, label: label.value, translatable: false, dependsOn: [], isDefault: false });
const exclusionListItem = (list: { standard_id: string; name: string }) => ({ key: list.standard_id, label: list.name, translatable: false, dependsOn: [], isDefault: false });
const phaseItem = (phase: { standard_id: string; kill_chain_name: string; phase_name: string }) => ({
  key: phase.standard_id,
  label: `${phase.kill_chain_name}: ${phase.phase_name}`,
  translatable: false,
  dependsOn: [],
  isDefault: false,
});
const vocabularyItem = (category: string) => ({
  key: category,
  label: category,
  translatable: false,
  dependsOn: [],
  isDefault: false,
});
const onePage = (globalCount: number) => ({ hasNextPage: false, globalCount });

describe('Config preset exportable types query', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    flags.enabled = true;
    enterpriseEdition.enabled = true;
    vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_theme: customTheme.id }] as never);
    mockConfigPresetLoaders();
  });

  it('returns the exportable types to a BYPASS user when the flag is enabled', async () => {
    const result = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    const platformSettings = { key: 'platformSettings', label: 'Platform settings' };
    expect(result.data?.configPresetExportableTypes).toEqual([
      {
        key: 'platform',
        label: 'Platform configuration',
        description: 'Title, favicon, default theme, language',
        group: platformSettings,
        // The custom default theme is a dependency
        items: [staticItem('platform', 'Platform configuration', [{ type: 'branding', key: customTheme.standard_id }])],
        itemsPageInfo: onePage(1),
      },
      {
        key: 'branding',
        label: 'Branding',
        description: 'Themes, colors, logos',
        group: platformSettings,
        // Every theme but the built-in ones
        items: [themeItem(otherCustomTheme, false), themeItem(customTheme, true)],
        itemsPageInfo: onePage(2),
      },
      {
        // No message is set in the default settings of these tests: the category is listed without item
        key: 'messages',
        label: 'Messages',
        description: 'Banner, login and consent messages',
        group: platformSettings,
        items: [],
        itemsPageInfo: onePage(0),
      },
      {
        key: 'whitemark',
        label: 'Remove Filigran logos',
        description: '',
        group: platformSettings,
        items: [staticItem('whitemark', 'Remove Filigran logos')],
        itemsPageInfo: onePage(1),
      },
      {
        key: 'hiddenEntityTypes',
        label: 'Hidden entity types',
        description: 'Entity types hidden in the platform',
        group: { key: 'dataModel', label: 'Data model' },
        items: [staticItem('hiddenEntityTypes', 'Hidden entity types')],
        itemsPageInfo: onePage(1),
      },
      {
        key: 'markings',
        label: 'Markings',
        description: 'Marking definitions, their colors and orders',
        group: { key: 'securityAccess', label: 'Security & Access' },
        // The markings by definition, without the built-in ones
        items: [customMarking, papRed].map((marking) => ({ key: marking.standard_id, label: marking.definition, translatable: false, dependsOn: [], isDefault: false })),
        itemsPageInfo: onePage(2),
      },
      {
        key: 'roles',
        label: 'Roles',
        description: 'Roles and their capabilities',
        group: { key: 'securityAccess', label: 'Security & Access' },
        items: [administratorRole, analystRole].map((role) => ({ key: role.standard_id, label: role.name, translatable: false, dependsOn: [], isDefault: false })),
        itemsPageInfo: onePage(2),
      },
      {
        key: 'groups',
        label: 'Groups',
        description: 'Groups with their roles, markings and confidence level',
        group: { key: 'securityAccess', label: 'Security & Access' },
        // Each group depends on its roles
        items: [[administratorsGroup, administratorRole], [analystsGroup, analystRole]].map(([group, role]) => ({
          key: group.standard_id,
          label: group.name,
          translatable: false,
          dependsOn: [{ type: 'roles', key: role.standard_id }],
          isDefault: false,
        })),
        itemsPageInfo: onePage(2),
      },
      {
        key: 'policies',
        label: 'Policies',
        description: 'Password policy, users visibility and main organization',
        group: { key: 'securityAccess', label: 'Security & Access' },
        items: [staticItem('policies', 'Policies')],
        itemsPageInfo: onePage(1),
      },
      {
        key: 'labels',
        label: 'Labels',
        description: 'Labels and their colors',
        group: { key: 'taxonomy', label: 'Taxonomy' },
        // The labels by value
        items: [labelItem(otherLabel), labelItem(customLabel)],
        itemsPageInfo: onePage(2),
      },
      {
        key: 'exclusionLists',
        label: 'Exclusion lists',
        description: 'Exclusion lists and their values',
        group: { key: 'customization', label: 'Customization' },
        // By name
        items: [exclusionListItem(dnsExclusionList), exclusionListItem(retiredExclusionList)],
        itemsPageInfo: onePage(2),
      },
      {
        key: 'killChainPhases',
        label: 'Kill chain phases',
        description: 'Kill chains, their phases and their order',
        group: { key: 'taxonomy', label: 'Taxonomy' },
        // By kill chain, then by order in the kill chain
        items: [phaseItem(disarmKillChainPhase), phaseItem(otherKillChainPhase), phaseItem(killChainPhase)],
        itemsPageInfo: onePage(3),
      },
      {
        key: 'vocabularies',
        label: 'Vocabularies',
        description: 'Vocabulary categories and their entries',
        group: { key: 'taxonomy', label: 'Taxonomy' },
        // All the categories, by category
        items: [vocabularyItem('case_severity_ov'), vocabularyItem('incident_type_ov'), vocabularyItem('integrity_level_ov'), vocabularyItem('report_types_ov')],
        itemsPageInfo: onePage(4),
      },
    ]);
  });

  it('exposes no id on the catalog objects: a singleton category and its item share a key, and the Relay store would merge objects with the same id', () => {
    const schema = buildSchema();
    ['ConfigPresetExportableType', 'ConfigPresetExportableItem', 'ConfigPresetExportableGroup', 'ConfigPresetItemReference'].forEach((typeName) => {
      const fields = Object.keys((schema.getType(typeName) as GraphQLObjectType).getFields());
      expect(fields).toContain('key');
      expect(fields).not.toContain('id');
    });
  });

  it('lists the messages set on the platform, and the category without item when none is set', async () => {
    // No message is set in the default settings of these tests: the category has no item
    const none = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: bypassUser } });
    const noMessages = (none.data?.configPresetExportableTypes as { key: string; items: unknown[]; itemsPageInfo: unknown }[]).find((type) => type.key === 'messages');
    expect(noMessages).toMatchObject({ items: [], itemsPageInfo: onePage(0) });

    vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_theme: customTheme.id, platform_login_message: 'Welcome' }] as never);
    const result = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    const messages = (result.data?.configPresetExportableTypes as { key: string }[]).find((type) => type.key === 'messages');
    expect(messages).toEqual({
      key: 'messages',
      label: 'Messages',
      description: 'Banner, login and consent messages',
      group: { key: 'platformSettings', label: 'Platform settings' },
      items: [staticItem('login', 'Login message')],
      itemsPageInfo: onePage(1),
    });
  });

  it('lists a family that requires the Enterprise Edition without its items when the platform has none, so the dialog can show it locked', async () => {
    enterpriseEdition.enabled = false;
    const source = '{ configPresetExportableTypes { key lockedByEnterpriseEdition items { key } itemsPageInfo { hasNextPage globalCount } } }';
    const result = await graphql({ schema: buildSchema(), source, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    const types = result.data?.configPresetExportableTypes as { key: string; lockedByEnterpriseEdition: boolean; items: unknown[]; itemsPageInfo: unknown }[];
    expect(types.map((type) => [type.key, type.lockedByEnterpriseEdition])).toEqual([
      ['platform', false], ['branding', false], ['messages', false], ['whitemark', true], ['hiddenEntityTypes', false],
      ['markings', false], ['roles', false], ['groups', false], ['policies', false], ['labels', false], ['exclusionLists', false], ['killChainPhases', false],
      ['vocabularies', false],
    ]);
    expect(types.find((type) => type.key === 'whitemark')).toMatchObject({ lockedByEnterpriseEdition: true, items: [], itemsPageInfo: { hasNextPage: false, globalCount: 0 } });
    enterpriseEdition.enabled = true;
    const licensed = await graphql({ schema: buildSchema(), source, contextValue: { user: bypassUser } });
    const whitemark = (licensed.data?.configPresetExportableTypes as { key: string; lockedByEnterpriseEdition: boolean; items: unknown[] }[]).find((type) => type.key === 'whitemark');
    expect(whitemark).toMatchObject({ lockedByEnterpriseEdition: false });
    expect(whitemark?.items).toHaveLength(1);
  });

  it('rejects a user without BYPASS', async () => {
    const result = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: settingsUser } });
    expect(result.errors?.[0].message).toBe('You are not allowed to do this.');
    expect(result.data).toBeNull();
  });

  it('rejects a BYPASS user when the flag is disabled', async () => {
    flags.enabled = false;
    const result = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: bypassUser } });
    expect(result.errors?.[0].message).toMatch(/Feature is disabled/i);
    expect(result.data).toBeNull();
  });

  it('asks each family for its first page of 10 items, with the context and user of the caller', async () => {
    const context = { source: 'test' } as AuthContext;
    const user = bypassUser as unknown as AuthUser;
    const items = [{ id: 'entity-id', label: 'User data label', translatable: false, exporter: async () => ({}) }];
    const listItems = vi.spyOn(CONFIG_PRESET_FAMILIES[0], 'listItems').mockResolvedValueOnce(
      buildPaginationFromEdges(10, null, items.map((node) => ({ node, cursor: node.id })), 25),
    );
    const types = await findConfigPresetExportableTypes(context, user);
    expect(listItems).toHaveBeenCalledWith(context, user, { first: 10 });
    expect(types.map(({ key, group }) => [key, group.key])).toEqual([
      ['platform', 'platformSettings'],
      ['branding', 'platformSettings'],
      ['messages', 'platformSettings'],
      ['whitemark', 'platformSettings'],
      ['hiddenEntityTypes', 'dataModel'],
      ['markings', 'securityAccess'],
      ['roles', 'securityAccess'],
      ['groups', 'securityAccess'],
      ['policies', 'securityAccess'],
      ['labels', 'taxonomy'],
      ['exclusionLists', 'customization'],
      ['killChainPhases', 'taxonomy'],
      ['vocabularies', 'taxonomy'],
    ]);
    expect(types[0].items).toEqual([{ key: 'entity-id', label: 'User data label', translatable: false, dependsOn: [], isDefault: false, isEnabled: null }]);
    expect(types[0].itemsPageInfo.globalCount).toBe(25);
    listItems.mockRestore();
  });
});

const ITEMS_QUERY = `query($type: ID!, $first: Int, $after: ID, $search: String, $ids: [ID!], $excludedIds: [ID!]) {
  configPresetExportableItems(type: $type, first: $first, after: $after, search: $search, ids: $ids, excludedIds: $excludedIds) {
    pageInfo { hasNextPage endCursor globalCount }
    edges { cursor node { ${ITEM_FIELDS} } }
  }
}`;

describe('Config preset exportable items query', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    flags.enabled = true;
    enterpriseEdition.enabled = true;
    vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_theme: builtInTheme.id }] as never);
    mockConfigPresetLoaders();
  });

  const queryItems = (variables: Record<string, unknown>, user: unknown = bypassUser) => graphql({
    schema: buildSchema(),
    source: ITEMS_QUERY,
    variableValues: variables,
    contextValue: { user },
  });

  it('pages and searches the items of a type, built-in themes excluded', async () => {
    const first = await queryItems({ type: 'branding', first: 1 });
    expect(first.errors).toBeUndefined();
    const connection = first.data?.configPresetExportableItems as { pageInfo: { hasNextPage: boolean; globalCount: number }; edges: { node: unknown }[] };
    expect(connection.edges.map(({ node }) => node)).toEqual([themeItem(otherCustomTheme, false)]);
    expect(connection.pageInfo).toMatchObject({ hasNextPage: true, globalCount: 2 });
    const searched = await queryItems({ type: 'branding', search: 'soc' });
    expect((searched.data?.configPresetExportableItems as typeof connection).edges.map(({ node }) => node)).toEqual([themeItem(customTheme, false)]);
  });

  it('passes the paging, search and id filters to the family', async () => {
    const context = { source: 'test' } as AuthContext;
    const user = bypassUser as unknown as AuthUser;
    const branding = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'branding')!;
    const listItems = vi.spyOn(branding, 'listItems');
    const args = { first: 5, after: 'cursor', search: 'soc', ids: [customTheme.standard_id], excludedIds: [otherCustomTheme.standard_id] };
    await findConfigPresetExportableItems(context, user, { type: 'branding', ...args });
    expect(listItems).toHaveBeenCalledWith(context, user, args);
    listItems.mockRestore();
  });

  it('rejects an unknown type', async () => {
    const result = await queryItems({ type: 'dashboards' });
    expect(result.errors?.[0].message).toBe('Unknown configuration preset type');
  });

  it('serves the items of a family that requires the Enterprise Edition only when the platform has it', async () => {
    const withEnterpriseEdition = await queryItems({ type: 'whitemark' });
    expect(withEnterpriseEdition.errors).toBeUndefined();
    const connection = withEnterpriseEdition.data?.configPresetExportableItems as { edges: { node: unknown }[] };
    expect(connection.edges.map(({ node }) => node)).toEqual([staticItem('whitemark', 'Remove Filigran logos')]);
    enterpriseEdition.enabled = false;
    const withoutEnterpriseEdition = await queryItems({ type: 'whitemark' });
    expect(withoutEnterpriseEdition.errors?.[0].message).toBe('Enterprise edition is not enabled');
  });

  it('rejects a user without BYPASS', async () => {
    const result = await queryItems({ type: 'branding' }, settingsUser);
    expect(result.errors?.[0].message).toBe('You are not allowed to do this.');
    expect(result.data).toBeNull();
  });

  it('rejects a BYPASS user when the flag is disabled', async () => {
    flags.enabled = false;
    const result = await queryItems({ type: 'branding' });
    expect(result.errors?.[0].message).toMatch(/Feature is disabled/i);
  });
});

const MUTATION = 'mutation { configPresetExport(selections: [{ type: "platform", items: ["platform"] }], bundle_name: "Prod") { id name } }';

describe('Config preset export mutation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    flags.enabled = true;
    vi.mocked(configPresetExport).mockResolvedValue({ id: 'config_preset/0b5c1e9e-4b0a-4f37-9a43-1f1c2b7c9d10/bundle.zip', name: 'bundle.zip' } as never);
  });

  it('returns the stored file to a BYPASS user when the flag is enabled', async () => {
    const result = await graphql({ schema: buildSchema(), source: MUTATION, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    expect(result.data?.configPresetExport).toEqual({ id: 'config_preset/0b5c1e9e-4b0a-4f37-9a43-1f1c2b7c9d10/bundle.zip', name: 'bundle.zip' });
    expect(configPresetExport).toHaveBeenCalledWith(expect.anything(), bypassUser, [{ type: 'platform', items: ['platform'] }], 'Prod');
  });

  it('accepts a selection without items, meaning every item of the type', async () => {
    const source = 'mutation { configPresetExport(selections: [{ type: "messages" }]) { id } }';
    const result = await graphql({ schema: buildSchema(), source, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    expect(configPresetExport).toHaveBeenCalledWith(expect.anything(), bypassUser, [{ type: 'messages' }], undefined);
  });

  it('passes the excluded items of a selection of every item', async () => {
    const source = 'mutation { configPresetExport(selections: [{ type: "branding", excluded_items: ["theme-id"] }]) { id } }';
    const result = await graphql({ schema: buildSchema(), source, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    expect(configPresetExport).toHaveBeenCalledWith(expect.anything(), bypassUser, [{ type: 'branding', excluded_items: ['theme-id'] }], undefined);
  });

  it('rejects a user without BYPASS', async () => {
    const result = await graphql({ schema: buildSchema(), source: MUTATION, contextValue: { user: settingsUser } });
    expect(result.errors?.[0].message).toBe('You are not allowed to do this.');
    expect(configPresetExport).not.toHaveBeenCalled();
  });

  it('rejects a BYPASS user when the flag is disabled', async () => {
    flags.enabled = false;
    const result = await graphql({ schema: buildSchema(), source: MUTATION, contextValue: { user: bypassUser } });
    expect(result.errors?.[0].message).toMatch(/Feature is disabled/i);
    expect(configPresetExport).not.toHaveBeenCalled();
  });
});

describe('Config preset import result fields', () => {
  const fields = configPresetResolvers.ConfigPresetImportResult as Record<string, (parent: unknown) => unknown>;
  const result = (overrides: Record<string, unknown> = {}) => ({ type: 'branding', key: 'theme--1', status: 'CREATED', reason: null, ...overrides });

  it('names a result by its label, and by its key when it was stored before the names were kept', () => {
    expect(fields.label(result({ label: 'SOC night' }))).toBe('SOC night');
    expect(fields.label(result())).toBe('theme--1');
    expect(fields.translatable(result({ translatable: true }))).toBe(true);
    expect(fields.translatable(result())).toBe(false);
  });

  it('gives the type and the group of a result from the registry, and the place of the type among the types', () => {
    expect(fields.type_label(result())).toBe('Branding');
    expect(fields.group(result())).toEqual({ key: 'platformSettings', label: 'Platform settings' });
    expect(fields.group(result({ type: 'hiddenEntityTypes' }))).toEqual({ key: 'dataModel', label: 'Data model' });
    const places = ['platform', 'branding', 'messages', 'whitemark', 'hiddenEntityTypes'].map((type) => fields.type_index(result({ type })));
    expect(places).toEqual([0, 1, 2, 3, 4]);
  });

  it('does not fail on a type the registry does not know', () => {
    expect(fields.type_label(result({ type: 'gone' }))).toBe('gone');
    expect(fields.group(result({ type: 'gone' }))).toEqual({ key: 'gone', label: 'gone' });
    expect(fields.type_index(result({ type: 'gone' }))).toBe(0);
  });
});
