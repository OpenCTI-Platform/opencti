import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { graphql, type GraphQLObjectType } from 'graphql';
import type { IResolvers } from '@graphql-tools/utils';

const flags = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => flags.enabled),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));
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
import { builtInTheme, customTheme, mockThemeLoaders, otherCustomTheme } from './configPreset-themes-fixtures';

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
const themeItem = (theme: { id: string; name: string }, isDefault: boolean) => ({
  key: theme.id,
  label: theme.name,
  translatable: false,
  dependsOn: [],
  isDefault,
});
const onePage = (globalCount: number) => ({ hasNextPage: false, globalCount });

describe('Config preset exportable types query', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    flags.enabled = true;
    vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_theme: customTheme.id }] as never);
    mockThemeLoaders();
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
        items: [staticItem('platform', 'Platform configuration', [{ type: 'branding', key: customTheme.id }])],
        itemsPageInfo: onePage(1),
      },
      {
        key: 'branding',
        label: 'Branding',
        description: 'Themes, colors, logos',
        group: platformSettings,
        // Whitemark first, then every theme but the built-in ones
        items: [staticItem('whitemark', 'Remove Filigran logos'), themeItem(otherCustomTheme, false), themeItem(customTheme, true)],
        itemsPageInfo: onePage(3),
      },
      {
        key: 'hiddenEntityTypes',
        label: 'Hidden entity types',
        description: 'Entity types hidden in the platform',
        group: { key: 'dataModel', label: 'Data model' },
        items: [staticItem('hiddenEntityTypes', 'Hidden entity types')],
        itemsPageInfo: onePage(1),
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

  it('lists the messages set on the platform and hides the category when none is set', async () => {
    // No message is set in the default settings of these tests: the category is not returned
    const none = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: bypassUser } });
    expect((none.data?.configPresetExportableTypes as { key: string }[]).map((type) => type.key)).toEqual(['platform', 'branding', 'hiddenEntityTypes']);

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
      ['hiddenEntityTypes', 'dataModel'],
    ]);
    expect(types[0].items).toEqual([{ key: 'entity-id', label: 'User data label', translatable: false, dependsOn: [], isDefault: false }]);
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
    vi.mocked(topEntitiesList).mockResolvedValue([{ id: 'settings-id', platform_theme: builtInTheme.id }] as never);
    mockThemeLoaders();
  });

  const queryItems = (variables: Record<string, unknown>, user: unknown = bypassUser) => graphql({
    schema: buildSchema(),
    source: ITEMS_QUERY,
    variableValues: variables,
    contextValue: { user },
  });

  it('pages and searches the items of a type, whitemark first, built-in themes excluded', async () => {
    const first = await queryItems({ type: 'branding', first: 2 });
    expect(first.errors).toBeUndefined();
    const connection = first.data?.configPresetExportableItems as { pageInfo: { hasNextPage: boolean; globalCount: number }; edges: { node: unknown }[] };
    expect(connection.edges.map(({ node }) => node)).toEqual([staticItem('whitemark', 'Remove Filigran logos'), themeItem(otherCustomTheme, false)]);
    expect(connection.pageInfo).toMatchObject({ hasNextPage: true, globalCount: 3 });
    const searched = await queryItems({ type: 'branding', search: 'soc' });
    // The search applies to the themes: whitemark, a static item, is always listed
    expect((searched.data?.configPresetExportableItems as typeof connection).edges.map(({ node }) => node)).toEqual([staticItem('whitemark', 'Remove Filigran logos'), themeItem(customTheme, false)]);
  });

  it('passes the paging, search and id filters to the family', async () => {
    const context = { source: 'test' } as AuthContext;
    const user = bypassUser as unknown as AuthUser;
    const branding = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'branding')!;
    const listItems = vi.spyOn(branding, 'listItems');
    const args = { first: 5, after: 'cursor', search: 'soc', ids: [customTheme.id], excludedIds: [otherCustomTheme.id] };
    await findConfigPresetExportableItems(context, user, { type: 'branding', ...args });
    expect(listItems).toHaveBeenCalledWith(context, user, args);
    listItems.mockRestore();
  });

  it('rejects an unknown type', async () => {
    const result = await queryItems({ type: 'dashboards' });
    expect(result.errors?.[0].message).toBe('Unknown configuration preset type');
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
