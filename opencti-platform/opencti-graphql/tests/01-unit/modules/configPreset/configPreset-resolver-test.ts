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
vi.mock('../../../../src/modules/configPreset/configPreset-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/configPreset/configPreset-domain')>()),
  configPresetExport: vi.fn(),
}));

import { authDirectiveBuilder } from '../../../../src/graphql/authDirective';
import { makeFeatureFlagDirectiveTransformer } from '../../../../src/graphql/featureFlagDirective';
import configPresetResolvers from '../../../../src/modules/configPreset/configPreset-resolver';
import { configPresetExport, findConfigPresetExportableTypes } from '../../../../src/modules/configPreset/configPreset-domain';
import { CONFIG_PRESET_FAMILIES } from '../../../../src/modules/configPreset/configPreset-registry';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

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
        type File { id: ID! name: String! }
      `,
      readFileSync(new URL('../../../../src/modules/configPreset/configPreset.graphql', import.meta.url), 'utf8'),
    ],
    resolvers: configPresetResolvers as IResolvers,
  });
  return makeFeatureFlagDirectiveTransformer()(authDirectiveBuilder('auth').authDirectiveTransformer(schema));
};

const QUERY = '{ configPresetExportableTypes { key label group { key label } items { key label translatable } } }';
const bypassUser = { id: 'admin', capabilities: [{ name: 'BYPASS' }] };
const settingsUser = { id: 'settings-admin', capabilities: [{ name: 'SETTINGS_SETPARAMETERS' }] };

describe('Config preset exportable types query', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    flags.enabled = true;
  });

  it('returns the catalog to a BYPASS user when the flag is enabled', async () => {
    const result = await graphql({ schema: buildSchema(), source: QUERY, contextValue: { user: bypassUser } });
    expect(result.errors).toBeUndefined();
    const platformSettings = { key: 'platformSettings', label: 'Platform settings' };
    expect(result.data?.configPresetExportableTypes).toEqual([
      {
        key: 'platform',
        label: 'Platform configuration',
        group: platformSettings,
        items: [{ key: 'platform', label: 'Platform configuration', translatable: true }],
      },
      {
        key: 'messages',
        label: 'Messages',
        group: platformSettings,
        items: [{ key: 'messages', label: 'Messages', translatable: true }],
      },
      {
        key: 'hiddenEntityTypes',
        label: 'Hidden entity types',
        group: { key: 'dataModel', label: 'Data model' },
        items: [{ key: 'hiddenEntityTypes', label: 'Hidden entity types', translatable: true }],
      },
    ]);
  });

  it('exposes no id on the catalog objects: a singleton category and its item share a key, and the Relay store would merge objects with the same id', () => {
    const schema = buildSchema();
    ['ConfigPresetExportableType', 'ConfigPresetExportableItem', 'ConfigPresetExportableGroup'].forEach((typeName) => {
      const fields = Object.keys((schema.getType(typeName) as GraphQLObjectType).getFields());
      expect(fields).toContain('key');
      expect(fields).not.toContain('id');
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

  it('builds the catalog in registry order, with the group of each family and the items it lists for the caller', async () => {
    const context = { source: 'test' } as AuthContext;
    const user = bypassUser as unknown as AuthUser;
    const listItems = vi.spyOn(CONFIG_PRESET_FAMILIES[0], 'listItems').mockResolvedValueOnce([
      { id: 'entity-id', label: 'User data label', translatable: false, exporter: async () => ({}) },
    ]);
    const types = await findConfigPresetExportableTypes(context, user);
    expect(listItems).toHaveBeenCalledWith(context, user);
    expect(types.map(({ key, group }) => [key, group.key])).toEqual([['platform', 'platformSettings'], ['messages', 'platformSettings'], ['hiddenEntityTypes', 'dataModel']]);
    expect(types[0].items).toEqual([{ key: 'entity-id', label: 'User data label', translatable: false }]);
    listItems.mockRestore();
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
