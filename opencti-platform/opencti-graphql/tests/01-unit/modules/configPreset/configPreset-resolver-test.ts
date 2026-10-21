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

import { authDirectiveBuilder } from '../../../../src/graphql/authDirective';
import { makeFeatureFlagDirectiveTransformer } from '../../../../src/graphql/featureFlagDirective';
import configPresetResolvers from '../../../../src/modules/configPreset/configPreset-resolver';
import { findConfigPresetExportableTypes } from '../../../../src/modules/configPreset/configPreset-domain';
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
