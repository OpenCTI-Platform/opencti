import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/domain/internalObject', () => ({ createInternalObject: vi.fn(), editInternalObject: vi.fn() }));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addCustomViewCreatedCount: vi.fn(),
}));
// The entity types a platform can have views for come from its schema, not under test here
vi.mock('../../../../src/modules/customView/customView-domain', () => ({ isCustomViewsAvailableForEntityType: vi.fn((type: string) => type !== 'Note') }));
// The ids of the filters are resolved on the platform: the manifests of these tests are returned as they are
vi.mock('../../../../src/modules/dashboard/dashboard-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/dashboard/dashboard-utils')>()),
  convertDashboardManifestIds: vi.fn(async (_context, _user, manifest) => manifest),
}));

import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { createInternalObject, editInternalObject } from '../../../../src/domain/internalObject';
import { addCustomViewCreatedCount } from '../../../../src/manager/telemetryManager';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { importCustomView } from '../../../../src/modules/customView/customView-import';
import { customViewImportKey } from '../../../../src/modules/customView/customView-import';
import { ENTITY_TYPE_CUSTOM_VIEW } from '../../../../src/modules/customView/customView-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { toB64 } from '../../../../src/utils/base64';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const manifest = toB64({ config: {}, widgets: { widget1: { id: 'widget1', type: 'number', dataSelection: [] } } });
const configuration = { name: 'Executive overview', target_entity_type: 'Report', description: 'The executives', manifest };
const stored = (overrides: Record<string, unknown> = {}) => ({
  id: 'stored-id', name: 'Executive overview', target_entity_type: 'Report', description: 'The executives', manifest, enabled: true, default: true, ...overrides,
});
const platformHas = (...views: Record<string, unknown>[]) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, args) => {
    const filters = (args as { filters: { filters: { key: string[]; values: string[] }[] } }).filters.filters;
    // As the platform does: the filter on a name does not tell the case apart
    const same = (a: unknown, b: unknown) => (typeof a === 'string' && typeof b === 'string' ? a.toLowerCase() === b.toLowerCase() : a === b);
    return views.filter((view) => filters.every(({ key, values }) => values.some((value) => same(value, view[key[0]])))) as never;
  });
};
const written = () => vi.mocked(createInternalObject).mock.calls.map(([, , input]) => input);
const patched = () => vi.mocked(editInternalObject).mock.calls.map(([, , id, , patch]) => ({ id, patch }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(createInternalObject).mockResolvedValue({ id: 'created-id' } as never);
  vi.mocked(editInternalObject).mockResolvedValue({ id: 'stored-id' } as never);
  platformHas();
});

describe('Custom view import from a bundle', () => {
  describe('validation', () => {
    it('refuses an invalid configuration with the reason, and reads nothing', async () => {
      const result = await importCustomView(context, user, { name: '  ', target_entity_type: 'Report' }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
      expect(result.reason).toContain('name');
      expect(fullEntitiesList).not.toHaveBeenCalled();
      expect(createInternalObject).not.toHaveBeenCalled();
    });

    it('refuses a view of an entity type the platform cannot have views for, and goes no further', async () => {
      const result = await importCustomView(context, user, { ...configuration, target_entity_type: 'Note' }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'failed', code: 'entity_type', reason: 'Custom views cannot be created for this entity type', exists: false });
      expect(fullEntitiesList).not.toHaveBeenCalled();
      expect(createInternalObject).not.toHaveBeenCalled();
    });

    it('refuses a view with a widget that uses dashboard variables, as every way into a custom view does', async () => {
      const variableId = '11111111-1111-4111-8111-111111111111';
      const withToken = toB64({ widgets: { widget1: { id: 'widget1', dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['entity_type'], values: [`$var:${variableId}`] }], filterGroups: [] } }] } } });
      const result = await importCustomView(context, user, { ...configuration, manifest: withToken }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
      expect(result.reason).toContain('dashboard variables');
      expect(createInternalObject).not.toHaveBeenCalled();
    });
  });

  describe('overwrite', () => {
    it('creates a view that the platform does not have, neither enabled nor the default of its entity type', async () => {
      const result = await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'created', exists: false });
      expect(written()).toEqual([{
        description: 'The executives', manifest, name: 'Executive overview', slug: 'executive-overview', target_entity_type: 'Report', enabled: false, default: false,
      }]);
      expect(addCustomViewCreatedCount).toHaveBeenCalledTimes(1);
    });

    it('writes nothing in a dry run, and says what it would do', async () => {
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      platformHas(stored({ description: 'Other' }));
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
      expect(createInternalObject).not.toHaveBeenCalled();
      expect(editInternalObject).not.toHaveBeenCalled();
    });

    it('finds the view by its entity type and its name: the same name on another entity type is another view', async () => {
      platformHas(stored({ target_entity_type: 'Malware', description: 'Other' }));
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'created', exists: false });
      expect(editInternalObject).not.toHaveBeenCalled();
    });

    it('patches the description and the manifest of the view that has the name, and never whether it is enabled or the default', async () => {
      const otherManifest = toB64({ config: {}, widgets: {} });
      platformHas(stored({ description: 'Old', manifest: otherManifest }));
      const result = await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(patched()).toEqual([{ id: 'stored-id', patch: [{ key: 'description', value: ['The executives'] }, { key: 'manifest', value: [manifest] }] }]);
      expect(patched()[0].patch.map(({ key }) => key)).not.toEqual(expect.arrayContaining(['enabled', 'default', 'name', 'slug', 'target_entity_type']));
      expect(createInternalObject).not.toHaveBeenCalled();
    });

    it('overwrites a view that uses a saved filter with the inline filters the export writes, as an overwritten dashboard is', async () => {
      // The export inlines the saved filters (as the file export and the export of the dashboards do): on the platform the bundle comes from,
      // the stored manifest still holds the reference, so the view is overwritten, not up to date. Same behaviour as a dashboard.
      const inlineFilters = { mode: 'and', filters: [{ key: ['objectLabel'], values: ['label-id'] }], filterGroups: [] };
      const widgetOf = (selection: Record<string, unknown>) => toB64({ config: {}, widgets: { widget1: { id: 'widget1', type: 'number', dataSelection: [selection] } } });
      const exported = widgetOf({ filters: inlineFilters });
      platformHas(stored({ manifest: widgetOf({ filters_id: 'saved-id' }) }));
      const result = await importCustomView(context, user, { ...configuration, manifest: exported }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(patched()[0].patch).toEqual([{ key: 'manifest', value: [exported] }]);
    });

    it('does not patch the description again when the bundle holds it padded', async () => {
      platformHas(stored());
      const padded = { ...configuration, description: '  The executives  ' };
      expect(await importCustomView(context, user, padded, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    });

    it('leaves a field the bundle does not set to the view, and clears a description the bundle empties', async () => {
      platformHas(stored({ description: 'Old' }));
      expect(await importCustomView(context, user, { name: 'Executive overview', target_entity_type: 'Report', description: '' }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten' });
      expect(patched()[0].patch).toEqual([{ key: 'description', value: [''] }]);
      vi.mocked(editInternalObject).mockClear();
      expect(await importCustomView(context, user, { name: 'Executive overview', target_entity_type: 'Report', description: null, manifest: null }, { mode: ConfigImportMode.Overwrite }))
        .toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(editInternalObject).not.toHaveBeenCalled();
    });

    it('skips a view that is already as the bundle has it, whatever its state', async () => {
      platformHas(stored({ enabled: false, default: false }));
      const result = await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date', exists: true });
      expect(editInternalObject).not.toHaveBeenCalled();
    });

    it('refuses a name that several views of the entity type have', async () => {
      platformHas(stored(), stored({ id: 'other-id' }));
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
      expect(editInternalObject).not.toHaveBeenCalled();
    });

    it('does not tell the case apart when it looks for the name, as the filter of the platform does not either', async () => {
      platformHas(stored({ name: 'executive overview' }));
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'created', exists: false });
    });

    it('refuses an existing view in add mode', async () => {
      platformHas(stored());
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    });
  });

  describe('names taken by the same import', () => {
    it('refuses the second view of a name in a dry run, which reads the platform only', async () => {
      const reservedNames = new Set<string>();
      const options = { mode: ConfigImportMode.Overwrite, dryRun: true, reservedNames };
      expect(await importCustomView(context, user, configuration, options)).toMatchObject({ status: 'created' });
      expect(reservedNames).toEqual(new Set([customViewImportKey('Report', 'Executive overview')]));
      // exists is false: the clash is with an earlier item of the bundle, not with a view of the platform
      expect(await importCustomView(context, user, configuration, options)).toMatchObject({ status: 'failed', code: 'duplicate', exists: false });
      // another entity type, another view
      expect(await importCustomView(context, user, { ...configuration, target_entity_type: 'Malware' }, options)).toMatchObject({ status: 'created' });
    });
  });

  describe('copy', () => {
    it('adds the view under its name when the platform does not have it, and under a free name when it does', async () => {
      expect(await importCustomView(context, user, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'created', exists: false, reason: undefined });
      expect(written()[0]).toMatchObject({ name: 'Executive overview', slug: 'executive-overview' });
      platformHas(stored(), stored({ name: 'Executive overview (1)' }));
      const result = await importCustomView(context, user, configuration, { mode: ConfigImportMode.Copy });
      expect(result).toMatchObject({ status: 'created', exists: true, reason: 'Added as "Executive overview (2)"' });
      expect(written()[1]).toMatchObject({ name: 'Executive overview (2)', slug: 'executive-overview-2', enabled: false, default: false });
      expect(editInternalObject).not.toHaveBeenCalled();
    });

    it('never makes a copy of the default view the default, nor enables it', async () => {
      platformHas(stored({ enabled: true, default: true }));
      await importCustomView(context, user, configuration, { mode: ConfigImportMode.Copy });
      expect(written()[0]).toMatchObject({ enabled: false, default: false });
    });

    it('takes the names the earlier items of a dry run reserved, and reserves its own', async () => {
      const reservedNames = new Set([customViewImportKey('Report', 'Executive overview'), customViewImportKey('Malware', 'Executive overview (1)')]);
      const result = await importCustomView(context, user, configuration, { mode: ConfigImportMode.Copy, dryRun: true, reservedNames });
      expect(result).toMatchObject({ status: 'created', exists: false, reason: 'Added as "Executive overview (1)"' });
      expect(reservedNames.has(customViewImportKey('Report', 'Executive overview (1)'))).toBe(true);
      expect(createInternalObject).not.toHaveBeenCalled();
    });

    it('keeps a copy within the length of a name', async () => {
      const name = 'a'.repeat(512);
      platformHas(stored({ name }));
      const result = await importCustomView(context, user, { name, target_entity_type: 'Report' }, { mode: ConfigImportMode.Copy });
      expect(result.reason).toBe(`Added as "${'a'.repeat(508)} (1)"`);
    });
  });

  it('writes a view with the entity type of the bundle, whichever the screen it is imported from', async () => {
    await importCustomView(context, user, { name: 'Malware triage', target_entity_type: 'Malware' }, { mode: ConfigImportMode.Overwrite });
    expect(written()[0]).toMatchObject({ target_entity_type: 'Malware' });
    expect(vi.mocked(createInternalObject).mock.calls[0][3]).toBe(ENTITY_TYPE_CUSTOM_VIEW);
  });
});
