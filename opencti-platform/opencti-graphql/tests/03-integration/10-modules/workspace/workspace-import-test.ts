import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { patchAttribute } from '../../../../src/database/middleware';
import { ENABLED_FEATURE_FLAGS } from '../../../../src/config/conf';
import { addLabel, labelDelete } from '../../../../src/domain/label';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { dashboardsFamily } from '../../../../src/modules/configPreset/registry/dashboards-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import { addWorkspace, findAllWorkspaces, workspaceDelete, workspaceEditField } from '../../../../src/modules/workspace/workspace-domain';
import { exportDashboard } from '../../../../src/modules/workspace/workspace-export';
import { findDashboardsByName, importDashboard } from '../../../../src/modules/workspace/workspace-import';
import { ENTITY_TYPE_WORKSPACE, type BasicStoreEntityWorkspace } from '../../../../src/modules/workspace/workspace-types';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { fromB64, toB64 } from '../../../../src/utils/base64';

const PREFIX = 'Config preset dashboard';
const mode = ConfigImportMode.Overwrite;
const emptyGroup = { mode: 'and', filters: [], filterGroups: [] };

// A manifest with one widget filtered on the given values of a key
const manifestOf = (key: string, values: string[], variables?: unknown[]) => toB64({
  config: {},
  widgets: {
    widget1: {
      id: 'widget1',
      type: 'number',
      perspective: 'entities',
      dataSelection: [{
        label: '',
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: 'entities',
        isTo: true,
        filters: { mode: 'and', filters: [{ key: [key], values, operator: 'eq', mode: 'or' }], filterGroups: [] },
        dynamicFrom: emptyGroup,
        dynamicTo: emptyGroup,
      }],
      parameters: { title: 'Widget' },
      layout: { w: 4, h: 2, x: 0, y: 0, i: 'widget1', moved: false, static: false },
    },
  },
  ...(variables ? { variables } : {}),
}) as string;

const loadWorkspace = async (name: string) => {
  const [workspace] = await findDashboardsByName(testContext, ADMIN_USER, name);
  return workspace;
};
// The members, whatever their order
const membersOf = (workspace: BasicStoreEntityWorkspace) => [...workspace.restricted_members].sort((a, b) => a.id.localeCompare(b.id));
const storedFilterValues = (workspace: BasicStoreEntityWorkspace) => {
  const [widget] = Object.values<{ dataSelection: { filters: { filters: { values: string[] }[] } }[] }>(fromB64(workspace.manifest).widgets);
  return widget.dataSelection[0].filters.filters[0].values;
};

describe('Dashboard import and export (configuration preset)', () => {
  const labelValue = `${PREFIX} label`;
  let labelId: string | undefined;
  const names = [`${PREFIX} one`, `${PREFIX} one (1)`, `${PREFIX} two`, `${PREFIX} round trip`, `${PREFIX} imported`, `${PREFIX} dangling`, `${PREFIX} ambiguous`, `${PREFIX} shared`];

  afterAll(async () => {
    const workspaces = await findAllWorkspaces(testContext, ADMIN_USER, {}) as BasicStoreEntityWorkspace[];
    for (const workspace of workspaces.filter(({ name }) => name.startsWith(PREFIX))) {
      await workspaceDelete(testContext, ADMIN_USER, workspace.id);
    }
    if (labelId) {
      await labelDelete(testContext, ADMIN_USER, labelId).catch(() => undefined);
    }
  });

  it('writes nothing on a dry run, and creates the dashboard with its fields otherwise', async () => {
    const configuration = { name: names[0], description: 'A dashboard', tags: ['soc'], refresh_interval: 300, manifest: manifestOf('entity_type', ['Report']) };
    expect(await importDashboard(testContext, ADMIN_USER, configuration, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await loadWorkspace(names[0])).toBeUndefined();
    expect(await importDashboard(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    const created = await loadWorkspace(names[0]);
    expect(created).toMatchObject({ type: 'dashboard', description: 'A dashboard', tags: ['soc'], refresh_interval: 300 });
    // Only the importing user can open it
    expect(created.restricted_members).toEqual([{ id: ADMIN_USER.id, access_right: 'admin' }]);
  });

  it('skips what is already up to date, refuses an existing name in add mode, and patches the fields that differ', async () => {
    const configuration = { name: names[0], description: 'A dashboard', tags: ['soc'], refresh_interval: 300, manifest: manifestOf('entity_type', ['Report']) };
    expect(await importDashboard(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importDashboard(testContext, ADMIN_USER, configuration, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    // null or absent leaves the dashboard untouched
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[0], description: null }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    const changed = { ...configuration, description: 'Another description', refresh_interval: 60, manifest: manifestOf('entity_type', ['Malware']) };
    expect(await importDashboard(testContext, ADMIN_USER, changed, { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await loadWorkspace(names[0])).toMatchObject({ description: 'A dashboard', refresh_interval: 300 });
    expect(await importDashboard(testContext, ADMIN_USER, changed, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    const overwritten = await loadWorkspace(names[0]);
    expect(overwritten).toMatchObject({ description: 'Another description', refresh_interval: 60 });
    expect(storedFilterValues(overwritten)).toEqual(['Malware']);
    // The members are kept
    expect(overwritten.restricted_members).toEqual([{ id: ADMIN_USER.id, access_right: 'admin' }]);
  });

  it('replaces the variables of the dashboard, which the editing of a manifest would keep', async () => {
    const variable = (name: string) => ({ id: '0b1c9a52-6f2b-4d5e-9a64-6c1f0a0f9a11', name, type: 'text', restriction: { mode: 'none' }, defaultValue: 'phishing' });
    await importDashboard(testContext, ADMIN_USER, { name: names[2], manifest: manifestOf('entity_type', ['Report'], [variable('First')]) }, { mode });
    expect(fromB64((await loadWorkspace(names[2])).manifest).variables.map(({ name }: { name: string }) => name)).toEqual(['First']);
    await importDashboard(testContext, ADMIN_USER, { name: names[2], manifest: manifestOf('entity_type', ['Report'], [variable('Second')]) }, { mode });
    expect(fromB64((await loadWorkspace(names[2])).manifest).variables.map(({ name }: { name: string }) => name)).toEqual(['Second']);
    // A bundle without `variables` (from a platform without the feature flag) keeps them: they are neither compared nor wiped
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[2], manifest: manifestOf('entity_type', ['Report']) }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[2], manifest: manifestOf('entity_type', ['Malware']) }, { mode })).toMatchObject({ status: 'overwritten' });
    const kept = await loadWorkspace(names[2]);
    expect(storedFilterValues(kept)).toEqual(['Malware']);
    expect(fromB64(kept.manifest).variables.map(({ name }: { name: string }) => name)).toEqual(['Second']);
    // An empty list is a bundle that has none on purpose: it clears them
    await importDashboard(testContext, ADMIN_USER, { name: names[2], manifest: manifestOf('entity_type', ['Malware'], []) }, { mode });
    expect(fromB64((await loadWorkspace(names[2])).manifest).variables).toEqual([]);
  });

  it('adds a copy under a free name', async () => {
    const configuration = { name: names[0], manifest: manifestOf('entity_type', ['Report']) };
    const dryRun = await importDashboard(testContext, ADMIN_USER, configuration, { mode: ConfigImportMode.Copy, dryRun: true });
    expect(dryRun).toMatchObject({ status: 'created', exists: true });
    expect(dryRun.reason).toContain(`Added as "${names[1]}"`);
    expect(await loadWorkspace(names[1])).toBeUndefined();
    expect(await importDashboard(testContext, ADMIN_USER, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'created', exists: true });
    expect(await loadWorkspace(names[1])).toMatchObject({ type: 'dashboard' });
    // A name taken by an earlier item of the same dry run is not free
    const reservedNames = new Set<string>();
    const first = await importDashboard(testContext, ADMIN_USER, { name: 'Config preset dashboard fresh' }, { mode: ConfigImportMode.Copy, dryRun: true, reservedNames });
    const second = await importDashboard(testContext, ADMIN_USER, { name: 'Config preset dashboard fresh' }, { mode: ConfigImportMode.Copy, dryRun: true, reservedNames });
    expect(first.reason).toBeUndefined();
    expect(second.reason).toContain('Added as "Config preset dashboard fresh (1)"');
  });

  it('finds the dashboard by the name the platform stores, whatever the spaces around the name of the bundle: no duplicate', async () => {
    const name = `${PREFIX} padded`;
    // The platform trims the names at indexing
    await addWorkspace(testContext, ADMIN_USER, { type: 'dashboard', name: `${name} ` });
    const [stored] = await findDashboardsByName(testContext, ADMIN_USER, name);
    expect(stored.name).toBe(name);
    // The import overwrites it, it does not add a second dashboard next to it
    expect(await importDashboard(testContext, ADMIN_USER, { name: `  ${name} `, description: 'imported' }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await findDashboardsByName(testContext, ADMIN_USER, name)).toMatchObject([{ description: 'imported' }]);
    // A copy is named after the stored name too
    expect(await importDashboard(testContext, ADMIN_USER, { name: ` ${name}  ` }, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'created', exists: true, reason: `Added as "${name} (1)"` });
    // And the name of an export is the one of the bundle
    expect((await exportDashboard(testContext, ADMIN_USER, stored)).name).toBe(name);
  });

  it('clears the description, the tags and the refresh interval of the dashboard when the bundle has none, as it exports them empty', async () => {
    const name = `${PREFIX} cleared`;
    await importDashboard(testContext, ADMIN_USER, { name, description: 'A description', tags: ['soc'], refresh_interval: 300 }, { mode });
    expect(await loadWorkspace(name)).toMatchObject({ description: 'A description', tags: ['soc'], refresh_interval: 300 });
    // A dashboard without description, tag nor refresh interval exports them empty (0 is no refresh), and the import writes them
    const source = await addWorkspace(testContext, ADMIN_USER, { type: 'dashboard', name: `${PREFIX} cleared source` });
    const exported = await exportDashboard(testContext, ADMIN_USER, await loadWorkspace(source.name));
    expect(exported).toMatchObject({ description: '', tags: [], refresh_interval: 0 });
    expect(await importDashboard(testContext, ADMIN_USER, { ...exported, name }, { mode })).toMatchObject({ status: 'overwritten' });
    const cleared = await loadWorkspace(name);
    expect(cleared.description ?? '').toBe('');
    expect(cleared.tags ?? []).toEqual([]);
    expect(cleared.refresh_interval ?? 0).toBe(0);
    // And the same import is then up to date
    expect(await importDashboard(testContext, ADMIN_USER, { ...exported, name }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
  });

  it('names the copies of two dashboards of one bundle as the preview said, item after item as the engine does', async () => {
    const name = `${PREFIX} copies`;
    await importDashboard(testContext, ADMIN_USER, { name }, { mode });
    const copy = ConfigImportMode.Copy;
    const reservedNames = new Set<string>();
    // Each item is computed on the names of the plan, then written from what the platform holds
    const promised: string[] = [];
    for (let index = 0; index < 2; index += 1) {
      const preview = await importDashboard(testContext, ADMIN_USER, { name }, { mode: copy, dryRun: true, reservedNames });
      promised.push(/Added as "(.+)"/.exec(preview.reason ?? '')?.[1] ?? '');
      await importDashboard(testContext, ADMIN_USER, { name }, { mode: copy });
    }
    expect(promised).toEqual([`${name} (1)`, `${name} (2)`]);
    for (const copyName of promised) {
      expect(await loadWorkspace(copyName)).toMatchObject({ type: 'dashboard' });
    }
  });

  it('does not see a dashboard the importing user cannot open: it neither finds it nor overwrites it', async () => {
    const name = `${PREFIX} not mine`;
    const foreign = await addWorkspace(testContext, ADMIN_USER, { type: 'dashboard', name });
    try {
      // Its only member is someone else, even a user with every capability is not a member of it
      await patchAttribute(testContext, ADMIN_USER, foreign.id, ENTITY_TYPE_WORKSPACE, {
        description: 'not mine',
        restricted_members: [{ id: '2f3c0b5e-7a1d-4c8e-9b2f-5d6e7f8a9b0c', access_right: 'admin' }],
      });
      expect(await findDashboardsByName(testContext, ADMIN_USER, name)).toEqual([]);
      expect((await dashboardsFamily.resolveItems(testContext, ADMIN_USER, null, [])).map(({ label }) => label)).not.toContain(name);
      // Overwrite does not reach it: the dashboard is created, the other one is left as it was
      expect(await importDashboard(testContext, ADMIN_USER, { name, description: 'imported' }, { mode })).toMatchObject({ status: 'created', exists: false });
      const all = await findAllWorkspaces(testContext, SYSTEM_USER, {}) as BasicStoreEntityWorkspace[];
      const sameName = all.filter((workspace) => workspace.name === name);
      expect(sameName).toHaveLength(2);
      expect(sameName.find(({ id }) => id === foreign.id)).toMatchObject({ description: 'not mine' });
    } finally {
      const all = await findAllWorkspaces(testContext, SYSTEM_USER, {}) as BasicStoreEntityWorkspace[];
      for (const workspace of all.filter((found) => found.name === name)) {
        await workspaceDelete(testContext, SYSTEM_USER, workspace.id);
      }
    }
  });

  it('refuses a name twice in a dry run, and a name that several dashboards have', async () => {
    const reservedNames = new Set<string>();
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[6] }, { mode, dryRun: true, reservedNames })).toMatchObject({ status: 'created' });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[6] }, { mode, dryRun: true, reservedNames })).toMatchObject({ status: 'failed', code: 'duplicate', exists: false });
    await addWorkspace(testContext, ADMIN_USER, { type: 'dashboard', name: names[6] });
    await addWorkspace(testContext, ADMIN_USER, { type: 'dashboard', name: names[6] });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[6] }, { mode })).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
    // A copy does not care: it takes a free name
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[6] }, { mode: ConfigImportMode.Copy, dryRun: true })).toMatchObject({ status: 'created' });
  });

  it('refuses an invalid configuration with a reason, an invalid manifest included', async () => {
    expect(await importDashboard(testContext, ADMIN_USER, { name: '   ' }, { mode })).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[5], unknown: true }, { mode })).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[5], manifest: 'not a manifest' }, { mode })).toMatchObject({ status: 'failed', code: 'invalid' });
    // A widget without data selection is refused, not an error
    const withoutSelection = toB64({ widgets: { w: { id: 'w', type: 'number' } } });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[5], manifest: withoutSelection }, { mode })).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[5], manifest: manifestOf('entity_type', ['Report'], [{ name: 'Bad', type: 'unknown' }]) }, { mode })).toMatchObject({ status: 'failed', code: 'invalid' });
    // A variable that is not well formed is refused with the reason of its validation
    const malformed = { id: '4e6f5a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5b', name: 'Malformed', type: 'label', restriction: { mode: 'selection', values: [1, null] }, defaultValue: '0b1c9a52-6f2b-4d5e-9a64-6c1f0a0f9a11' };
    const refusedVariable = await importDashboard(testContext, ADMIN_USER, { name: names[5], manifest: manifestOf('entity_type', ['Report'], [malformed]) }, { mode });
    expect(refusedVariable).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(refusedVariable.reason).toContain('Invalid dashboard variable restriction');
    expect(await loadWorkspace(names[5])).toBeUndefined();
  });

  it('exports the ids of the filters as standard ids and imports them back as the ids of the platform', async () => {
    const label = await addLabel(testContext, ADMIN_USER, { value: labelValue, color: '#ff0000' });
    labelId = label.id;
    await importDashboard(testContext, ADMIN_USER, { name: names[3], manifest: manifestOf('objectLabel', [label.standard_id]) }, { mode });
    const stored = await loadWorkspace(names[3]);
    expect(storedFilterValues(stored)).toEqual([label.id]);

    const exported = await exportDashboard(testContext, ADMIN_USER, stored);
    expect(storedFilterValues({ manifest: exported.manifest } as BasicStoreEntityWorkspace)).toEqual([label.standard_id]);
    expect(JSON.stringify(exported)).not.toContain(label.id);

    // The bundle item built by the family is the same
    const [item] = await dashboardsFamily.resolveItems(testContext, ADMIN_USER, [stored.standard_id], []);
    expect((await exportConfigPresetItem(testContext, ADMIN_USER, dashboardsFamily, item)).configuration).toEqual(exported);

    // On a platform that has the label, the ids are the ones of the platform: no warning
    const imported = await importDashboard(testContext, ADMIN_USER, { ...exported, name: names[4] }, { mode });
    expect(imported).toMatchObject({ status: 'created' });
    expect(imported.reason).toBeUndefined();
    expect(storedFilterValues(await loadWorkspace(names[4]))).toEqual([label.id]);

    // On a platform that has not, the reference is kept as it is, as the file import does
    await labelDelete(testContext, ADMIN_USER, label.id);
    const dangling = await importDashboard(testContext, ADMIN_USER, { ...exported, name: names[5] }, { mode });
    expect(dangling).toMatchObject({ status: 'created' });
    expect(dangling.reason).toBeUndefined();
    expect(storedFilterValues(await loadWorkspace(names[5]))).toEqual([label.standard_id]);
  });

  it('converts the ids held by the variables as the ones of the filters, and takes the variables only with their feature flag', async () => {
    const label = await addLabel(testContext, ADMIN_USER, { value: `${PREFIX} variable label`, color: '#00ff00' });
    const name = `${PREFIX} variables`;
    const variablesOf = (workspace: { manifest?: string }) => fromB64(workspace.manifest).variables;
    const variable = { id: '5a1f0c2e-7b3d-4e8a-9c4b-1d2e3f4a5b6c', name: 'Label', type: 'label', restriction: { mode: 'selection', values: [label.id] }, defaultValue: label.id };
    const textVariable = { id: '6b2a1d3f-8c4e-4f9b-8d5c-2e3f4a5b6c7d', name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: 'phishing' };
    try {
      await importDashboard(testContext, ADMIN_USER, { name, manifest: manifestOf('entity_type', ['Report'], [variable, textVariable]) }, { mode });
      const stored = await loadWorkspace(name);
      expect(variablesOf(stored)[0]).toMatchObject({ defaultValue: label.id, restriction: { mode: 'selection', values: [label.id] } });

      // Exported as standard ids, a literal left as it is
      const exported = await exportDashboard(testContext, ADMIN_USER, stored);
      expect(variablesOf(exported)[0]).toMatchObject({ defaultValue: label.standard_id, restriction: { mode: 'selection', values: [label.standard_id] } });
      expect(variablesOf(exported)[1]).toMatchObject({ defaultValue: 'phishing' });
      expect(JSON.stringify(exported)).not.toContain(label.id);

      // Imported as the ids of the platform, with no warning
      const imported = await importDashboard(testContext, ADMIN_USER, { ...exported, name: `${PREFIX} variables copy` }, { mode });
      expect(imported).toMatchObject({ status: 'created' });
      expect(imported.reason).toBeUndefined();
      expect(variablesOf(await loadWorkspace(`${PREFIX} variables copy`))[0]).toMatchObject({ defaultValue: label.id, restriction: { values: [label.id] } });

      // Without the feature flag the variables stay out of the bundle: not exported, not imported, and the ones of a dashboard are not replaced
      const enabled = [...ENABLED_FEATURE_FLAGS];
      ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
      try {
        expect(variablesOf(await exportDashboard(testContext, ADMIN_USER, stored))).toBeUndefined();
        await importDashboard(testContext, ADMIN_USER, { ...exported, name: `${PREFIX} variables off` }, { mode });
        expect(variablesOf(await loadWorkspace(`${PREFIX} variables off`))).toBeUndefined();
        const overwrite = await importDashboard(testContext, ADMIN_USER, { name, manifest: manifestOf('entity_type', ['Malware'], []) }, { mode });
        expect(overwrite).toMatchObject({ status: 'overwritten' });
        const overwritten = await loadWorkspace(name);
        expect(storedFilterValues(overwritten)).toEqual(['Malware']);
        expect(variablesOf(overwritten)).toHaveLength(2);
        // The variables of the bundle do not make a dashboard that has the same widgets differ
        expect(await importDashboard(testContext, ADMIN_USER, { name, manifest: manifestOf('entity_type', ['Malware'], [textVariable]) }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
      } finally {
        ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...enabled);
      }

      // A reference the platform does not have is kept as it is, as in the filters
      await labelDelete(testContext, ADMIN_USER, label.id);
      const dangling = await importDashboard(testContext, ADMIN_USER, { ...exported, name: `${PREFIX} variables dangling` }, { mode });
      expect(dangling).toMatchObject({ status: 'created' });
      expect(dangling.reason).toBeUndefined();
      expect(variablesOf(await loadWorkspace(`${PREFIX} variables dangling`))[0]).toMatchObject({ defaultValue: label.standard_id });
    } finally {
      await labelDelete(testContext, ADMIN_USER, label.id).catch(() => undefined);
    }
  });

  it('does not export nor import the presets, and an overwrite keeps the presets of the dashboard', async () => {
    const name = `${PREFIX} presets`;
    const variable = { id: '7c3b2e4a-9d5f-4a0c-8e6d-3f4a5b6c7d8e', name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: 'phishing' };
    const preset = { id: '8d4c3f5b-0e6a-4b1d-9f7e-4a5b6c7d8e9f', name: 'Phishing', values: { [variable.id]: 'phishing' }, config: { startDate: null, endDate: null, relativeDate: null } };
    await importDashboard(testContext, ADMIN_USER, { name, manifest: manifestOf('entity_type', ['Report'], [variable]) }, { mode });
    const created = await loadWorkspace(name);
    await patchAttribute(testContext, ADMIN_USER, created.id, ENTITY_TYPE_WORKSPACE, {
      manifest: toB64({ ...fromB64<Record<string, unknown>>(created.manifest), presets: [preset] }) as string,
    });
    // Not exported
    expect(fromB64((await exportDashboard(testContext, ADMIN_USER, await loadWorkspace(name))).manifest).presets).toBeUndefined();
    // Not imported: a bundle that has some creates a dashboard without
    const withPresets = toB64({ ...fromB64<Record<string, unknown>>(manifestOf('entity_type', ['Report'], [variable])), presets: [preset] }) as string;
    expect(await importDashboard(testContext, ADMIN_USER, { name: `${PREFIX} presets copy`, manifest: withPresets }, { mode })).toMatchObject({ status: 'created' });
    expect(fromB64((await loadWorkspace(`${PREFIX} presets copy`)).manifest).presets).toBeUndefined();
    // An overwrite writes the widgets of the bundle and keeps the presets the dashboard has
    expect(await importDashboard(testContext, ADMIN_USER, { name, manifest: withPresets }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(await importDashboard(testContext, ADMIN_USER, { name, manifest: manifestOf('entity_type', ['Malware'], [variable]) }, { mode })).toMatchObject({ status: 'overwritten' });
    const overwritten = await loadWorkspace(name);
    expect(storedFilterValues(overwritten)).toEqual(['Malware']);
    expect(fromB64(overwritten.manifest).presets).toEqual([preset]);
  });

  it('exports a saved filter that does not exist as it is, instead of failing', async () => {
    const [workspace] = await findDashboardsByName(testContext, ADMIN_USER, names[4]);
    const manifest = fromB64(workspace.manifest);
    manifest.widgets.widget1.dataSelection[0].filters_id = '3b2a1c0d-9e8f-4a7b-8c6d-5e4f3a2b1c0d';
    await workspaceEditField(testContext, ADMIN_USER, workspace.id, [{ key: 'manifest', value: [toB64(manifest) as string] }]);
    const exported = await exportDashboard(testContext, ADMIN_USER, await loadWorkspace(names[4]));
    expect(fromB64(exported.manifest).widgets.widget1.dataSelection[0].filters_id).toBe('3b2a1c0d-9e8f-4a7b-8c6d-5e4f3a2b1c0d');
  });

  it('does not export who can open a dashboard, creates it for the importing user only and never touches the members of an existing one', async () => {
    // A dashboard shared with everyone is exported without it
    await importDashboard(testContext, ADMIN_USER, { name: names[7] }, { mode });
    await patchAttribute(testContext, ADMIN_USER, (await loadWorkspace(names[7])).id, ENTITY_TYPE_WORKSPACE, {
      restricted_members: [{ id: ADMIN_USER.id, access_right: 'admin' }, { id: 'ALL', access_right: 'view' }],
    });
    expect(await exportDashboard(testContext, ADMIN_USER, await loadWorkspace(names[7]))).toEqual({ name: names[7], description: '', tags: [], refresh_interval: 0 });
    // The bundle does not carry it: the key is refused, as every unknown one
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[7], shared_with_all: 'view' }, { mode })).toMatchObject({ status: 'failed', code: 'invalid' });
    // A new dashboard is the importing user's, as with the file import
    const name = `${PREFIX} members`;
    expect(await importDashboard(testContext, ADMIN_USER, { name }, { mode })).toMatchObject({ status: 'created' });
    expect(membersOf(await loadWorkspace(name))).toEqual([{ id: ADMIN_USER.id, access_right: 'admin' }]);
    // An overwrite keeps the members of the dashboard, whoever they are
    expect(await importDashboard(testContext, ADMIN_USER, { name: names[7], description: 'after' }, { mode })).toMatchObject({ status: 'overwritten' });
    expect(membersOf(await loadWorkspace(names[7]))).toEqual([{ id: 'ALL', access_right: 'view' }, { id: ADMIN_USER.id, access_right: 'admin' }].sort((a, b) => a.id.localeCompare(b.id)));
  });

  it('lists the dashboards only, never an investigation', async () => {
    await addWorkspace(testContext, ADMIN_USER, { type: 'investigation', name: `${PREFIX} investigation` });
    const items = await dashboardsFamily.resolveItems(testContext, ADMIN_USER, null, []);
    const labels = items.map(({ label }) => label);
    expect(labels).toContain(names[0]);
    expect(labels).not.toContain(`${PREFIX} investigation`);
    const page = await dashboardsFamily.listItems(testContext, ADMIN_USER, { first: 50, search: PREFIX });
    expect(page.edges.map(({ node }) => node.label)).not.toContain(`${PREFIX} investigation`);
  });
});
