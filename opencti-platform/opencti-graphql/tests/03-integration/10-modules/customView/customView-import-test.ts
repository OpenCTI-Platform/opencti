import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { findLabelPaginated } from '../../../../src/domain/label';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import { customViewsFamily } from '../../../../src/modules/configPreset/registry/customViews-configPreset-registry';
import { addCustomView, deleteCustomView, exportCustomView, findAllCustomViews } from '../../../../src/modules/customView/customView-domain';
import { exportCustomViewToBundle } from '../../../../src/modules/customView/customView-export';
import { findCustomViewsByName, importCustomView } from '../../../../src/modules/customView/customView-import';
import type { BasicStoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import { redisClearTelemetryGauge } from '../../../../src/database/redis';
import { TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED, TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED } from '../../../../src/manager/telemetryManager';

const PREFIX = 'Config preset custom view';
const mode = ConfigImportMode.Overwrite;
const TARGET = 'Report';
const emptyGroup = { mode: 'and', filters: [], filterGroups: [] };

// A manifest with one widget filtered on the given values of a key
const manifestOf = (key: string, values: string[]) => toB64({
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
}) as string;

// A label of the platform, never created nor deleted here: the label events of the stream are counted by the stream tests (tests/10-streams),
// which run after this file and read every event since the start
const existingLabel = async () => {
  const page = await findLabelPaginated(testContext, ADMIN_USER, { first: 1 });
  return page.edges[0].node as { id: string; standard_id: string };
};
// The standard id of a label the platform does not have
const MISSING_LABEL_ID = 'label--7d9e2b34-5c1a-4f6e-9a3b-0e8c4d2f1a65';

const loadView = async (name: string, targetEntityType = TARGET) => {
  const [view] = await findCustomViewsByName(testContext, ADMIN_USER, targetEntityType, name);
  return view;
};
const storedFilterValues = (view: BasicStoreEntityCustomView) => {
  const [widget] = Object.values<{ dataSelection: { filters: { filters: { values: string[] }[] } }[] }>(fromB64(view.manifest).widgets);
  return widget.dataSelection[0].filters.filters[0].values;
};

describe('Custom view import and export (configuration preset)', () => {
  afterAll(async () => {
    const page = await findAllCustomViews(testContext, ADMIN_USER, null, { first: 500 });
    for (const { node } of page.edges.filter(({ node: view }) => view.name.startsWith(PREFIX))) {
      await deleteCustomView(testContext, ADMIN_USER, node.id);
    }
    // Creations count in the telemetry gauges that the tests of the custom view resolvers check, which run after this file
    await redisClearTelemetryGauge(TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED);
    await redisClearTelemetryGauge(TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED);
  });

  it('writes nothing on a dry run, and creates the view neither enabled nor the default of its entity type otherwise', async () => {
    const name = `${PREFIX} one`;
    const configuration = { name, target_entity_type: TARGET, description: 'A view', manifest: manifestOf('entity_type', ['Report']) };
    expect(await importCustomView(testContext, ADMIN_USER, configuration, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await loadView(name)).toBeUndefined();
    expect(await importCustomView(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await loadView(name)).toMatchObject({ name, description: 'A view', target_entity_type: TARGET, enabled: false, default: false, slug: 'config-preset-custom-view-one' });
    // The same import is then up to date, and a dry run says so
    expect(await importCustomView(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
  });

  it('overwrites the description and the manifest of the view that has the name, and keeps whether it is enabled and the default', async () => {
    const name = `${PREFIX} state`;
    await addCustomView(testContext, ADMIN_USER, { name, targetEntityType: TARGET, description: 'Old', enabled: true, default: true, manifest: manifestOf('entity_type', ['Report']) });
    const configuration = { name, target_entity_type: TARGET, description: 'New', manifest: manifestOf('entity_type', ['Malware']) };
    expect(await importCustomView(testContext, ADMIN_USER, configuration, { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await loadView(name)).toMatchObject({ description: 'Old' });
    expect(await importCustomView(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    const overwritten = await loadView(name);
    expect(overwritten).toMatchObject({ description: 'New', enabled: true, default: true, slug: 'config-preset-custom-view-state' });
    expect(storedFilterValues(overwritten)).toEqual(['Malware']);
    // Still one view of the name
    expect((await findCustomViewsByName(testContext, ADMIN_USER, TARGET, name))).toHaveLength(1);
  });

  it('keeps the views of two entity types apart: the same name is another view', async () => {
    const name = `${PREFIX} two types`;
    await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: TARGET, description: 'Report view' }, { mode });
    expect(await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: 'Malware', description: 'Malware view' }, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await loadView(name, TARGET)).toMatchObject({ description: 'Report view' });
    expect(await loadView(name, 'Malware')).toMatchObject({ description: 'Malware view' });
  });

  it('refuses a view of an entity type that cannot have custom views, without writing it', async () => {
    const name = `${PREFIX} note`;
    expect(await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: 'Note' }, { mode }))
      .toMatchObject({ status: 'failed', code: 'entity_type', exists: false });
    expect(await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: 'Not-An-Entity-Type' }, { mode })).toMatchObject({ status: 'failed', code: 'entity_type' });
    expect(await loadView(name, 'Note')).toBeUndefined();
  });

  it('refuses a name that several views of the entity type have, and overwrites none of them', async () => {
    const name = `${PREFIX} ambiguous`;
    await addCustomView(testContext, ADMIN_USER, { name, targetEntityType: TARGET, description: 'First' });
    await addCustomView(testContext, ADMIN_USER, { name, targetEntityType: TARGET, description: 'Second' });
    expect(await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: TARGET, description: 'Imported' }, { mode })).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
    const views = await findCustomViewsByName(testContext, ADMIN_USER, TARGET, name);
    expect(views.map(({ description }) => description).sort()).toEqual(['First', 'Second']);
  });

  it('adds a copy under a free name, never the default nor enabled, and leaves the view as it is', async () => {
    const name = `${PREFIX} copy`;
    await addCustomView(testContext, ADMIN_USER, { name, targetEntityType: TARGET, description: 'Source', enabled: true, default: true });
    const copy = ConfigImportMode.Copy;
    const reservedNames = new Set<string>();
    // Each item is computed on the names of the plan, then written from what the platform holds
    const promised: string[] = [];
    for (let index = 0; index < 2; index += 1) {
      const preview = await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: TARGET, description: 'Copied' }, { mode: copy, dryRun: true, reservedNames });
      promised.push(/Added as "(.+)"/.exec(preview.reason ?? '')?.[1] ?? '');
      await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: TARGET, description: 'Copied' }, { mode: copy });
    }
    expect(promised).toEqual([`${name} (1)`, `${name} (2)`]);
    for (const copyName of promised) {
      expect(await loadView(copyName)).toMatchObject({ description: 'Copied', enabled: false, default: false });
    }
    // The source keeps its description and stays the default of its entity type
    expect(await loadView(name)).toMatchObject({ description: 'Source', enabled: true, default: true });
  });

  it('exports the view in the import format with standard ids, and imports it back as the same view', async () => {
    const label = await existingLabel();
    const name = `${PREFIX} round trip`;
    await addCustomView(testContext, ADMIN_USER, { name, targetEntityType: TARGET, enabled: true, default: true, manifest: manifestOf('objectLabel', [label.id]) });
    const view = await loadView(name);
    const exported = await exportCustomViewToBundle(testContext, ADMIN_USER, view);
    expect(Object.keys(exported).sort()).toEqual(['description', 'manifest', 'name', 'target_entity_type']);
    expect(exported).toMatchObject({ name, target_entity_type: TARGET, description: '' });
    expect(fromB64(exported.manifest as string).widgets.widget1.dataSelection[0].filters.filters[0].values).toEqual([label.standard_id]);
    // The same platform: the ids are converted back to its own, so the view is up to date
    expect(await importCustomView(testContext, ADMIN_USER, exported, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(storedFilterValues(await loadView(name))).toEqual([label.id]);
    // Through the item of the registry, which is what the export of a bundle writes
    const [item] = await customViewsFamily.resolveItems(testContext, ADMIN_USER, [view.standard_id], []);
    expect(item).toMatchObject({ id: view.standard_id, label: `${name} (${TARGET})`, translatable: false });
    expect((await exportConfigPresetItem(testContext, ADMIN_USER, customViewsFamily, item)).configuration).toEqual(exported);
  });

  it('keeps a reference the platform does not have as it is, as the file import does', async () => {
    const name = `${PREFIX} dangling`;
    const result = await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: TARGET, manifest: manifestOf('objectLabel', [MISSING_LABEL_ID]) }, { mode });
    expect(result).toMatchObject({ status: 'created' });
    expect(storedFilterValues(await loadView(name))).toEqual([MISSING_LABEL_ID]);
  });

  it('exports a saved filter that does not exist as it is, where the file export fails', async () => {
    const name = `${PREFIX} missing saved filter`;
    const savedFilterId = '5a1f3c7e-2b4d-4e69-8c0a-9d7e6f5b4a32';
    const manifest = toB64({
      config: {},
      widgets: { widget1: { id: 'widget1', type: 'number', perspective: 'entities', dataSelection: [{ label: '', attribute: 'entity_type', perspective: 'entities', filters_id: savedFilterId }], parameters: {} } },
    }) as string;
    await addCustomView(testContext, ADMIN_USER, { name, targetEntityType: TARGET, manifest });
    const view = await loadView(name);
    const exported = await exportCustomViewToBundle(testContext, ADMIN_USER, view);
    expect(fromB64(exported.manifest as string).widgets.widget1.dataSelection[0].filters_id).toBe(savedFilterId);
    // The same custom view through the file export is still an error: only the export of a bundle keeps the reference
    await expect(exportCustomView(testContext, ADMIN_USER, view)).rejects.toThrow('Saved filter not found');
  });

  it('finds a view by its exact name: the filter of the platform does not tell the case apart, the import does', async () => {
    const upper = `${PREFIX} Case`;
    const lower = `${PREFIX} case`;
    await addCustomView(testContext, ADMIN_USER, { name: upper, targetEntityType: TARGET, description: 'Upper' });
    await addCustomView(testContext, ADMIN_USER, { name: lower, targetEntityType: TARGET, description: 'Lower' });
    expect((await findCustomViewsByName(testContext, ADMIN_USER, TARGET, upper)).map(({ name }) => name)).toEqual([upper]);
    expect((await findCustomViewsByName(testContext, ADMIN_USER, TARGET, lower)).map(({ name }) => name)).toEqual([lower]);
    // Neither ambiguous nor mixed up: the overwrite reaches the view that has this very name
    expect(await importCustomView(testContext, ADMIN_USER, { name: lower, target_entity_type: TARGET, description: 'Imported' }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await loadView(lower)).toMatchObject({ description: 'Imported' });
    expect(await loadView(upper)).toMatchObject({ description: 'Upper' });
  });

  it('refuses a widget that uses dashboard variables, as every way into a custom view does', async () => {
    const name = `${PREFIX} variables`;
    const variableId = '11111111-1111-4111-8111-111111111111';
    const result = await importCustomView(testContext, ADMIN_USER, { name, target_entity_type: TARGET, manifest: manifestOf('entity_type', [`$var:${variableId}`]) }, { mode });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(await loadView(name)).toBeUndefined();
  });

  it('lists the views by name with the entity type, and pages them, for the export of a bundle', async () => {
    const all = await customViewsFamily.listItems(testContext, ADMIN_USER, { first: 500, search: PREFIX });
    const labels = all.edges.map(({ node }) => node.label);
    expect(labels).toContain(`${PREFIX} one (${TARGET})`);
    expect(labels).toContain(`${PREFIX} two types (Malware)`);
    // Ordered by the name of the view, not by its label: the entity type that ends the label is not part of the order
    // The index orders the names without telling the case apart
    const names = labels.map((label) => label.replace(/ \([^()]+\)$/, '').toLowerCase());
    expect(names).toEqual([...names].sort());
    const one = await customViewsFamily.listItems(testContext, ADMIN_USER, { first: 1, search: PREFIX });
    expect(one.edges).toHaveLength(1);
    expect(one.pageInfo.hasNextPage).toBe(true);
  });
});
