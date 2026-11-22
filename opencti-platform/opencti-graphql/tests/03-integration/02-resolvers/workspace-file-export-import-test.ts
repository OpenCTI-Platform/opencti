import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import pjson from '../../../package.json';
import { elLoadById } from '../../../src/database/engine';
import { findLabelPaginated } from '../../../src/domain/label';
import { addSavedFilter, deleteSavedFilter } from '../../../src/modules/savedFilter/savedFilter-domain';
import { fromB64, toB64 } from '../../../src/utils/base64';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createUploadFromBuffer, createUploadFromTestDataFile, queryAsAdmin } from '../../utils/testQueryHelper';

// The single-file export and import of a dashboard (the "Export" action of a dashboard, the "Import dashboard" file card, what XTM Hub calls),
// and of a widget: guarded as a whole, from the resolvers, because the configuration bundle shares their code and files travel between platforms
// and versions. What a file holds, and what an import makes of it, must not change.

const DELETE_QUERY = gql`
  mutation workspaceDelete($id: ID!) {
    workspaceDelete(id: $id)
  }
`;
const ADD_QUERY = gql`
  mutation WorkspaceAdd($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) { id name }
  }
`;
const PATCH_QUERY = gql`
  mutation WorkspaceEdit($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) { id }
  }
`;
const READ_QUERY = gql`
  query workspace($id: String!) {
    workspace(id: $id) {
      id
      type
      name
      manifest
      authorizedMembers { id access_right }
    }
  }
`;
const EXPORT_QUERY = gql`
  query workspaceExport($id: String!) {
    workspace(id: $id) { toConfigurationExport }
  }
`;
const IMPORT_QUERY = gql`
  mutation workspaceImport($file: Upload!) {
    workspaceConfigurationImport(file: $file)
  }
`;
const EXPORT_WIDGET_QUERY = gql`
  query workspaceWidgetExport($id: String!, $widgetId: ID!) {
    workspace(id: $id) { toWidgetExport(widgetId: $widgetId) }
  }
`;
const IMPORT_WIDGET_QUERY = gql`
  mutation workspaceImportWidget($id: ID!, $input: ImportConfigurationInput!) {
    workspaceWidgetConfigurationImport(id: $id, input: $input) { id manifest }
  }
`;

type Selection = Record<string, unknown>;
type Widget = { id: string; type: string; perspective?: string; dataSelection: Selection[]; parameters: unknown; layout: unknown };

const filterOn = (key: string, values: unknown[]) => ({ mode: 'and', filters: [{ key, values, operator: 'eq', mode: 'or' }], filterGroups: [] });
const widgetOf = (id: string, selection: Selection, index: number): Widget => ({
  id,
  type: 'vertical-bar',
  perspective: 'entities',
  dataSelection: [{ date_attribute: 'created_at', label: `Selection of ${id}`, ...selection }],
  parameters: { title: `Widget ${id}` },
  layout: { w: 4, h: 3, x: index * 4, y: 0, i: id, moved: false, static: false },
});

// The data of a response, which is never empty for the queries of this file (an error is asserted on its own)
const dataOf = (result: { data?: unknown }) => result.data as Record<string, any>;
const read = async (id: string) => dataOf(await queryAsAdmin({ query: READ_QUERY, variables: { id } })).workspace;
const remove = (id: string) => queryAsAdmin({ query: DELETE_QUERY, variables: { id } });
const upload = (content: string, name = 'dashboard.json') => createUploadFromBuffer(Buffer.from(content), name, 'application/json');
// The id of a member of a workspace is `<workspace>_<member>_<index>`: the member, with its right
const membersOf = (workspace: { authorizedMembers: { id: string; access_right: string }[] }) => workspace.authorizedMembers.map(({ id, access_right }) => ({ member: id.split('_')[1], access_right }));
const importFile = async (file: ReturnType<typeof upload>) => queryAsAdmin({ query: IMPORT_QUERY, variables: { file } });

describe('Single-file export and import of a dashboard and of a widget', () => {
  const createdIds: string[] = [];
  const savedFilterContent = filterOn('relationship_type', ['targets']);
  let labelId = '';
  let markingId = '';
  let malwareId = '';
  let savedFilterId = '';
  let sourceId = '';
  let sourceManifest: { widgets: Record<string, Widget>; config: unknown };

  beforeAll(async () => {
    // A label of the platform, never created nor deleted here: the label events of the stream are counted by the stream tests (tests/10-streams)
    const page = await findLabelPaginated(testContext, ADMIN_USER, { first: 1 });
    labelId = page.edges[0].node.id;
    const marking = await elLoadById(testContext, ADMIN_USER, 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9') as { internal_id: string };
    markingId = marking.internal_id;
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85') as { internal_id: string };
    malwareId = malware.internal_id;
    const savedFilter = await addSavedFilter(testContext, ADMIN_USER, { name: 'file-export-import-filter', filters: JSON.stringify(savedFilterContent), scope: 'Stix-Core-Object' });
    savedFilterId = savedFilter.id;
    sourceManifest = {
      config: {},
      widgets: {
        'widget-label': widgetOf('widget-label', { filters: filterOn('objectLabel', [labelId]) }, 0),
        'widget-marking': widgetOf('widget-marking', { filters: filterOn('objectMarking', [markingId]) }, 1),
        'widget-entity': widgetOf('widget-entity', { filters: filterOn('objects', [malwareId]) }, 2),
        'widget-saved': widgetOf('widget-saved', { filters_id: savedFilterId, filters: null }, 3),
      },
    };
    // Shared with everyone: an import must not carry it over
    const added = await queryAsAdmin({
      query: ADD_QUERY,
      variables: { input: { type: 'dashboard', name: 'File export import source', authorized_members: [{ id: 'ALL', access_right: 'view' }] } },
    });
    sourceId = dataOf(added).workspaceAdd.id;
    createdIds.push(sourceId);
    const patched = await queryAsAdmin({ query: PATCH_QUERY, variables: { id: sourceId, input: { key: 'manifest', value: toB64(sourceManifest) } } });
    expect(patched.errors).toBeUndefined();
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await remove(id);
    }
    await deleteSavedFilter(testContext, ADMIN_USER, savedFilterId).catch(() => undefined);
  });

  it('exports a file of the exact shape older platforms and XTM Hub rely on', async () => {
    const result = await queryAsAdmin({ query: EXPORT_QUERY, variables: { id: sourceId } });
    expect(result.errors).toBeUndefined();
    const file = JSON.parse(dataOf(result).workspace.toConfigurationExport);
    expect(Object.keys(file).sort()).toEqual(['configuration', 'openCTI_version', 'type']);
    expect(file.openCTI_version).toBe(pjson.version);
    expect(file.type).toBe('dashboard');
    expect(Object.keys(file.configuration).sort()).toEqual(['manifest', 'name']);
    expect(file.configuration.name).toBe('File export import source');
    // The manifest is the base64 of the widgets and the config, nothing server side
    const manifest = fromB64<{ widgets: Record<string, Widget>; config: unknown }>(file.configuration.manifest);
    expect(Object.keys(manifest).sort()).toEqual(['config', 'widgets']);
    expect(Object.keys(manifest.widgets).sort()).toEqual(Object.keys(sourceManifest.widgets).sort());
    // The ids of the platform do not travel: the filters hold standard ids, the saved filter is inlined
    expect(file.configuration.manifest).not.toContain(toB64(labelId));
    const exportedText = JSON.stringify(manifest);
    [labelId, markingId, malwareId, savedFilterId].forEach((id) => expect(exportedText).not.toContain(id));
    expect(manifest.widgets['widget-saved'].dataSelection[0]).toMatchObject({ filters: savedFilterContent });
    expect(manifest.widgets['widget-saved'].dataSelection[0].filters_id).toBeUndefined();
  });

  it('imports its own export as the same dashboard: the widgets, their layout and the ids of the platform, the saved filter inlined, the importer alone', async () => {
    const exported = await queryAsAdmin({ query: EXPORT_QUERY, variables: { id: sourceId } });
    const imported = await importFile(upload(dataOf(exported).workspace.toConfigurationExport));
    expect(imported.errors).toBeUndefined();
    const importedId = dataOf(imported).workspaceConfigurationImport;
    createdIds.push(importedId);
    const workspace = await read(importedId);
    expect(workspace).toMatchObject({ type: 'dashboard', name: 'File export import source' });
    const { widgets, config } = fromB64<{ widgets: Record<string, Widget>; config: unknown }>(workspace.manifest);
    // The saved filter is inlined: no more `filters_id`
    const savedSelection = Object.fromEntries(Object.entries(sourceManifest.widgets['widget-saved'].dataSelection[0]).filter(([key]) => key !== 'filters_id'));
    const expectedSaved = { ...savedSelection, filters: savedFilterContent };
    expect(config).toEqual(sourceManifest.config);
    expect(widgets).toEqual({
      ...sourceManifest.widgets,
      'widget-saved': { ...sourceManifest.widgets['widget-saved'], dataSelection: [expectedSaved] },
    });
    // The filters of this platform are the ones of the source again
    expect(widgets['widget-label'].dataSelection[0].filters).toEqual(filterOn('objectLabel', [labelId]));
    expect(widgets['widget-marking'].dataSelection[0].filters).toEqual(filterOn('objectMarking', [markingId]));
    expect(widgets['widget-entity'].dataSelection[0].filters).toEqual(filterOn('objects', [malwareId]));
    // Not shared as the source: the importing user is the only member
    expect(membersOf(workspace)).toEqual([{ member: ADMIN_USER.id, access_right: 'admin' }]);
    expect(membersOf(await read(sourceId))).toEqual(expect.arrayContaining([{ member: 'ALL', access_right: 'view' }]));
  });

  it('still imports the file of the 5.12 format, with its widgets', async () => {
    const result = await importFile(await createUploadFromTestDataFile('20233010_octi_dashboard_Custom Dash_valid.json', 'valid.json', 'application/json'));
    expect(result.errors).toBeUndefined();
    const id = dataOf(result).workspaceConfigurationImport;
    createdIds.push(id);
    const workspace = await read(id);
    expect(workspace).toMatchObject({ type: 'dashboard', name: 'Hello Dashboard From Import' });
    const { widgets } = fromB64<{ widgets: Record<string, Widget> }>(workspace.manifest);
    expect(Object.values(widgets).map(({ type }) => type).sort()).toEqual(['donut', 'list', 'timeline']);
    expect(membersOf(workspace)).toEqual([{ member: ADMIN_USER.id, access_right: 'admin' }]);
  });

  it('still imports a 6.5.4 file with every kind of widget (the file the e2e dashboard comes from)', async () => {
    // A copy of opencti-front/tests_e2e/dashboard/dashboard_e2e.json: the backend tests run without the front package
    const result = await importFile(await createUploadFromTestDataFile('20241113_octi_dashboard_full_6.5.4.json', 'full.json', 'application/json'));
    expect(result.errors).toBeUndefined();
    const id = dataOf(result).workspaceConfigurationImport;
    createdIds.push(id);
    const workspace = await read(id);
    expect(workspace).toMatchObject({ type: 'dashboard', name: 'Full Dashboard' });
    const { widgets } = fromB64<{ widgets: Record<string, Widget> }>(workspace.manifest);
    const counts: Record<string, number> = {};
    Object.values(widgets).forEach(({ type, perspective }) => {
      const key = `${type}/${perspective ?? 'none'}`;
      counts[key] = (counts[key] ?? 0) + 1;
    });
    expect(Object.values(widgets)).toHaveLength(30);
    expect(counts).toEqual({
      'number/entities': 1, 'number/relationships': 1,
      'line/entities': 1, 'line/relationships': 1,
      'area/entities': 1, 'area/relationships': 1,
      'donut/entities': 1, 'donut/relationships': 1,
      'list/entities': 1, 'list/relationships': 1,
      'distribution-list/entities': 1, 'distribution-list/relationships': 1,
      'polar-area/entities': 1, 'polar-area/relationships': 1,
      'horizontal-bar/entities': 1, 'horizontal-bar/relationships': 1,
      'vertical-bar/entities': 1, 'vertical-bar/relationships': 1,
      'timeline/entities': 1, 'timeline/relationships': 1,
      'radar/entities': 1, 'radar/relationships': 1,
      'heatmap/entities': 1, 'heatmap/relationships': 1,
      'tree/entities': 1, 'tree/relationships': 1,
      'text/none': 2,
      'map/relationships': 1,
      'wordcloud/entities': 1,
    });
  });

  it('imports the file of an exported widget into an existing dashboard, as the widget it was', async () => {
    const exported = await queryAsAdmin({ query: EXPORT_WIDGET_QUERY, variables: { id: sourceId, widgetId: 'widget-entity' } });
    expect(exported.errors).toBeUndefined();
    const file = JSON.parse(dataOf(exported).workspace.toWidgetExport);
    expect(Object.keys(file).sort()).toEqual(['configuration', 'openCTI_version', 'type']);
    expect(file.type).toBe('widget');
    // Into an existing dashboard that already has a widget: the imported one is added next to it
    const added = await queryAsAdmin({ query: ADD_QUERY, variables: { input: { type: 'dashboard', name: 'File export import target' } } });
    const targetId = dataOf(added).workspaceAdd.id;
    createdIds.push(targetId);
    const existing = { config: {}, widgets: { 'widget-existing': sourceManifest.widgets['widget-label'] } };
    const imported = await queryAsAdmin({
      query: IMPORT_WIDGET_QUERY,
      variables: { id: targetId, input: { importType: 'widget', file: upload(dataOf(exported).workspace.toWidgetExport, 'widget.json'), dashboardManifest: toB64(existing) } },
    });
    expect(imported.errors).toBeUndefined();
    const { widgets } = fromB64<{ widgets: Record<string, Widget> }>(dataOf(imported).workspaceWidgetConfigurationImport.manifest);
    expect(Object.keys(widgets)).toHaveLength(2);
    expect(widgets['widget-existing']).toEqual(sourceManifest.widgets['widget-label']);
    const [added2] = Object.entries(widgets).filter(([key]) => key !== 'widget-existing').map(([, widget]) => widget);
    const source = sourceManifest.widgets['widget-entity'];
    // A new id, the rest as the source, the ids of the filters those of this platform
    expect(added2.id).not.toBe('widget-entity');
    expect(added2).toMatchObject({ type: source.type, perspective: source.perspective, dataSelection: source.dataSelection, parameters: source.parameters });
    // The stored dashboard is the one that was written
    expect(fromB64<{ widgets: Record<string, Widget> }>((await read(targetId)).manifest).widgets).toEqual(widgets);
  });
});
