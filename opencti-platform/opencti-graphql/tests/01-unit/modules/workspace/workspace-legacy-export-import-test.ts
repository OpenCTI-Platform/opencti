import { beforeEach, describe, expect, it, vi } from 'vitest';

// The file export and import of a dashboard, and the export and import of a widget, are the ones that were in workspace-domain: they must behave as before
// the configuration bundle took the same dashboards. The reads and writes of the platform are replaced, what the functions ask of them is checked.
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  createEntity: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  notify: vi.fn(async (_topic: string, element: unknown) => element),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../src/utils/fileToContent', () => ({ extractContentFrom: vi.fn() }));
vi.mock('../../../../src/modules/workspace/workspace-variables-domain', () => ({
  withWorkspaceManifestLock: vi.fn(async (_id: string, callback: () => Promise<unknown>) => callback()),
}));
vi.mock('../../../../src/modules/workspace/workspace-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/workspace/workspace-utils')>()),
  convertWidgetsIds: vi.fn(),
}));
vi.mock('../../../../src/modules/savedFilter/savedFilter-domain', () => ({ findSavedFilter: vi.fn() }));
// The widget file is read from an upload: what it gives is replaced, the write that follows is what is checked
vi.mock('../../../../src/modules/dashboard/dashboard-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/dashboard/dashboard-utils')>()),
  importDashboardWidgetConfiguration: vi.fn(),
}));

import pjson from '../../../../package.json';
import { BUS_TOPICS } from '../../../../src/config/conf';
import { createEntity, updateAttribute } from '../../../../src/database/middleware';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { notify } from '../../../../src/database/redis';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { extractContentFrom } from '../../../../src/utils/fileToContent';
import { generateWidgetExportConfiguration, generateWorkspaceExportConfiguration } from '../../../../src/modules/workspace/workspace-export';
import { workspaceImportConfiguration, workspaceImportWidgetConfiguration } from '../../../../src/modules/workspace/workspace-import';
import { ENTITY_TYPE_WORKSPACE, type BasicStoreEntityWorkspace } from '../../../../src/modules/workspace/workspace-types';
import { convertWidgetsIds } from '../../../../src/modules/workspace/workspace-utils';
import { findSavedFilter } from '../../../../src/modules/savedFilter/savedFilter-domain';
import { convertDashboardManifestIds, importDashboardWidgetConfiguration, resolveSavedFiltersInDataSelection } from '../../../../src/modules/dashboard/dashboard-utils';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const SAVED_FILTER_ID = '3b2a1c0d-9e8f-4a7b-8c6d-5e4f3a2b1c0d';
const VARIABLE_ID = '11111111-1111-4111-8111-111111111111';
const savedFilterGroup = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const widgetOf = (selection: Record<string, unknown>) => ({ id: 'widget1', type: 'number', dataSelection: [{ filters: { mode: 'and', filters: [], filterGroups: [] }, ...selection }] });
const manifestOf = (widgets: Record<string, unknown>, rest: Record<string, unknown> = {}) => toB64({ config: {}, widgets, ...rest }) as string;
const workspaceOf = (overrides: Partial<BasicStoreEntityWorkspace> = {}) => ({
  id: 'workspace-id',
  type: 'dashboard',
  name: 'SOC overview',
  manifest: manifestOf({ widget1: widgetOf({ filters_id: SAVED_FILTER_ID }) }),
  ...overrides,
}) as unknown as BasicStoreEntityWorkspace;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Legacy file export of a dashboard', () => {
  it('writes the version, the type, the name and the manifest, with the saved filters resolved', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue({ filters: JSON.stringify(savedFilterGroup) } as never);
    const file = JSON.parse(await generateWorkspaceExportConfiguration(context, user, workspaceOf()));
    expect(file).toEqual({ openCTI_version: pjson.version, type: 'dashboard', configuration: { name: 'SOC overview', manifest: expect.any(String) } });
    const [widget] = Object.values<{ dataSelection: Record<string, unknown>[] }>(fromB64(file.configuration.manifest).widgets);
    expect(widget.dataSelection[0]).toMatchObject({ filters: savedFilterGroup });
    expect(widget.dataSelection[0].filters_id).toBeUndefined();
    // The ids are converted to the standard ids, as ever
    expect(convertWidgetsIds).toHaveBeenCalledWith(context, user, expect.any(Array), 'internal');
  });

  it('keeps the variables and the presets of the manifest as they are: the bundle is the one that converts or drops them', async () => {
    const variable = { id: VARIABLE_ID, name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: 'phishing' };
    const manifest = manifestOf({}, { variables: [variable], presets: [{ id: 'preset' }] });
    const file = JSON.parse(await generateWorkspaceExportConfiguration(context, user, workspaceOf({ manifest })));
    expect(fromB64(file.configuration.manifest)).toMatchObject({ variables: [variable], presets: [{ id: 'preset' }] });
  });

  it('fails when a saved filter does not exist: the file export stays strict', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue(undefined as never);
    await expect(generateWorkspaceExportConfiguration(context, user, workspaceOf())).rejects.toThrow('Saved filter not found');
  });

  it('refuses a workspace that is not a dashboard', async () => {
    await expect(generateWorkspaceExportConfiguration(context, user, workspaceOf({ type: 'investigation' }))).rejects.toThrow('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE');
  });
});

describe('Export of a widget', () => {
  it('writes the widget as a file, without its id', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue({ filters: JSON.stringify(savedFilterGroup) } as never);
    const data = JSON.parse(await generateWidgetExportConfiguration(context, user, workspaceOf(), 'widget1'));
    expect(data).toMatchObject({ openCTI_version: pjson.version, type: 'widget', configuration: expect.any(String) });
    const widget = fromB64(data.configuration);
    expect(widget.id).toBeUndefined();
    expect(widget.dataSelection[0]).toMatchObject({ filters: savedFilterGroup });
  });

  it('fails for a widget that is not in the dashboard, a workspace that is not a dashboard, and a missing saved filter', async () => {
    await expect(generateWidgetExportConfiguration(context, user, workspaceOf(), 'unknown')).rejects.toThrow('WIDGET_EXPORT_NOT_FOUND');
    await expect(generateWidgetExportConfiguration(context, user, workspaceOf({ type: 'investigation' }), 'widget1')).rejects.toThrow('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE');
    vi.mocked(findSavedFilter).mockResolvedValue(undefined as never);
    await expect(generateWidgetExportConfiguration(context, user, workspaceOf(), 'widget1')).rejects.toThrow('Saved filter not found');
  });
});

describe('Strict resolution of the saved filters, the default of every export but the bundle', () => {
  it('fails on a saved filter that does not exist unless the caller keeps it', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue(undefined as never);
    // The public dashboard and the custom view call the resolution like this
    await expect(resolveSavedFiltersInDataSelection(context, user, widgetOf({ filters_id: SAVED_FILTER_ID }) as never)).rejects.toThrow('Saved filter not found');
    await expect(convertDashboardManifestIds(context, user, workspaceOf().manifest, 'internal')).rejects.toThrow('Saved filter not found');
    const widget = widgetOf({ filters_id: SAVED_FILTER_ID, dynamicFrom_id: SAVED_FILTER_ID });
    await expect(resolveSavedFiltersInDataSelection(context, user, widget as never, true)).resolves.toBeUndefined();
    expect(widget.dataSelection[0]).toMatchObject({ filters_id: SAVED_FILTER_ID, dynamicFrom_id: SAVED_FILTER_ID });
    const converted = await convertDashboardManifestIds(context, user, workspaceOf().manifest, 'internal', { keepMissingSavedFilters: true });
    expect(Object.values<{ dataSelection: Record<string, unknown>[] }>(fromB64(converted).widgets)[0].dataSelection[0].filters_id).toBe(SAVED_FILTER_ID);
  });

  it('does not read a saved filter on an import', async () => {
    await convertDashboardManifestIds(context, user, workspaceOf().manifest, 'stix');
    expect(findSavedFilter).not.toHaveBeenCalled();
  });
});

describe('Legacy file import of a dashboard', () => {
  const file = (overrides: Record<string, unknown> = {}) => ({
    openCTI_version: '6.0.0',
    type: 'dashboard',
    configuration: { name: 'Imported dashboard', manifest: manifestOf({ widget1: widgetOf({}) }) },
    ...overrides,
  });
  const created = { id: 'created-id', name: 'Imported dashboard', manifest: 'manifest', entity_type: 'Workspace' };

  it('creates the dashboard for the importing user only, tells the audit and the subscribers, and returns its id', async () => {
    vi.mocked(extractContentFrom).mockResolvedValue(file() as never);
    vi.mocked(createEntity).mockResolvedValue(created as never);
    expect(await workspaceImportConfiguration(context, user, Promise.resolve({}) as never)).toBe('created-id');
    expect(createEntity).toHaveBeenCalledTimes(1);
    expect(createEntity).toHaveBeenCalledWith(context, user, {
      type: 'dashboard',
      openCTI_version: '6.0.0',
      name: 'Imported dashboard',
      manifest: expect.any(String),
      restricted_members: [{ id: 'user-id', access_right: 'admin' }],
    }, ENTITY_TYPE_WORKSPACE);
    expect(publishUserAction).toHaveBeenCalledWith({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'extended',
      message: 'import Imported dashboard workspace',
      // The manifest is left out of the audit
      context_data: { id: 'created-id', entity_type: ENTITY_TYPE_WORKSPACE, input: { ...created, manifest: undefined } },
    });
    expect(notify).toHaveBeenCalledWith(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
  });

  it('validates the variables of the file like the typed API, and drops the presets', async () => {
    const variable = { id: VARIABLE_ID, name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: 'phishing' };
    const manifest = manifestOf({ widget1: widgetOf({}) }, { variables: [variable], presets: [{ id: 'preset' }] });
    vi.mocked(extractContentFrom).mockResolvedValue(file({ configuration: { name: 'Imported dashboard', manifest } }) as never);
    vi.mocked(createEntity).mockResolvedValue(created as never);
    await workspaceImportConfiguration(context, user, Promise.resolve({}) as never);
    const stored = fromB64(vi.mocked(createEntity).mock.calls[0][2].manifest as string);
    expect(stored.variables).toEqual([variable]);
    expect(stored.presets).toBeUndefined();
    vi.mocked(extractContentFrom).mockResolvedValue(file({ configuration: { name: 'Imported dashboard', manifest: manifestOf({}, { variables: [{ name: 'Bad', type: 'unknown' }] }) } }) as never);
    await expect(workspaceImportConfiguration(context, user, Promise.resolve({}) as never)).rejects.toThrow('Invalid dashboard variable type');
  });

  it('writes nothing for a file of another type, of an old version or without a name', async () => {
    vi.mocked(extractContentFrom).mockResolvedValue(file({ type: 'widget' }) as never);
    await expect(workspaceImportConfiguration(context, user, Promise.resolve({}) as never)).rejects.toThrow('Invalid type. Please import OpenCTI dashboard-type only');
    vi.mocked(extractContentFrom).mockResolvedValue(file({ openCTI_version: '5.10.5' }) as never);
    await expect(workspaceImportConfiguration(context, user, Promise.resolve({}) as never)).rejects.toThrow('Invalid version of the platform');
    vi.mocked(extractContentFrom).mockResolvedValue(file({ configuration: { name: '  ', manifest: '' } }) as never);
    await expect(workspaceImportConfiguration(context, user, Promise.resolve({}) as never)).rejects.toThrow('The dashboard configuration must have a name');
    expect(createEntity).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
    expect(notify).not.toHaveBeenCalled();
  });
});

describe('Import of a widget', () => {
  const variableOf = (name: string) => ({ id: VARIABLE_ID, name, type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' });

  it('writes the manifest sent by the client with the variables of the stored dashboard, whatever the client sends, and tells the audit and the subscribers', async () => {
    vi.mocked(importDashboardWidgetConfiguration).mockResolvedValue({ updatedManifest: manifestOf({ widget1: widgetOf({}) }, { variables: [variableOf('Forged')] }), importedWidgetId: 'widget1' } as never);
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'workspace-id', manifest: manifestOf({}, { variables: [variableOf('Stored')] }) } as never);
    const updated = { id: 'workspace-id', name: 'SOC overview', manifest: 'updated' };
    vi.mocked(updateAttribute).mockResolvedValue({ element: updated } as never);
    const input = { file: Promise.resolve({}), dashboardManifest: 'client-manifest' };

    expect(await workspaceImportWidgetConfiguration(context, user, 'workspace-id', input as never)).toBe(updated);
    expect(importDashboardWidgetConfiguration).toHaveBeenCalledWith(context, user, input.file, 'client-manifest');
    const [, , workspaceId, entityType, inputs] = vi.mocked(updateAttribute).mock.calls[0];
    expect([workspaceId, entityType]).toEqual(['workspace-id', ENTITY_TYPE_WORKSPACE]);
    expect(inputs).toHaveLength(1);
    const manifest = fromB64(inputs[0].value?.[0] as string);
    expect(Object.keys(manifest.widgets)).toEqual(['widget1']);
    expect(manifest.variables).toEqual([variableOf('Stored')]);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      event_scope: 'create',
      message: 'import widget (id : widget1) in workspace (id : workspace-id)',
      context_data: { id: 'workspace-id', entity_type: ENTITY_TYPE_WORKSPACE, input: { ...updated, manifest: undefined } },
    }));
    expect(notify).toHaveBeenCalledWith(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, updated, user);
  });

  it('writes nothing when the widget file is refused', async () => {
    vi.mocked(importDashboardWidgetConfiguration).mockRejectedValue(new Error('Invalid type. Please import OpenCTI widget-type only'));
    await expect(workspaceImportWidgetConfiguration(context, user, 'workspace-id', { file: Promise.resolve({}), dashboardManifest: '' } as never)).rejects.toThrow('widget-type only');
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(notify).not.toHaveBeenCalled();
  });
});
