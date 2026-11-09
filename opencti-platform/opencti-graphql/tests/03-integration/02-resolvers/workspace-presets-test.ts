import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, USER_EDITOR } from '../../utils/testQuery';
import {
  awaitUntilCondition,
  createUploadFromBuffer,
  queryAsAdmin,
  queryAsAdminWithError,
  queryAsAdminWithSuccess,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
} from '../../utils/testQueryHelper';
import { fromB64, toB64 } from '../../../src/utils/base64';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN } from '../../../src/schema/identifier';

const CREATE = gql`
  mutation WorkspacePresetsTestAdd($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) { id }
  }
`;
const DELETE = gql`
  mutation WorkspacePresetsTestDelete($id: ID!) {
    workspaceDelete(id: $id)
  }
`;
const READ = gql`
  query WorkspacePresetsTestRead($id: String!) {
    workspace(id: $id) {
      id
      manifest
      variables { id name type defaultValue }
      presets { id name values { variableId value } config { startDate endDate relativeDate } }
      currentUserDefaultPresetId
    }
  }
`;
const UPSERT_VARIABLE = gql`
  mutation WorkspacePresetsTestUpsertVariable($id: ID!, $input: DashboardVariableInput!) {
    workspaceVariableUpsert(id: $id, input: $input) { id variables { id name } }
  }
`;
const DELETE_VARIABLE = gql`
  mutation WorkspacePresetsTestDeleteVariable($id: ID!, $variableId: ID!) {
    workspaceVariableDelete(id: $id, variableId: $variableId) {
      id
      presets { id name values { variableId value } }
    }
  }
`;
const UPSERT = gql`
  mutation WorkspacePresetsTestUpsert($id: ID!, $input: DashboardPresetInput!) {
    workspacePresetUpsert(id: $id, input: $input) {
      id
      presets { id name values { variableId value } config { startDate endDate relativeDate } }
    }
  }
`;
const DELETE_PRESET = gql`
  mutation WorkspacePresetsTestDeletePreset($id: ID!, $presetId: ID!) {
    workspacePresetDelete(id: $id, presetId: $presetId) { id presets { id } }
  }
`;
const PATCH = gql`
  mutation WorkspacePresetsTestPatch($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) { id manifest }
  }
`;
const EXPORT = gql`
  query WorkspacePresetsTestExport($id: String!) {
    workspace(id: $id) { id toConfigurationExport }
  }
`;
const IMPORT_CONFIGURATION = gql`
  mutation WorkspacePresetsTestImportConfiguration($file: Upload!) {
    workspaceConfigurationImport(file: $file)
  }
`;
const DUPLICATE = gql`
  mutation WorkspacePresetsTestDuplicate($input: WorkspaceDuplicateInput!) {
    workspaceDuplicate(input: $input) { id presets { id name values { variableId value } } }
  }
`;
const EDIT_AUTHORIZED_MEMBERS = gql`
  mutation WorkspacePresetsTestEditMembers($id: ID!, $input: [MemberAccessInput!]!) {
    workspaceEditAuthorizedMembers(id: $id, input: $input) { id }
  }
`;
const MARKING = gql`
  query WorkspacePresetsTestMarking($id: String!) {
    markingDefinition(id: $id) { id standard_id }
  }
`;
const ME_EDIT = gql`
  mutation WorkspacePresetsTestMeEdit($input: [EditInput]!) {
    meEdit(input: $input) { id default_dashboard { id } default_dashboard_preset }
  }
`;

const createdIds: string[] = [];
const createDashboard = async (name: string) => {
  const { data } = await queryAsAdminWithSuccess({ query: CREATE, variables: { input: { type: 'dashboard', name } } });
  createdIds.push(data.workspaceAdd.id);
  return data.workspaceAdd.id as string;
};
const readWorkspace = async (id: string) => (await queryAsAdminWithSuccess({ query: READ, variables: { id } })).data.workspace;
const upsertVariable = async (id: string, input: Record<string, unknown>) => {
  const { data } = await queryAsAdminWithSuccess({ query: UPSERT_VARIABLE, variables: { id, input } });
  return data.workspaceVariableUpsert.variables as { id: string; name: string }[];
};
const upsertPreset = async (id: string, input: Record<string, unknown>) => {
  const { data } = await queryAsAdminWithSuccess({ query: UPSERT, variables: { id, input } });
  return data.workspacePresetUpsert.presets;
};
const variableIdByName = (variables: { id: string; name: string }[], name: string) => variables.find((v) => v.name === name)?.id as string;

describe('Dashboard presets API', () => {
  let dashboardId: string;
  let sectorId: string;
  let confidenceId: string;
  beforeAll(async () => {
    dashboardId = await createDashboard('Dashboard presets test');
    await upsertVariable(dashboardId, { name: 'Sector', type: 'entity', entityTypes: ['Sector'], defaultValue: 'sector-a' });
    const variables = await upsertVariable(dashboardId, { name: 'Min confidence', type: 'numeric', defaultValue: '50' });
    sectorId = variableIdByName(variables, 'Sector');
    confidenceId = variableIdByName(variables, 'Min confidence');
  });
  afterAll(async () => {
    const ids = createdIds.splice(0);
    for (let i = 0; i < ids.length; i += 1) {
      await queryAsAdmin({ query: DELETE, variables: { id: ids[i] } });
    }
  });

  it('should expose no preset on a fresh dashboard', async () => {
    const workspace = await readWorkspace(dashboardId);
    expect(workspace.presets).toEqual([]);
    expect(workspace.currentUserDefaultPresetId).toBeNull();
  });

  it('should drive the whole preset lifecycle', async () => {
    const created = await upsertPreset(dashboardId, {
      name: 'Energy',
      values: [{ variableId: sectorId, value: 'sector-energy' }, { variableId: confidenceId, value: '80' }],
      config: { relativeDate: 'months-1', startDate: '2026-01-01' },
    });
    expect(created).toHaveLength(1);
    const presetId = created[0].id;
    expect(created[0]).toMatchObject({
      name: 'Energy',
      values: [{ variableId: sectorId, value: 'sector-energy' }, { variableId: confidenceId, value: '80' }],
      config: { relativeDate: 'months-1', startDate: null, endDate: null },
    });
    // The preset is stored on the manifest, under the server owned key
    const { manifest } = await readWorkspace(dashboardId);
    expect(fromB64(manifest).presets).toEqual([{ id: presetId, name: 'Energy', values: { [sectorId]: 'sector-energy', [confidenceId]: '80' }, config: { relativeDate: 'months-1', startDate: null, endDate: null } }]);
    // Update keeps the id; an empty value drops the entry
    const updated = await upsertPreset(dashboardId, { id: presetId, name: 'Energy & Utilities', values: [{ variableId: sectorId, value: 'sector-energy' }, { variableId: confidenceId, value: '' }], config: { startDate: '2026-01-01', endDate: '2026-03-31' } });
    expect(updated).toEqual([expect.objectContaining({ id: presetId, name: 'Energy & Utilities', values: [{ variableId: sectorId, value: 'sector-energy' }], config: { relativeDate: null, startDate: '2026-01-01', endDate: '2026-03-31' } })]);
    // A second preset, then the first one is deleted
    await upsertPreset(dashboardId, { name: 'Finance', values: [{ variableId: sectorId, value: 'sector-finance' }] });
    const { data } = await queryAsAdminWithSuccess({ query: DELETE_PRESET, variables: { id: dashboardId, presetId } });
    expect(data.workspacePresetDelete.presets).toHaveLength(1);
    expect(data.workspacePresetDelete.presets[0].id).not.toEqual(presetId);
  });

  it('should reject invalid inputs with a functional error', async () => {
    await queryAsAdminWithError({ query: UPSERT, variables: { id: dashboardId, input: { name: 'finance' } } }, 'A dashboard preset with this name already exists', 'FUNCTIONAL_ERROR');
    await queryAsAdminWithError({ query: UPSERT, variables: { id: dashboardId, input: { name: 'Unknown', values: [{ variableId: '99999999-9999-4999-8999-999999999999', value: 'x' }] } } }, 'Unknown dashboard variable', 'FUNCTIONAL_ERROR');
    await queryAsAdminWithError({ query: UPSERT, variables: { id: dashboardId, input: { name: 'Bad value', values: [{ variableId: confidenceId, value: 'high' }] } } }, 'Invalid dashboard preset value', 'FUNCTIONAL_ERROR');
    await queryAsAdminWithError({ query: UPSERT, variables: { id: dashboardId, input: { name: 'Bad range', config: { relativeDate: 'soon' } } } }, 'Invalid dashboard preset time range', 'FUNCTIONAL_ERROR');
    await queryAsAdminWithError({ query: DELETE_PRESET, variables: { id: dashboardId, presetId: '99999999-9999-4999-8999-999999999999' } }, 'Dashboard preset not found', 'FUNCTIONAL_ERROR');
  });

  it('should drop the value of a deleted variable from the presets', async () => {
    const id = await createDashboard('Presets variable deletion');
    const variables = await upsertVariable(id, { name: 'Sector', type: 'entity', entityTypes: ['Sector'], defaultValue: 'sector-a' });
    const variableId = variables[0].id;
    await upsertVariable(id, { name: 'Confidence', type: 'numeric', defaultValue: '50' });
    const { variables: all } = await readWorkspace(id);
    const confidence = variableIdByName(all, 'Confidence');
    await upsertPreset(id, { name: 'Both', values: [{ variableId, value: 'sector-b' }, { variableId: confidence, value: '80' }] });
    const { data } = await queryAsAdminWithSuccess({ query: DELETE_VARIABLE, variables: { id, variableId } });
    expect(data.workspaceVariableDelete.presets).toEqual([expect.objectContaining({ name: 'Both', values: [{ variableId: confidence, value: '80' }] })]);
  });

  it('should ignore presets sent through a full manifest and refuse them on an investigation', async () => {
    const { manifest } = await readWorkspace(dashboardId);
    const stale = { ...fromB64<Record<string, unknown>>(manifest), presets: [{ id: 'injected', name: 'Injected', values: {}, config: {} }] };
    await queryAsAdminWithSuccess({ query: PATCH, variables: { id: dashboardId, input: [{ key: 'manifest', value: [toB64(stale)] }] } });
    const after = await readWorkspace(dashboardId);
    expect(after.presets.map((preset: { name: string }) => preset.name)).toEqual(['Finance']);
    const { data } = await queryAsAdminWithSuccess({ query: CREATE, variables: { input: { type: 'investigation', name: 'Presets investigation' } } });
    createdIds.push(data.workspaceAdd.id);
    await queryAsAdminWithError({ query: UPSERT, variables: { id: data.workspaceAdd.id, input: { name: 'Nope' } } }, 'Variables can only be defined on dashboards', 'FUNCTIONAL_ERROR');
  });

  it('should refuse a user with view only access and allow an editor', async () => {
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    const viewId = await createDashboard('Presets view only');
    const editId = await createDashboard('Presets editable');
    await queryAsAdminWithSuccess({ query: EDIT_AUTHORIZED_MEMBERS, variables: { id: viewId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }, { id: 'ALL', access_right: 'view' }, { id: editorId, access_right: 'view' }] } });
    await queryAsAdminWithSuccess({ query: EDIT_AUTHORIZED_MEMBERS, variables: { id: editId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }, { id: 'ALL', access_right: 'view' }, { id: editorId, access_right: 'edit' }] } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: UPSERT, variables: { id: viewId, input: { name: 'Forbidden' } } });
    const { data } = await queryAsUserWithSuccess(USER_EDITOR, { query: UPSERT, variables: { id: editId, input: { name: 'Allowed' } } });
    expect(data?.workspacePresetUpsert.presets).toHaveLength(1);
  });

  it('should resolve the default preset of the current user from their own choice', async () => {
    const presets = await readWorkspace(dashboardId);
    const presetId = presets.presets[0].id;
    await queryAsAdminWithSuccess({ query: ME_EDIT, variables: { input: [{ key: 'default_dashboard', value: [dashboardId] }, { key: 'default_dashboard_preset', value: [presetId] }] } });
    try {
      // The resolver reads the authenticated user from the cache of the API process, refreshed asynchronously by
      // the cache manager from the platform events: the edited user shows up a moment after meEdit.
      await awaitUntilCondition(async () => (await readWorkspace(dashboardId)).currentUserDefaultPresetId === presetId, 10000, {
        message: 'the default preset of the user is resolved once the user cache is refreshed',
      });
      // Another dashboard is not concerned, and a deleted preset is not resolved
      const other = await createDashboard('Presets other dashboard');
      expect((await readWorkspace(other)).currentUserDefaultPresetId).toBeNull();
      await queryAsAdminWithSuccess({ query: DELETE_PRESET, variables: { id: dashboardId, presetId } });
      expect((await readWorkspace(dashboardId)).currentUserDefaultPresetId).toBeNull();
    } finally {
      await queryAsAdminWithSuccess({ query: ME_EDIT, variables: { input: [{ key: 'default_dashboard', value: [null] }, { key: 'default_dashboard_preset', value: [null] }] } });
    }
  });
});

describe('Dashboard presets export, import and duplication', () => {
  const readMarking = async (id: string) => (await queryAsAdminWithSuccess({ query: MARKING, variables: { id } })).data.markingDefinition as { id: string; standard_id: string };
  let green: { id: string; standard_id: string };
  let amber: { id: string; standard_id: string };
  beforeAll(async () => {
    green = await readMarking(MARKING_TLP_GREEN);
    amber = await readMarking(MARKING_TLP_AMBER);
  });
  afterAll(async () => {
    const ids = createdIds.splice(0);
    for (let i = 0; i < ids.length; i += 1) {
      await queryAsAdmin({ query: DELETE, variables: { id: ids[i] } });
    }
  });

  it('should convert the preset values of entity variables on export and restore them on import', async () => {
    const id = await createDashboard('Presets round trip');
    const variables = await upsertVariable(id, { name: 'Marking', type: 'marking', defaultValue: green.id });
    const markingId = variables[0].id;
    await upsertVariable(id, { name: 'Text', type: 'text', defaultValue: 'x' });
    const { variables: all } = await readWorkspace(id);
    const textId = variableIdByName(all, 'Text');
    await upsertPreset(id, { name: 'Amber', values: [{ variableId: markingId, value: amber.id }, { variableId: textId, value: green.id }], config: { relativeDate: 'days-7' } });
    const { data: exported } = await queryAsAdminWithSuccess({ query: EXPORT, variables: { id } });
    const file = exported.workspace.toConfigurationExport as string;
    const manifest = fromB64(JSON.parse(file).configuration.manifest);
    expect(manifest.presets[0].values).toEqual({ [markingId]: amber.standard_id, [textId]: green.id });
    const upload = createUploadFromBuffer(Buffer.from(file), 'presets-round-trip.json', 'application/json');
    const { data } = await queryAsAdminWithSuccess({ query: IMPORT_CONFIGURATION, variables: { file: upload } });
    createdIds.push(data.workspaceConfigurationImport);
    const imported = await readWorkspace(data.workspaceConfigurationImport);
    expect(imported.presets).toEqual([expect.objectContaining({
      name: 'Amber',
      values: [{ variableId: markingId, value: amber.id }, { variableId: textId, value: green.id }],
      config: { relativeDate: 'days-7', startDate: null, endDate: null },
    })]);
  });

  it('should keep the presets of a duplicated dashboard and drop them elsewhere', async () => {
    const id = await createDashboard('Presets duplication');
    const variables = await upsertVariable(id, { name: 'Sector', type: 'entity', entityTypes: ['Sector'], defaultValue: 'sector-a' });
    await upsertPreset(id, { name: 'Energy', values: [{ variableId: variables[0].id, value: 'sector-energy' }] });
    const { manifest } = await readWorkspace(id);
    const { data } = await queryAsAdminWithSuccess({ query: DUPLICATE, variables: { input: { type: 'dashboard', name: 'Presets duplicate', manifest } } });
    createdIds.push(data.workspaceDuplicate.id);
    expect(data.workspaceDuplicate.presets).toEqual([expect.objectContaining({ name: 'Energy', values: [{ variableId: variables[0].id, value: 'sector-energy' }] })]);
    const { data: investigation } = await queryAsAdminWithSuccess({ query: DUPLICATE, variables: { input: { type: 'investigation', name: 'Presets duplicate investigation', manifest } } });
    createdIds.push(investigation.workspaceDuplicate.id);
    expect(fromB64((await readWorkspace(investigation.workspaceDuplicate.id)).manifest).presets).toBeUndefined();
  });
});
