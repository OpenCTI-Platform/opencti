import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { getUserIdByEmail, USER_EDITOR } from '../../utils/testQuery';
import {
  createUploadFromTestDataFile,
  queryAsAdmin,
  queryAsAdminWithError,
  queryAsAdminWithSuccess,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
} from '../../utils/testQueryHelper';
import { fromB64, toB64 } from '../../../src/utils/base64';
import { ENABLED_FEATURE_FLAGS } from '../../../src/config/conf';

const CREATE = gql`
  mutation WorkspaceVariablesTestAdd($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) { id }
  }
`;
const DELETE = gql`
  mutation WorkspaceVariablesTestDelete($id: ID!) {
    workspaceDelete(id: $id)
  }
`;
const READ = gql`
  query WorkspaceVariablesTestRead($id: String!) {
    workspace(id: $id) {
      id
      manifest
      variables { id name type vocabularyCategory killChainName entityTypes defaultValue usedInWidgetIds restriction { mode values filters } }
    }
  }
`;
const UPSERT = gql`
  mutation WorkspaceVariablesTestUpsert($id: ID!, $input: DashboardVariableInput!) {
    workspaceVariableUpsert(id: $id, input: $input) {
      id
      variables { id name type defaultValue usedInWidgetIds restriction { mode values filters } }
    }
  }
`;
const DELETE_VARIABLE = gql`
  mutation WorkspaceVariablesTestDeleteVariable($id: ID!, $variableId: ID!) {
    workspaceVariableDelete(id: $id, variableId: $variableId) {
      id
      variables { id }
    }
  }
`;
const IMPORT_WIDGET = gql`
  mutation WorkspaceVariablesTestImportWidget($id: ID!, $input: ImportConfigurationInput!) {
    workspaceWidgetConfigurationImport(id: $id, input: $input) { id manifest }
  }
`;
const PATCH = gql`
  mutation WorkspaceVariablesTestPatch($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) { id manifest }
  }
`;

const createdIds: string[] = [];
const createWorkspace = async (input: Record<string, unknown>) => {
  const { data } = await queryAsAdminWithSuccess({ query: CREATE, variables: { input } });
  createdIds.push(data.workspaceAdd.id);
  return data.workspaceAdd.id as string;
};
const readWorkspace = async (id: string) => (await queryAsAdminWithSuccess({ query: READ, variables: { id } })).data.workspace;
const upsert = async (id: string, input: Record<string, unknown>) => {
  const { data } = await queryAsAdminWithSuccess({ query: UPSERT, variables: { id, input } });
  return data.workspaceVariableUpsert;
};
const patchManifest = (id: string, manifest: unknown) => queryAsAdminWithSuccess({ query: PATCH, variables: { id, input: [{ key: 'manifest', value: [toB64(manifest)] }] } });
const widgetUsing = (variableId: string) => ({
  id: 'widget-1',
  type: 'number',
  perspective: 'entities',
  dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['createdBy'], values: [`$var:${variableId}`], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
  layout: { w: 2, h: 2, x: 0, y: 0, i: 'widget-1', moved: false, static: false },
});

describe('Dashboard variables API', () => {
  let dashboardId: string;
  beforeAll(async () => {
    dashboardId = await createWorkspace({ type: 'dashboard', name: 'Dashboard variables test' });
  });
  afterAll(async () => {
    for (let i = 0; i < createdIds.length; i += 1) {
      await queryAsAdmin({ query: DELETE, variables: { id: createdIds[i] } });
    }
  });

  it('should expose no variable on a fresh dashboard', async () => {
    expect((await readWorkspace(dashboardId)).variables).toEqual([]);
  });

  it('should drive the whole variable lifecycle', async () => {
    const created = await upsert(dashboardId, { name: 'Sector', type: 'entity', entityTypes: ['Sector'], defaultValue: 'sector-id' });
    expect(created.variables).toHaveLength(1);
    const variableId = created.variables[0].id;
    expect(created.variables[0]).toMatchObject({ name: 'Sector', type: 'entity', defaultValue: 'sector-id', usedInWidgetIds: [], restriction: { mode: 'none' } });
    // A widget using the variable makes it used
    const { manifest } = await readWorkspace(dashboardId);
    await patchManifest(dashboardId, { ...fromB64<Record<string, unknown>>(manifest), widgets: { 'widget-1': widgetUsing(variableId) } });
    expect((await readWorkspace(dashboardId)).variables[0].usedInWidgetIds).toEqual(['widget-1']);
    // Update keeps the id
    const updated = await upsert(dashboardId, { id: variableId, name: 'Sector renamed', type: 'entity', entityTypes: ['Sector'], defaultValue: 'other-id' });
    expect(updated.variables).toEqual([expect.objectContaining({ id: variableId, name: 'Sector renamed', defaultValue: 'other-id' })]);
    // Deleting a used variable is allowed and leaves the token as an orphan
    const { data } = await queryAsAdminWithSuccess({ query: DELETE_VARIABLE, variables: { id: dashboardId, variableId } });
    expect(data.workspaceVariableDelete.variables).toEqual([]);
    const after = await readWorkspace(dashboardId);
    expect(fromB64(after.manifest).widgets['widget-1'].dataSelection[0].filters.filters[0].values).toEqual([`$var:${variableId}`]);
  });

  it('should reject invalid inputs with a functional error', async () => {
    await upsert(dashboardId, { name: 'Unique', type: 'text', defaultValue: 'x' });
    await queryAsAdminWithError({ query: UPSERT, variables: { id: dashboardId, input: { name: 'unique', type: 'text', defaultValue: 'y' } } }, 'A dashboard variable with this name already exists', 'FUNCTIONAL_ERROR');
    await queryAsAdminWithError({ query: UPSERT, variables: { id: dashboardId, input: { name: 'No default', type: 'text' } } }, 'Dashboard variable default value is required', 'FUNCTIONAL_ERROR');
    await queryAsAdminWithError({ query: DELETE_VARIABLE, variables: { id: dashboardId, variableId: '99999999-9999-4999-8999-999999999999' } }, 'Dashboard variable not found', 'FUNCTIONAL_ERROR');
  });

  it('should reject an unknown vocabulary category at the GraphQL layer', async () => {
    const result = await queryAsAdmin({ query: UPSERT, variables: { id: dashboardId, input: { name: 'Vocab', type: 'vocabulary', vocabularyCategory: 'not_a_category', defaultValue: 'x' } } });
    expect(result.errors?.length).toEqual(1);
  });

  it('should refuse to define variables on an investigation', async () => {
    const investigationId = await createWorkspace({ type: 'investigation', name: 'Investigation variables test' });
    await queryAsAdminWithError({ query: UPSERT, variables: { id: investigationId, input: { name: 'Nope', type: 'text', defaultValue: 'x' } } }, 'Variables can only be defined on dashboards', 'FUNCTIONAL_ERROR');
    expect((await readWorkspace(investigationId)).variables).toEqual([]);
  });

  it('should only let users with edit access on the dashboard write variables', async () => {
    const userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    const viewDashboardId = await createWorkspace({ type: 'dashboard', name: 'Variables view access', authorized_members: [{ id: userEditorId, access_right: 'view' }] });
    const editDashboardId = await createWorkspace({ type: 'dashboard', name: 'Variables edit access', authorized_members: [{ id: userEditorId, access_right: 'edit' }] });
    const viewVariable = (await upsert(viewDashboardId, { name: 'Existing', type: 'text', defaultValue: 'x' })).variables[0];
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: UPSERT, variables: { id: viewDashboardId, input: { name: 'Forbidden', type: 'text', defaultValue: 'x' } } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: DELETE_VARIABLE, variables: { id: viewDashboardId, variableId: viewVariable.id } });
    const { data } = await queryAsUserWithSuccess(USER_EDITOR, { query: UPSERT, variables: { id: editDashboardId, input: { name: 'Allowed', type: 'text', defaultValue: 'x' } } });
    expect(data?.workspaceVariableUpsert.variables).toHaveLength(1);
  });

  it('should hide the API when the feature flag is disabled', async () => {
    const previous = [...ENABLED_FEATURE_FLAGS];
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    try {
      const result = await queryAsAdmin({ query: UPSERT, variables: { id: dashboardId, input: { name: 'Flag off', type: 'text', defaultValue: 'x' } } });
      expect(result.errors?.[0].message).toEqual('Feature is disabled');
      expect((await readWorkspace(dashboardId)).variables).toEqual([]);
    } finally {
      ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previous);
    }
  });

  it('should keep both variables when two upserts run concurrently', async () => {
    const id = await createWorkspace({ type: 'dashboard', name: 'Variables concurrency' });
    await Promise.all([
      upsert(id, { name: 'First', type: 'text', defaultValue: 'a' }),
      upsert(id, { name: 'Second', type: 'text', defaultValue: 'b' }),
    ]);
    expect((await readWorkspace(id)).variables.map((v: { name: string }) => v.name).sort()).toEqual(['First', 'Second']);
  });

  it('should keep a variable when a stale full manifest is saved', async () => {
    const id = await createWorkspace({ type: 'dashboard', name: 'Variables stale manifest' });
    await patchManifest(id, { widgets: {}, config: {} });
    const stale = fromB64((await readWorkspace(id)).manifest);
    await upsert(id, { name: 'Created meanwhile', type: 'text', defaultValue: 'a' });
    await patchManifest(id, { ...stale, widgets: { 'widget-1': widgetUsing('11111111-1111-4111-8111-111111111111') } });
    const after = await readWorkspace(id);
    expect(after.variables.map((v: { name: string }) => v.name)).toEqual(['Created meanwhile']);
    expect(Object.keys(fromB64(after.manifest).widgets)).toEqual(['widget-1']);
  });

  it('should not lose a layout change saved concurrently with an upsert', async () => {
    const id = await createWorkspace({ type: 'dashboard', name: 'Variables vs layout' });
    await patchManifest(id, { widgets: {}, config: {} });
    await Promise.all([
      patchManifest(id, { widgets: { 'widget-1': widgetUsing('11111111-1111-4111-8111-111111111111') }, config: {} }),
      upsert(id, { name: 'Concurrent', type: 'text', defaultValue: 'a' }),
    ]);
    const after = await readWorkspace(id);
    expect(Object.keys(fromB64(after.manifest).widgets)).toEqual(['widget-1']);
    expect(after.variables.map((v: { name: string }) => v.name)).toEqual(['Concurrent']);
  });

  it('should ignore variables injected through workspaceFieldPatch', async () => {
    const id = await createWorkspace({ type: 'dashboard', name: 'Variables injection' });
    await patchManifest(id, { widgets: {}, config: {}, variables: [{ id: 'injected', name: 'Injected', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' }] });
    expect((await readWorkspace(id)).variables).toEqual([]);
  });

  it('should keep the exact encoding of a legacy manifest', async () => {
    const id = await createWorkspace({ type: 'dashboard', name: 'Variables legacy encoding' });
    const encoded = toB64({ widgets: {}, config: { relativeDate: 'days-30' } });
    await queryAsAdminWithSuccess({ query: PATCH, variables: { id, input: [{ key: 'manifest', value: [encoded] }] } });
    expect((await readWorkspace(id)).manifest).toEqual(encoded);
  });

  it('should keep variables when a widget is imported with a manifest lacking them', async () => {
    const id = await createWorkspace({ type: 'dashboard', name: 'Variables widget import' });
    await patchManifest(id, { widgets: {}, config: {} });
    const stale = (await readWorkspace(id)).manifest;
    await upsert(id, { name: 'Before import', type: 'text', defaultValue: 'a' });
    const file = await createUploadFromTestDataFile('20231123_octi_widget_list.json', 'valid.json', 'application/json');
    await queryAsAdminWithSuccess({ query: IMPORT_WIDGET, variables: { id, input: { importType: 'widget', file, dashboardManifest: stale } } });
    const after = await readWorkspace(id);
    expect(after.variables.map((v: { name: string }) => v.name)).toEqual(['Before import']);
    expect(Object.keys(fromB64(after.manifest).widgets)).toHaveLength(1);
  });
});
