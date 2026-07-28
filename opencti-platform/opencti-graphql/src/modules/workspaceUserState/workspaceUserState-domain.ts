import { FunctionalError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import { createInternalObject, editInternalObject } from '../../domain/internalObject';
import { pageEntitiesConnection } from '../../database/middleware-loader';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { BasicStoreEntityWorkspaceUserState, StoreEntityWorkspaceUserState } from './workspaceUserState-types';
import { ENTITY_TYPE_WORKSPACE_USER_STATE } from './workspaceUserState-types';
import { checkDashboardEditRights, findById as findWorkspaceById, getWorkspacePresets } from '../workspace/workspace-domain';

const findUserStateForWorkspace = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
): Promise<BasicStoreEntityWorkspaceUserState | null> => {
  const filters = addFilter(undefined, 'workspace_id', [workspaceId]);
  const connection = await pageEntitiesConnection<BasicStoreEntityWorkspaceUserState>(
    context,
    user,
    [ENTITY_TYPE_WORKSPACE_USER_STATE],
    { filters, first: 1 },
  );
  return connection.edges[0]?.node ?? null;
};

export const myDashboardVariableState = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
): Promise<BasicStoreEntityWorkspaceUserState | null> => {
  return findUserStateForWorkspace(context, user, workspaceId);
};

export const workspaceVariableSetValue = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  variableId: string,
  value: string | null | undefined,
): Promise<BasicStoreEntityWorkspaceUserState> => {
  const workspace = await findWorkspaceById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: false });

  const existing = await findUserStateForWorkspace(context, user, workspaceId);
  const currentValues: Record<string, unknown> = existing
    ? JSON.parse(existing.variable_values ?? '{}') as Record<string, unknown>
    : {};
  const updatedValues = { ...currentValues, [variableId]: value ?? null };
  const serialised = JSON.stringify(updatedValues);

  if (existing) {
    return editInternalObject<StoreEntityWorkspaceUserState>(
      context,
      user,
      existing.id,
      ENTITY_TYPE_WORKSPACE_USER_STATE,
      [{ key: 'variable_values', value: [serialised] }],
    );
  }
  return createInternalObject<StoreEntityWorkspaceUserState>(context, user, {
    workspace_id: workspaceId,
    variable_values: serialised,
  }, ENTITY_TYPE_WORKSPACE_USER_STATE);
};

export const workspaceVariableResetValue = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  variableId: string,
): Promise<BasicStoreEntityWorkspaceUserState> => {
  const workspace = await findWorkspaceById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: false });

  const existing = await findUserStateForWorkspace(context, user, workspaceId);
  const currentValues: Record<string, unknown> = existing
    ? JSON.parse(existing.variable_values ?? '{}') as Record<string, unknown>
    : {};
  const { [variableId]: _removed, ...remaining } = currentValues;
  const serialised = JSON.stringify(remaining);

  if (existing) {
    return editInternalObject<StoreEntityWorkspaceUserState>(
      context,
      user,
      existing.id,
      ENTITY_TYPE_WORKSPACE_USER_STATE,
      [{ key: 'variable_values', value: [serialised] }],
    );
  }
  // Nothing to reset — create an empty state record
  return createInternalObject<StoreEntityWorkspaceUserState>(context, user, {
    workspace_id: workspaceId,
    variable_values: '{}',
  }, ENTITY_TYPE_WORKSPACE_USER_STATE);
};

export const workspacePresetApply = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  presetId: string,
): Promise<BasicStoreEntityWorkspaceUserState> => {
  const workspace = await findWorkspaceById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: false });

  const preset = getWorkspacePresets(workspace).find((p) => p.id === presetId);
  if (!preset) throw FunctionalError('Preset not found', { presetId });

  const serialised = preset.variable_values;
  const existing = await findUserStateForWorkspace(context, user, workspaceId);

  if (existing) {
    return editInternalObject<StoreEntityWorkspaceUserState>(
      context,
      user,
      existing.id,
      ENTITY_TYPE_WORKSPACE_USER_STATE,
      [{ key: 'variable_values', value: [serialised] }],
    );
  }
  return createInternalObject<StoreEntityWorkspaceUserState>(context, user, {
    workspace_id: workspaceId,
    variable_values: serialised,
  }, ENTITY_TYPE_WORKSPACE_USER_STATE);
};
