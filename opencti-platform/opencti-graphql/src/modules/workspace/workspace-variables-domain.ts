import { lockResources } from '../../lock/master-lock';
import { ForbiddenAccess, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { storeLoadById } from '../../database/middleware-loader';
import { editInternalObject } from '../../domain/internalObject';
import type { DashboardVariableInput, EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { AccessOperation, validateUserAccessOperation } from '../../utils/access';
import { fromB64, toB64 } from '../../utils/base64';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE, type StoreEntityWorkspace } from './workspace-types';
import type { StoreDashboardManifest, StoreDashboardVariable } from './workspace-variables-types';
import { buildDashboardVariable } from './workspace-variables-validation';
import { buildVariableAuditInput } from './workspace-variables-utils';

const MANIFEST_LOCK_PREFIX = 'workspace-manifest';

/**
 * Serialize every read-modify-write of a workspace manifest.
 * `updateAttribute` loads the element before taking its own lock, so it cannot protect
 * a manifest rewrite on its own; this dedicated key wraps the read *and* the write.
 */
export const withWorkspaceManifestLock = async <T>(workspaceId: string, callback: () => Promise<T>): Promise<T> => {
  const lockIds = [`${MANIFEST_LOCK_PREFIX}:${workspaceId}`];
  let lock;
  try {
    lock = await lockResources(lockIds);
    return await callback();
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) throw LockTimeoutError({ participantIds: lockIds });
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

const loadDashboardForVariableEdition = async (context: AuthContext, user: AuthUser, workspaceId: string) => {
  const workspace = await storeLoadById<BasicStoreEntityWorkspace>(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) throw FunctionalError('Workspace cannot be found', { id: workspaceId });
  if (workspace.type !== 'dashboard') throw FunctionalError('Variables can only be defined on dashboards', { type: workspace.type });
  if (!validateUserAccessOperation(user, workspace, AccessOperation.EDIT)) throw ForbiddenAccess();
  return workspace;
};

const saveDashboardVariables = (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  manifest: StoreDashboardManifest,
  variables: StoreDashboardVariable[],
  auditInput: EditInput[],
) => {
  const input: EditInput[] = [{ key: 'manifest', value: [toB64({ ...manifest, variables })] }];
  return editInternalObject<StoreEntityWorkspace>(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, input, {
    auditLogContextSanitizer: () => auditInput,
  });
};

export const workspaceVariableUpsert = async (context: AuthContext, user: AuthUser, workspaceId: string, input: DashboardVariableInput) => {
  return withWorkspaceManifestLock(workspaceId, async () => {
    const workspace = await loadDashboardForVariableEdition(context, user, workspaceId);
    const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
    const variables = manifest.variables ?? [];
    const variable = buildDashboardVariable(input, variables);
    const isUpdate = variables.some((v) => v.id === variable.id);
    const nextVariables = isUpdate ? variables.map((v) => (v.id === variable.id ? variable : v)) : [...variables, variable];
    return saveDashboardVariables(context, user, workspaceId, manifest, nextVariables, buildVariableAuditInput('upsert', variable));
  });
};

export const workspaceVariableDelete = async (context: AuthContext, user: AuthUser, workspaceId: string, variableId: string) => {
  return withWorkspaceManifestLock(workspaceId, async () => {
    const workspace = await loadDashboardForVariableEdition(context, user, workspaceId);
    const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
    const variables = manifest.variables ?? [];
    const variable = variables.find((v) => v.id === variableId);
    if (!variable) throw FunctionalError('Dashboard variable not found', { variableId });
    // Tokens left in widgets become orphans on purpose: recreating the variable with the same id repairs them.
    const nextVariables = variables.filter((v) => v.id !== variableId);
    return saveDashboardVariables(context, user, workspaceId, manifest, nextVariables, buildVariableAuditInput('delete', variable));
  });
};
