import { FunctionalError } from '../../config/errors';
import { editInternalObject } from '../../domain/internalObject';
import type { DashboardPresetInput, EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { fromB64, toB64 } from '../../utils/base64';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE, type StoreEntityWorkspace } from './workspace-types';
import type { StoreDashboardManifest, StoreDashboardPreset } from './workspace-variables-types';
import { buildDashboardPreset } from './workspace-presets-validation';
import { loadDashboardForVariableEdition, withWorkspaceManifestLock } from './workspace-variables-domain';
import { internalLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { SYSTEM_USER } from '../../utils/access';
import type { BasicStoreEntityUser } from '../user/user-types';
import { findCurrentUserDefaultPresetId } from './workspace-variables-utils';

export const buildPresetAuditInput = (operation: 'upsert' | 'delete', preset: Pick<StoreDashboardPreset, 'id' | 'name'>): EditInput[] => {
  // Never the manifest: it can be huge and carries every widget definition.
  return [{ key: 'presets', value: [{ operation, id: preset.id, name: preset.name }] }];
};

const saveDashboardPresets = (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  manifest: StoreDashboardManifest,
  presets: StoreDashboardPreset[],
  auditInput: EditInput[],
) => {
  const input: EditInput[] = [{ key: 'manifest', value: [toB64({ ...manifest, presets })] }];
  return editInternalObject<StoreEntityWorkspace>(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, input, {
    auditLogContextSanitizer: () => auditInput,
  });
};

/**
 * Create or update a preset of a dashboard. The preset values are checked against the variables as they are stored
 * when the lock is held, never against a manifest sent by the client.
 */
export const workspacePresetUpsert = async (context: AuthContext, user: AuthUser, workspaceId: string, input: DashboardPresetInput) => {
  return withWorkspaceManifestLock(workspaceId, async () => {
    const workspace = await loadDashboardForVariableEdition(context, user, workspaceId);
    const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
    const presets = manifest.presets ?? [];
    const preset = buildDashboardPreset(input, presets, manifest.variables ?? []);
    const isUpdate = presets.some((p) => p.id === preset.id);
    const nextPresets = isUpdate ? presets.map((p) => (p.id === preset.id ? preset : p)) : [...presets, preset];
    return saveDashboardPresets(context, user, workspaceId, manifest, nextPresets, buildPresetAuditInput('upsert', preset));
  });
};

export const workspacePresetDelete = async (context: AuthContext, user: AuthUser, workspaceId: string, presetId: string) => {
  return withWorkspaceManifestLock(workspaceId, async () => {
    const workspace = await loadDashboardForVariableEdition(context, user, workspaceId);
    const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
    const presets = manifest.presets ?? [];
    const preset = presets.find((p) => p.id === presetId);
    if (!preset) throw FunctionalError('Dashboard preset not found', { presetId });
    // A group or a user that references this preset as its default falls back to the dashboard defaults.
    const nextPresets = presets.filter((p) => p.id !== presetId);
    return saveDashboardPresets(context, user, workspaceId, manifest, nextPresets, buildPresetAuditInput('delete', preset));
  });
};

// One read of the user per HTTP request, whatever the number of dashboards resolved (a workspaces connection). A
// context without request (a subscription keeps one context for every payload) is not memoized: it would pin the
// user as they were when the subscription started.
const storedUsersByContext = new WeakMap<AuthContext, Map<string, Promise<BasicStoreEntityUser | undefined>>>();
const loadStoredUser = (context: AuthContext, userId: string) => {
  // An internal lookup: no read action is published for it.
  const load = () => internalLoadById<BasicStoreEntityUser>(context, SYSTEM_USER, userId, { type: ENTITY_TYPE_USER });
  if (!context.req) return load();
  let byUser = storedUsersByContext.get(context);
  if (!byUser) {
    byUser = new Map();
    storedUsersByContext.set(context, byUser);
  }
  let stored = byUser.get(userId);
  if (!stored) {
    stored = load();
    byUser.set(userId, stored);
  }
  return stored;
};

/**
 * The preset this dashboard opens on for the current user. The own choice of the user is read from the store
 * rather than from the authenticated user: that one comes from the platform cache, refreshed asynchronously across
 * the cluster, and the choice has to apply as soon as it is saved. The organizations and groups keep the cache.
 */
export const resolveCurrentUserDefaultPresetId = async (context: AuthContext, user: AuthUser, workspace: Pick<BasicStoreEntityWorkspace, 'id' | 'type' | 'manifest'>) => {
  if (workspace.type !== 'dashboard') return null;
  const stored = await loadStoredUser(context, user.id);
  const holder = stored
    ? { ...user, default_dashboard: stored.default_dashboard, default_dashboard_preset: stored.default_dashboard_preset }
    : user;
  return findCurrentUserDefaultPresetId(holder, workspace);
};
