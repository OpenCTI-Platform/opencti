import { FunctionalError } from '../../config/errors';
import { editInternalObject } from '../../domain/internalObject';
import type { DashboardPresetInput, EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { fromB64, toB64 } from '../../utils/base64';
import { ENTITY_TYPE_WORKSPACE, type StoreEntityWorkspace } from './workspace-types';
import type { StoreDashboardManifest, StoreDashboardPreset } from './workspace-variables-types';
import { buildDashboardPreset } from './workspace-presets-validation';
import { loadDashboardForVariableEdition, withWorkspaceManifestLock } from './workspace-variables-domain';

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
