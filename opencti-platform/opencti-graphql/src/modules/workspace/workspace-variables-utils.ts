import type { DashboardVariable, DashboardVariableRestrictionMode, DashboardVariableType, EditInput, VocabularyCategory } from '../../generated/graphql';
import { fromB64, toB64 } from '../../utils/base64';
import { FunctionalError } from '../../config/errors';
import { computeDashboardVariablesUsage } from '../dashboard/dashboard-variables-resolution';
import { DASHBOARD_MANIFEST_SERVER_OWNED_KEYS, type StoreDashboardManifest, type StoreDashboardVariable } from './workspace-variables-types';

export const buildVariableAuditInput = (
  operation: 'upsert' | 'delete',
  variable: Pick<StoreDashboardVariable, 'id' | 'name' | 'type'>,
): EditInput[] => {
  // Never the manifest: it can be huge and carries every widget definition.
  return [{ key: 'variables', value: [{ operation, id: variable.id, name: variable.name, type: variable.type }] }];
};

export const toGraphqlDashboardVariables = (workspace: { type?: string | null; manifest?: string | null }): DashboardVariable[] => {
  if (workspace.type !== 'dashboard' || !workspace.manifest) return [];
  const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
  const usage = computeDashboardVariablesUsage(manifest.widgets);
  return (manifest.variables ?? []).map((variable) => {
    const { restriction } = variable;
    return {
      id: variable.id,
      name: variable.name,
      type: variable.type as DashboardVariableType,
      vocabularyCategory: variable.type === 'vocabulary' ? variable.vocabularyCategory as VocabularyCategory : null,
      killChainName: variable.type === 'killChainPhase' ? variable.killChainName : null,
      entityTypes: variable.type === 'entity' ? variable.entityTypes : null,
      restriction: {
        mode: restriction.mode as DashboardVariableRestrictionMode,
        values: restriction.mode === 'selection' ? restriction.values : null,
        filters: restriction.mode === 'filters' ? JSON.stringify(restriction.filters) : null,
      },
      defaultValue: variable.defaultValue,
      usedInWidgetIds: usage.get(variable.id) ?? [],
    };
  });
};

const parseManifestObject = (encoded: string): Record<string, unknown> | null => {
  try {
    const parsed = fromB64(encoded);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

/**
 * `variables` and `presets` belong to the server: a full manifest sent through workspaceFieldPatch
 * (built from a possibly stale client copy) can neither add, change nor erase them.
 * The manifest is only rewritten when one of these keys is involved, so legacy dashboards keep
 * their exact encoding.
 */
export const preserveServerOwnedManifestKeys = (inputs: EditInput[], storedManifest: string | null | undefined): EditInput[] => {
  const stored = (storedManifest ? parseManifestObject(storedManifest) : null) ?? {};
  const storedHasServerKeys = DASHBOARD_MANIFEST_SERVER_OWNED_KEYS.some((key) => key in stored);
  return inputs.map((input) => {
    if (input.key !== 'manifest') return input;
    const encoded = input.value?.[0];
    const incoming = typeof encoded === 'string' && encoded !== '' ? parseManifestObject(encoded) : null;
    if (!incoming) {
      if (storedHasServerKeys) throw FunctionalError('Invalid dashboard manifest');
      return input;
    }
    const incomingHasServerKeys = DASHBOARD_MANIFEST_SERVER_OWNED_KEYS.some((key) => key in incoming);
    if (!incomingHasServerKeys && !storedHasServerKeys) return input;
    const next: Record<string, unknown> = { ...incoming };
    DASHBOARD_MANIFEST_SERVER_OWNED_KEYS.forEach((key) => {
      if (key in stored) next[key] = stored[key];
      else delete next[key];
    });
    return { ...input, value: [toB64(next)] };
  });
};
