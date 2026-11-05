import * as R from 'ramda';
import { type DashboardPreset, type DashboardVariable, DashboardVariableRestrictionMode, DashboardVariableType, type EditInput, VocabularyCategory } from '../../generated/graphql';
import { fromB64, toB64 } from '../../utils/base64';
import { FunctionalError } from '../../config/errors';
import type { AuthUser } from '../../types/user';
import { computeDashboardVariablesUsage } from '../dashboard/dashboard-variables-resolution';
import { DASHBOARD_MANIFEST_SERVER_OWNED_KEYS, type StoreDashboardManifest, type StoreDashboardPreset, type StoreDashboardVariable } from './workspace-variables-types';
import { buildDashboardVariable, type DashboardVariableInputLike } from './workspace-variables-validation';
import { buildDashboardPreset, type DashboardPresetInputLike } from './workspace-presets-validation';

export const buildVariableAuditInput = (
  operation: 'upsert' | 'delete',
  variable: Pick<StoreDashboardVariable, 'id' | 'name' | 'type'>,
): EditInput[] => {
  // Never the manifest: it can be huge and carries every widget definition.
  return [{ key: 'variables', value: [{ operation, id: variable.id, name: variable.name, type: variable.type }] }];
};

type WorkspaceLike = { id?: string; type?: string | null; manifest?: string | null };

// The three Workspace fields below decode the same manifest of the same loaded workspace: decoded once per object.
const decodedManifests = new WeakMap<object, { encoded: string; manifest: StoreDashboardManifest }>();
const decodeDashboardManifest = (workspace: WorkspaceLike): StoreDashboardManifest | null => {
  if (workspace.type !== 'dashboard' || !workspace.manifest) return null;
  const cached = decodedManifests.get(workspace);
  if (cached && cached.encoded === workspace.manifest) return cached.manifest;
  const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
  decodedManifests.set(workspace, { encoded: workspace.manifest, manifest });
  return manifest;
};

export const toGraphqlDashboardVariables = (workspace: WorkspaceLike): DashboardVariable[] => {
  const manifest = decodeDashboardManifest(workspace);
  if (!manifest || !manifest.variables || manifest.variables.length === 0) return [];
  const usage = computeDashboardVariablesUsage(manifest.widgets);
  return manifest.variables.map((variable) => {
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

export const toGraphqlDashboardPresets = (workspace: WorkspaceLike): DashboardPreset[] => {
  const manifest = decodeDashboardManifest(workspace);
  if (!manifest) return [];
  return (manifest.presets ?? []).map((preset) => ({
    id: preset.id,
    name: preset.name,
    values: Object.entries(preset.values ?? {}).map(([variableId, value]) => ({ variableId, value })),
    config: {
      startDate: preset.config?.startDate ?? null,
      endDate: preset.config?.endDate ?? null,
      relativeDate: preset.config?.relativeDate ?? null,
    },
  }));
};

type DefaultDashboardHolder = { default_dashboard?: string | null; default_dashboard_preset?: string | null };

/**
 * The preset this dashboard opens on for the current user: the one attached to their own default dashboard choice,
 * else the one of the first organization or group (the order of findDefaultDashboards) whose default dashboard is this
 * one. Null when no holder points to this dashboard, when the first one holds no preset, or when it no longer exists.
 */
export const findCurrentUserDefaultPresetId = (user: AuthUser, workspace: WorkspaceLike & { id: string }) => {
  if (workspace.type !== 'dashboard' || !workspace.manifest) return null;
  const self = user as unknown as DefaultDashboardHolder;
  const holders: DefaultDashboardHolder[] = [
    ...(self.default_dashboard ? [self] : []),
    ...((user.organizations ?? []) as unknown as DefaultDashboardHolder[]),
    ...((user.groups ?? []) as unknown as DefaultDashboardHolder[]),
  ];
  // The first holder that opens on this dashboard decides, with or without a preset: a user who chose this dashboard
  // with No preset is not caught up by the preset of their group.
  const holder = holders.find((candidate) => candidate.default_dashboard === workspace.id);
  if (!holder?.default_dashboard_preset) return null;
  const manifest = decodeDashboardManifest(workspace);
  return (manifest?.presets ?? []).some((preset) => preset.id === holder.default_dashboard_preset) ? holder.default_dashboard_preset : null;
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

// Derived from the GraphQL enums: an imported variable is checked against exactly what the mutation accepts.
const DASHBOARD_VARIABLE_TYPE_NAMES: ReadonlySet<string> = new Set(Object.values(DashboardVariableType));
const RESTRICTION_MODES: ReadonlySet<string> = new Set(Object.values(DashboardVariableRestrictionMode));
const VOCABULARY_CATEGORIES: ReadonlySet<string> = new Set(Object.values(VocabularyCategory));

const isOptionalString = (value: unknown) => value === undefined || value === null || typeof value === 'string';
const isOptionalStringList = (value: unknown) => value === undefined || value === null
  || (Array.isArray(value) && value.every((item) => typeof item === 'string'));

// A stored variable coming from outside the typed API (import, duplication) is untrusted:
// what GraphQL checks on the mutation input (enums, scalar types) is checked here.
const toVariableInput = (variable: unknown): DashboardVariableInputLike => {
  if (typeof variable !== 'object' || variable === null || Array.isArray(variable)) throw FunctionalError('Invalid dashboard variable');
  const value = variable as Record<string, any>;
  if (typeof value.name !== 'string' || !isOptionalString(value.id) || !isOptionalString(value.defaultValue)
    || !isOptionalString(value.killChainName) || !isOptionalStringList(value.entityTypes)) {
    throw FunctionalError('Invalid dashboard variable', { variableId: value.id });
  }
  if (!DASHBOARD_VARIABLE_TYPE_NAMES.has(value.type)) throw FunctionalError('Invalid dashboard variable type', { type: value.type });
  if (value.vocabularyCategory != null && !(typeof value.vocabularyCategory === 'string' && VOCABULARY_CATEGORIES.has(value.vocabularyCategory))) {
    throw FunctionalError('Invalid dashboard variable vocabulary category', { vocabularyCategory: value.vocabularyCategory });
  }
  const restriction = value.restriction ?? { mode: 'none' };
  if (typeof restriction !== 'object' || !RESTRICTION_MODES.has(restriction.mode) || !isOptionalStringList(restriction.values)) {
    throw FunctionalError('Invalid dashboard variable restriction', { variableId: value.id });
  }
  const filters = restriction.mode === 'filters' && restriction.filters ? JSON.stringify(restriction.filters) : restriction.filters;
  return {
    id: value.id,
    name: value.name,
    type: value.type,
    vocabularyCategory: value.vocabularyCategory,
    killChainName: value.killChainName,
    entityTypes: value.entityTypes,
    restriction: { mode: restriction.mode, values: restriction.values, filters },
    defaultValue: value.defaultValue,
  };
};

// A stored preset coming from outside the typed API (import, duplication) is untrusted: checked like the mutation input.
const toPresetInput = (preset: unknown): DashboardPresetInputLike => {
  if (typeof preset !== 'object' || preset === null || Array.isArray(preset)) throw FunctionalError('Invalid dashboard preset');
  const value = preset as Record<string, any>;
  if (typeof value.name !== 'string' || !isOptionalString(value.id)) throw FunctionalError('Invalid dashboard preset', { presetId: value.id });
  const values = value.values ?? {};
  if (typeof values !== 'object' || values === null || Array.isArray(values)) throw FunctionalError('Invalid dashboard preset values', { presetId: value.id });
  const config = value.config ?? {};
  if (typeof config !== 'object' || config === null || Array.isArray(config)
    || !isOptionalString(config.startDate) || !isOptionalString(config.endDate) || !isOptionalString(config.relativeDate)) {
    throw FunctionalError('Invalid dashboard preset time range', { presetId: value.id });
  }
  return {
    id: value.id,
    name: value.name,
    values: Object.entries(values).map(([variableId, presetValue]) => ({ variableId, value: presetValue as string })),
    config: { startDate: config.startDate, endDate: config.endDate, relativeDate: config.relativeDate },
  };
};

/**
 * Validate the server-owned keys of a manifest written outside the typed API (configuration import,
 * duplication): every variable goes through the same validation as workspaceVariableUpsert, keeping its id
 * so the widget tokens still resolve, and every preset through the same validation as workspacePresetUpsert
 * (a value for a variable the dashboard does not hold is dropped, the preset is kept).
 * A manifest without these keys is returned untouched.
 */
export const validateManifestVariables = (encoded: string | null | undefined) => {
  if (!encoded) return encoded;
  const manifest = parseManifestObject(encoded);
  if (!manifest || !DASHBOARD_MANIFEST_SERVER_OWNED_KEYS.some((key) => key in manifest)) return encoded;
  const { variables, presets } = manifest;
  if (variables !== undefined && !Array.isArray(variables)) throw FunctionalError('Invalid dashboard variables');
  if (presets !== undefined && !Array.isArray(presets)) throw FunctionalError('Invalid dashboard presets');
  const validated: StoreDashboardVariable[] = [];
  (variables ?? []).forEach((variable: unknown) => {
    const input = toVariableInput(variable);
    if (input.id && validated.some((existing) => existing.id === input.id)) {
      throw FunctionalError('Duplicated dashboard variable id', { variableId: input.id });
    }
    validated.push(buildDashboardVariable(input, validated));
  });
  const validatedPresets: StoreDashboardPreset[] = [];
  (presets ?? []).forEach((preset: unknown) => {
    const input = toPresetInput(preset);
    if (input.id && validatedPresets.some((existing) => existing.id === input.id)) {
      throw FunctionalError('Duplicated dashboard preset id', { presetId: input.id });
    }
    validatedPresets.push(buildDashboardPreset(input, validatedPresets, validated, { dropUnknownVariables: true }));
  });
  const withoutServerKeys = R.omit([...DASHBOARD_MANIFEST_SERVER_OWNED_KEYS], manifest);
  return toB64({
    ...withoutServerKeys,
    ...(variables !== undefined && { variables: validated }),
    ...(presets !== undefined && { presets: validatedPresets }),
  });
};

/**
 * Remove the server-owned keys from a manifest stored where dashboard variables cannot live
 * (custom views): a malformed or forged `variables` key would otherwise reach the frontend.
 * A manifest without these keys, or unreadable, is returned untouched.
 */
export const stripServerOwnedManifestKeys = (encoded: string | null | undefined) => {
  if (!encoded) return encoded;
  const manifest = parseManifestObject(encoded);
  if (!manifest || !DASHBOARD_MANIFEST_SERVER_OWNED_KEYS.some((key) => key in manifest)) return encoded;
  return toB64(R.omit([...DASHBOARD_MANIFEST_SERVER_OWNED_KEYS], manifest));
};
