import * as R from 'ramda';
import { type DashboardVariable, type DashboardVariableRestrictionMode, type DashboardVariableType, type EditInput, VocabularyCategory } from '../../generated/graphql';
import { fromB64, toB64 } from '../../utils/base64';
import { FunctionalError } from '../../config/errors';
import { computeDashboardVariablesUsage } from '../dashboard/dashboard-variables-resolution';
import { DASHBOARD_MANIFEST_SERVER_OWNED_KEYS, type DashboardVariableTypeName, type StoreDashboardManifest, type StoreDashboardVariable } from './workspace-variables-types';
import { buildDashboardVariable, type DashboardVariableInputLike } from './workspace-variables-validation';

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

const DASHBOARD_VARIABLE_TYPE_NAMES: ReadonlySet<string> = new Set<DashboardVariableTypeName>([
  'vocabulary', 'killChainPhase', 'entity', 'entityType', 'label', 'user',
  'marking', 'status', 'group', 'boolean', 'numeric', 'text', 'date',
]);
const RESTRICTION_MODES: ReadonlySet<string> = new Set(['none', 'selection', 'filters']);
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

/**
 * Validate the server-owned keys of a manifest written outside the typed API (configuration import,
 * duplication): every variable goes through the same validation as workspaceVariableUpsert, keeping its id
 * so the widget tokens still resolve. Presets are dropped until they can be validated.
 * A manifest without these keys is returned untouched.
 */
export const validateManifestVariables = (encoded: string | null | undefined) => {
  if (!encoded) return encoded;
  const manifest = parseManifestObject(encoded);
  if (!manifest || !DASHBOARD_MANIFEST_SERVER_OWNED_KEYS.some((key) => key in manifest)) return encoded;
  const { variables } = manifest;
  if (variables !== undefined && !Array.isArray(variables)) throw FunctionalError('Invalid dashboard variables');
  const validated: StoreDashboardVariable[] = [];
  (variables ?? []).forEach((variable: unknown) => {
    const input = toVariableInput(variable);
    if (input.id && validated.some((existing) => existing.id === input.id)) {
      throw FunctionalError('Duplicated dashboard variable id', { variableId: input.id });
    }
    validated.push(buildDashboardVariable(input, validated));
  });
  const withoutServerKeys = R.omit([...DASHBOARD_MANIFEST_SERVER_OWNED_KEYS], manifest);
  return toB64(variables === undefined ? withoutServerKeys : { ...withoutServerKeys, variables: validated });
};
