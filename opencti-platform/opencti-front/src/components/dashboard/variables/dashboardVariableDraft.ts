import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import type { DashboardVariable, DashboardVariableRestriction, DashboardVariableType } from '../dashboard-types';
import { isStrictIsoDate } from '../dashboardVariablesResolution';

// Mirror of the server limits (workspace-variables-types.ts).
export const DASHBOARD_VARIABLES_LIMITS = { variables: 50, nameLength: 200, selectionValues: 200 } as const;

const VARIABLE_TOKEN_PREFIX = '$var:';

export interface DashboardVariableDraft {
  id?: string;
  name: string;
  type: DashboardVariableType | '';
  vocabularyCategory: string;
  killChainName: string;
  entityTypes: string[];
  restrictionMode: 'none' | 'selection' | 'filters';
  selectionValues: string[];
  filters?: FilterGroup;
  defaultValue: string;
}

export const emptyDraft: DashboardVariableDraft = {
  name: '',
  type: '',
  vocabularyCategory: '',
  killChainName: '',
  entityTypes: [],
  restrictionMode: 'none',
  selectionValues: [],
  filters: undefined,
  defaultValue: '',
};

export const variableToDraft = (variable: DashboardVariable): DashboardVariableDraft => ({
  ...emptyDraft,
  id: variable.id,
  name: variable.name,
  type: variable.type,
  ...(variable.type === 'vocabulary' && { vocabularyCategory: variable.vocabularyCategory }),
  ...(variable.type === 'killChainPhase' && { killChainName: variable.killChainName }),
  ...(variable.type === 'entity' && { entityTypes: variable.entityTypes }),
  restrictionMode: variable.restriction.mode,
  ...(variable.restriction.mode === 'selection' && { selectionValues: variable.restriction.values }),
  ...(variable.restriction.mode === 'filters' && { filters: variable.restriction.filters }),
  defaultValue: variable.defaultValue ?? '',
});

const draftToRestriction = (draft: DashboardVariableDraft): DashboardVariableRestriction => {
  if (draft.restrictionMode === 'selection') return { mode: 'selection', values: draft.selectionValues };
  if (draft.restrictionMode === 'filters' && draft.filters) return { mode: 'filters', filters: draft.filters };
  return { mode: 'none' };
};

// A boolean, numeric or date default is stored trimmed (as validateDraft checks it): the spaces would otherwise reach the
// filters of the widgets. The default of any other type is stored as typed.
// A valid date default is also stored normalized (`toISOString`), like the server does, unless a selection restriction
// holds it: the default must then stay the pool value it matches.
const draftToDefaultValue = (draft: DashboardVariableDraft) => {
  const isTyped = draft.type === 'boolean' || draft.type === 'numeric' || draft.type === 'date';
  const defaultValue = isTyped ? draft.defaultValue.trim() : draft.defaultValue;
  if (draft.type === 'date' && draft.restrictionMode !== 'selection' && isStrictIsoDate(defaultValue)) {
    return new Date(defaultValue).toISOString();
  }
  return defaultValue === '' ? null : defaultValue;
};

export const draftToVariable = (draft: DashboardVariableDraft, id: string): DashboardVariable => {
  const common = {
    id,
    name: draft.name.trim(),
    restriction: draftToRestriction(draft),
    defaultValue: draftToDefaultValue(draft),
  };
  const type = draft.type as DashboardVariableType;
  if (type === 'vocabulary') return { ...common, type, vocabularyCategory: draft.vocabularyCategory };
  if (type === 'killChainPhase') return { ...common, type, killChainName: draft.killChainName.trim() };
  if (type === 'entity') return { ...common, type, entityTypes: draft.entityTypes };
  return { ...common, type };
};

/**
 * Validate a draft against the dashboard variables. Returns a map field -> message
 * (empty when valid). Selection and filters restrictions are not validated here.
 * Errors that belong to no field are returned under the `form` key.
 */
export const validateDraft = (
  draft: DashboardVariableDraft,
  existing: readonly DashboardVariable[],
  t_i18n: (s: string) => string,
): Record<string, string> => {
  const errors: Record<string, string> = {};
  const isEditing = draft.id !== undefined && existing.some((variable) => variable.id === draft.id);
  if (!isEditing && existing.length >= DASHBOARD_VARIABLES_LIMITS.variables) {
    errors.form = t_i18n('A dashboard cannot hold more than 50 variables');
  }

  const name = draft.name.trim();
  if (name === '') {
    errors.name = t_i18n('Name is required');
  } else if (name.length > DASHBOARD_VARIABLES_LIMITS.nameLength) {
    errors.name = t_i18n('Name is too long');
  } else if (existing.some((variable) => variable.id !== draft.id && variable.name.trim().toLowerCase() === name.toLowerCase())) {
    errors.name = t_i18n('A variable with this name already exists');
  }

  if (draft.type === '') errors.type = t_i18n('Type is required');
  if (draft.type === 'vocabulary' && draft.vocabularyCategory.trim() === '') {
    errors.vocabularyCategory = t_i18n('Vocabulary category is required');
  }
  if (draft.type === 'killChainPhase' && draft.killChainName.trim() === '') {
    errors.killChainName = t_i18n('Kill chain is required');
  }
  if (draft.type === 'entity' && draft.entityTypes.length === 0) {
    errors.entityTypes = t_i18n('At least one entity type is required');
  }

  const defaultValue = draft.defaultValue.trim();
  if (defaultValue.includes(VARIABLE_TOKEN_PREFIX)) {
    errors.defaultValue = t_i18n('A value cannot reference another variable');
  } else if (defaultValue === '') {
    // The server defaults a blank boolean or date, but the form makes the user choose one.
    errors.defaultValue = t_i18n('Default value is required');
  } else if (draft.type === 'numeric' && !Number.isFinite(Number(defaultValue))) {
    errors.defaultValue = t_i18n('Default value must be a number');
  } else if (draft.type === 'boolean' && defaultValue !== 'true' && defaultValue !== 'false') {
    errors.defaultValue = t_i18n('Default value is not valid');
  } else if (draft.type === 'date' && !isStrictIsoDate(defaultValue)) {
    errors.defaultValue = t_i18n('Default value is not valid');
  }
  return errors;
};
