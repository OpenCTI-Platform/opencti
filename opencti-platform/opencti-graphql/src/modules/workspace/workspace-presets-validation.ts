import { v4 as uuidv4 } from 'uuid';
import validator from 'validator';
import { FunctionalError } from '../../config/errors';
import { containsDashboardVariableToken, isValidDashboardVariableValue } from '../dashboard/dashboard-variables-resolution';
import { buildDashboardTimeRange, type DashboardTimeRangeInputLike } from '../dashboard/dashboard-time-range';
import {
  DASHBOARD_PRESET_NAME_MAX_LENGTH,
  DASHBOARD_PRESETS_MAX_COUNT,
  type StoreDashboardPreset,
  type StoreDashboardVariable,
} from './workspace-variables-types';

// Structural shape of the GraphQL DashboardPresetInput.
export interface DashboardPresetInputLike {
  id?: string | null;
  name: string;
  values?: readonly { variableId: string; value: string }[] | null;
  config?: DashboardTimeRangeInputLike | null;
}

export interface BuildDashboardPresetOptions {
  // Import and duplication: a value for a variable the dashboard does not hold is dropped instead of refused, since
  // the file may come from another platform. The typed API refuses it.
  dropUnknownVariables?: boolean;
  now?: Date;
}

/**
 * The values of a preset, keyed by variable id: each one belongs to a variable of the dashboard, is valid for the type
 * of this variable and, for a selection restriction, belongs to the selection (a filters restriction is not checked:
 * it would need a query). An empty value is not stored: the default of the variable then applies.
 */
const buildPresetValues = (
  input: DashboardPresetInputLike,
  variables: readonly StoreDashboardVariable[],
  dropUnknownVariables: boolean,
): Record<string, string> => {
  const byId = new Map(variables.map((variable) => [variable.id, variable]));
  const values: Record<string, string> = {};
  (input.values ?? []).forEach(({ variableId, value }) => {
    if (typeof variableId !== 'string' || typeof value !== 'string') throw FunctionalError('Invalid dashboard preset value');
    const variable = byId.get(variableId);
    if (!variable) {
      if (dropUnknownVariables) return;
      throw FunctionalError('Unknown dashboard variable', { variableId });
    }
    if (variableId in values) throw FunctionalError('Duplicated dashboard preset value', { variableId });
    if (value.trim() === '') return;
    // A value is never resolved further than one level: a token-shaped value would leave a token in the filter.
    if (containsDashboardVariableToken(value) || !isValidDashboardVariableValue(variable.type, value)) {
      throw FunctionalError('Invalid dashboard preset value', { variableId });
    }
    // A selection restriction is a closed list: a preset cannot restore a value the chip could not offer.
    if (variable.restriction.mode === 'selection' && !variable.restriction.values.includes(value)) {
      if (dropUnknownVariables) return;
      throw FunctionalError('The preset value must belong to the selection of the variable', { variableId });
    }
    values[variableId] = value;
  });
  return values;
};

/**
 * Validate a preset input against the presets and the variables already stored in the dashboard and build the preset
 * to store. Throws a FunctionalError on any invalid input.
 */
export const buildDashboardPreset = (
  input: DashboardPresetInputLike,
  existingPresets: readonly StoreDashboardPreset[],
  variables: readonly StoreDashboardVariable[],
  { dropUnknownVariables = false }: BuildDashboardPresetOptions = {},
): StoreDashboardPreset => {
  const current = input.id ? existingPresets.find((preset) => preset.id === input.id) : undefined;
  // An unknown id recreates the preset with it: a reference kept elsewhere (a default dashboard of a group) resolves again.
  if (input.id != null && !current && !validator.isUUID(input.id)) {
    throw FunctionalError('Invalid dashboard preset id', { presetId: input.id });
  }
  if (!current && existingPresets.length >= DASHBOARD_PRESETS_MAX_COUNT) {
    throw FunctionalError(`A dashboard cannot hold more than ${DASHBOARD_PRESETS_MAX_COUNT} presets`);
  }
  if (typeof input.name !== 'string') throw FunctionalError('Dashboard preset name is required');
  const name = input.name.trim();
  if (name === '') throw FunctionalError('Dashboard preset name is required');
  if (name.length > DASHBOARD_PRESET_NAME_MAX_LENGTH) throw FunctionalError('Dashboard preset name is too long');
  const isDuplicatedName = existingPresets.some((preset) => preset.id !== current?.id
    && preset.name.trim().toLowerCase() === name.toLowerCase());
  if (isDuplicatedName) throw FunctionalError('A dashboard preset with this name already exists', { name });
  const values = buildPresetValues(input, variables, dropUnknownVariables);
  const config = buildDashboardTimeRange(input.config, 'Invalid dashboard preset time range');
  return { id: input.id ?? uuidv4(), name, values, config };
};

/**
 * The presets of a dashboard once one of its variables is deleted: the value of this variable is removed from every
 * preset, which is otherwise kept (its other values and its time range still make sense).
 */
export const removeVariableFromPresets = (presets: readonly StoreDashboardPreset[], variableId: string): StoreDashboardPreset[] => {
  return presets.map((preset) => {
    if (!(variableId in preset.values)) return preset;
    const { [variableId]: _removed, ...values } = preset.values;
    return { ...preset, values };
  });
};
