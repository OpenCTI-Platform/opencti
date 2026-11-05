import type { DashboardPreset, DashboardVariable } from '../dashboard-types';
import { isSameTimeRange, pickTimeRange, type DashboardTimeRange } from '../dashboardTimeRange';

// A preset as the GraphQL API serves it: the values as a list, the time range possibly partial.
export interface GraphqlDashboardPreset {
  readonly id: string;
  readonly name: string;
  readonly values: readonly { readonly variableId: string; readonly value: string }[];
  readonly config: { readonly startDate?: string | null; readonly endDate?: string | null; readonly relativeDate?: string | null };
}

export const presetFromGraphql = (preset: GraphqlDashboardPreset): DashboardPreset => ({
  id: preset.id,
  name: preset.name,
  values: Object.fromEntries(preset.values.map(({ variableId, value }) => [variableId, value])),
  config: pickTimeRange(preset.config),
});

/**
 * The values a preset restores: its own value for every variable it holds, the manifest default for the others.
 * Only the variables that still exist are kept.
 */
export const presetEffectiveValues = (preset: DashboardPreset, variables: readonly DashboardVariable[], defaults: ReadonlyMap<string, string>) => {
  const values = new Map<string, string>();
  variables.forEach(({ id }) => {
    const value = preset.values[id] ?? defaults.get(id);
    if (value !== undefined && value !== '') values.set(id, value);
  });
  return values;
};

/**
 * Whether the current values and time range still are the ones of the preset: a changed value makes the preset
 * "modified", which offers to update it (like a saved filter).
 */
export const isPresetModified = (
  preset: DashboardPreset,
  variables: readonly DashboardVariable[],
  defaults: ReadonlyMap<string, string>,
  values: ReadonlyMap<string, string>,
  range: DashboardTimeRange,
) => {
  const expected = presetEffectiveValues(preset, variables, defaults);
  const differs = variables.some(({ id }) => (values.get(id) ?? '') !== (expected.get(id) ?? ''));
  return differs || !isSameTimeRange(range, preset.config);
};

/**
 * The input of the upsert mutation for the current values and range: a value equal to the manifest default is
 * stored all the same, so that the preset restores it even if the default changes later.
 */
export const presetInputFromValues = (
  name: string,
  variables: readonly DashboardVariable[],
  values: ReadonlyMap<string, string>,
  range: DashboardTimeRange,
  id?: string,
) => ({
  ...(id && { id }),
  name,
  values: variables.flatMap(({ id: variableId }) => {
    const value = values.get(variableId);
    return value !== undefined && value !== '' ? [{ variableId, value }] : [];
  }),
  config: { startDate: range.startDate, endDate: range.endDate, relativeDate: range.relativeDate },
});
