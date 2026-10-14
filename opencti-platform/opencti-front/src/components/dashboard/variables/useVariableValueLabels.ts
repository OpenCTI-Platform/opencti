import { useEffect, useMemo, useState } from 'react';
import { fetchQuery, useRelayEnvironment } from 'react-relay';
import { filterValuesContentQuery } from '../../FilterValuesContent';
import type { FilterValuesContentQuery } from '../../__generated__/FilterValuesContentQuery.graphql';
import { useFormatter } from '../../i18n';
import type { DashboardVariableShape } from './DashboardVariableValueInput';
import { isIdVariableType } from './variableTypeSearch';

export interface VariableValueLabels {
  // Display label of each value. No entry for an id still resolving.
  labels: ReadonlyMap<string, string>;
  // The ids known to be unresolvable (deleted, not visible to the user, or the query failed). Their label is
  // `Restricted`, but this set, not the label, tells them from an entity that is really named `Restricted`.
  restricted: ReadonlySet<string>;
}

// The name of each id (null when it cannot be resolved) once the query of exactly these ids has answered.
type Representatives = ReadonlyMap<string, string | null>;

interface Resolution {
  signature: string;
  representatives: Representatives;
}

/**
 * Resolves ids through the filters representatives (same query as `FilterValuesContent`), in one query for all of
 * them. Returns null until the query of exactly these ids has answered; a failed query answers no name for any id.
 */
const useRepresentatives = (ids: readonly string[]): Representatives | null => {
  const environment = useRelayEnvironment();
  // The signature keeps the effect stable across renders that pass a new array with the same ids.
  const idsSignature = JSON.stringify(ids);
  const [resolution, setResolution] = useState<Resolution | null>(null);

  useEffect(() => {
    const idsToResolve: string[] = JSON.parse(idsSignature);
    if (idsToResolve.length === 0) return undefined;
    const filters = { mode: 'and' as const, filterGroups: [], filters: [{ key: ['id'], values: idsToResolve, operator: 'eq' as const, mode: 'or' as const }] };
    const subscription = fetchQuery<FilterValuesContentQuery>(environment, filterValuesContentQuery, { filters }, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => setResolution({
          signature: idsSignature,
          representatives: new Map(data.filtersRepresentatives.map((representative) => [representative.representativeId, representative.value ?? null])),
        }),
        error: () => setResolution({ signature: idsSignature, representatives: new Map() }),
      });
    return () => subscription.unsubscribe();
  }, [environment, idsSignature]);

  return resolution?.signature === idsSignature ? resolution.representatives : null;
};

const NO_LABELS: VariableValueLabels = { labels: new Map(), restricted: new Set() };

/**
 * Labels of the values of one variable once its ids are known: an id that cannot be resolved is labelled
 * `Restricted`, never shown raw, and reported in `restricted`; while the ids are resolving there is no entry for
 * them. An entity type is labelled by its translated name, other types by their value.
 */
const buildLabels = (
  type: DashboardVariableShape['type'],
  values: readonly string[],
  representatives: Representatives | null,
  translate: (text: string) => string,
): VariableValueLabels => {
  if (!isIdVariableType(type)) {
    // An entity type is named as the platform names it (the same `entity_*` keys as the type search options).
    return {
      labels: new Map(values.map((value) => [value, type === 'entityType' ? translate(`entity_${value}`) : value])),
      restricted: new Set(),
    };
  }
  const ids = values.filter((value) => value !== '');
  if (!representatives || ids.length === 0) return NO_LABELS;
  return {
    labels: new Map(ids.map((id) => [id, representatives.get(id) ?? translate('Restricted')])),
    restricted: new Set(ids.filter((id) => representatives.get(id) == null)),
  };
};

/**
 * Display label of each value of a variable, resolved on its own (inputs of a popover).
 * The chips of a bar use `useVariablesValueLabels` instead, which resolves all of them at once.
 */
const useVariableValueLabels = (variable: DashboardVariableShape, values: string[]): VariableValueLabels => {
  const { t_i18n } = useFormatter();
  const isIdType = isIdVariableType(variable.type);
  const valuesSignature = JSON.stringify(values);
  const idsSignature = isIdType ? JSON.stringify(values.filter((value) => value !== '')) : '[]';
  const ids = useMemo<string[]>(() => JSON.parse(idsSignature), [idsSignature]);
  const representatives = useRepresentatives(ids);
  return useMemo(
    () => buildLabels(variable.type, JSON.parse(valuesSignature), representatives, t_i18n),
    [variable.type, valuesSignature, representatives, t_i18n],
  );
};

export interface VariableCurrentValue {
  // Identifies the variable in the result.
  id: string;
  variable: DashboardVariableShape;
  value: string | undefined;
}

/**
 * Labels of the current value of several variables, by variable id. Whatever their number, the ids of all the
 * variables that hold one are resolved in one single query.
 */
export const useVariablesValueLabels = (current: readonly VariableCurrentValue[]): ReadonlyMap<string, VariableValueLabels> => {
  const { t_i18n } = useFormatter();
  const signature = JSON.stringify(current.map(({ id, variable, value }) => [id, variable.type, value ?? '']));
  const ids = useMemo(() => {
    const entries: [string, DashboardVariableShape['type'], string][] = JSON.parse(signature);
    return [...new Set(entries.filter(([, type, value]) => isIdVariableType(type) && value !== '').map(([, , value]) => value))];
  }, [signature]);
  const representatives = useRepresentatives(ids);
  return useMemo(() => {
    const entries: [string, DashboardVariableShape['type'], string][] = JSON.parse(signature);
    return new Map(entries.map(([id, type, value]) => [id, buildLabels(type, value === '' ? [] : [value], representatives, t_i18n)]));
  }, [signature, representatives, t_i18n]);
};

export default useVariableValueLabels;
