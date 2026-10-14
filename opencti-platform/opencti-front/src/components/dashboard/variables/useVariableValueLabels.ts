import { useEffect, useMemo, useState } from 'react';
import { fetchQuery, useRelayEnvironment } from 'react-relay';
import { filterValuesContentQuery } from '../../FilterValuesContent';
import type { FilterValuesContentQuery } from '../../__generated__/FilterValuesContentQuery.graphql';
import { useFormatter } from '../../i18n';
import type { DashboardVariableShape } from './DashboardVariableValueInput';
import { isIdVariableType } from './variableTypeSearch';

interface Resolution {
  signature: string;
  labels: Map<string, string | null>;
}

export interface VariableValueLabels {
  // Display label of each value. No entry for an id still resolving.
  labels: ReadonlyMap<string, string>;
  // The ids known to be unresolvable (deleted, not visible to the user, or the query failed). Their label is
  // `Restricted`, but this set, not the label, tells them from an entity that is really named `Restricted`.
  restricted: ReadonlySet<string>;
}

/**
 * Display label of each value of a variable.
 * Entity ids are resolved through the filters representatives (same query as `FilterValuesContent`): an id that
 * cannot be resolved (deleted, or not visible to the user) is labelled `Restricted`, never shown raw, and reported
 * in `restricted`. While the ids are resolving there is no entry for them. An entity type is labelled by its
 * translated name, other types by their value.
 */
const useVariableValueLabels = (variable: DashboardVariableShape, values: string[]): VariableValueLabels => {
  const { t_i18n } = useFormatter();
  const environment = useRelayEnvironment();
  const isIdType = isIdVariableType(variable.type);
  // Signatures keep the effect and the memo stable across renders that pass a new array with the same values.
  const valuesSignature = JSON.stringify(values);
  const idsSignature = isIdType ? JSON.stringify(values.filter((value) => value !== '')) : '[]';
  const [resolution, setResolution] = useState<Resolution | null>(null);

  useEffect(() => {
    const ids: string[] = JSON.parse(idsSignature);
    if (ids.length === 0) return undefined;
    const filters = { mode: 'and' as const, filterGroups: [], filters: [{ key: ['id'], values: ids, operator: 'eq' as const, mode: 'or' as const }] };
    const subscription = fetchQuery<FilterValuesContentQuery>(environment, filterValuesContentQuery, { filters }, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => setResolution({
          signature: idsSignature,
          labels: new Map(data.filtersRepresentatives.map((representative) => [representative.representativeId, representative.value ?? null])),
        }),
        error: () => setResolution({ signature: idsSignature, labels: new Map() }),
      });
    return () => subscription.unsubscribe();
  }, [environment, idsSignature]);

  return useMemo(() => {
    if (!isIdType) {
      const allValues: string[] = JSON.parse(valuesSignature);
      // An entity type is named as the platform names it (the same `entity_*` keys as the type search options).
      return {
        labels: new Map(allValues.map((value) => [value, variable.type === 'entityType' ? t_i18n(`entity_${value}`) : value])),
        restricted: new Set<string>(),
      };
    }
    if (resolution?.signature !== idsSignature) return { labels: new Map<string, string>(), restricted: new Set<string>() };
    const ids: string[] = JSON.parse(idsSignature);
    return {
      labels: new Map(ids.map((id) => [id, resolution.labels.get(id) ?? t_i18n('Restricted')])),
      restricted: new Set(ids.filter((id) => resolution.labels.get(id) == null)),
    };
  }, [isIdType, variable.type, valuesSignature, idsSignature, resolution, t_i18n]);
};

export default useVariableValueLabels;
