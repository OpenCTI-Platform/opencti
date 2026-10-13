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

/**
 * Display label of each value of a variable.
 * Entity ids are resolved through the filters representatives (same query as `FilterValuesContent`): an id that
 * cannot be resolved (deleted, or not visible to the user) is labelled `Restricted`, never shown raw.
 * While the ids are resolving the map has no entry for them. Other types are labelled by their value.
 */
const useVariableValueLabels = (variable: DashboardVariableShape, values: string[]): Map<string, string> => {
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
      return new Map(allValues.map((value) => [value, value]));
    }
    if (resolution?.signature !== idsSignature) return new Map();
    const ids: string[] = JSON.parse(idsSignature);
    return new Map(ids.map((id) => [id, resolution.labels.get(id) ?? t_i18n('Restricted')]));
  }, [isIdType, valuesSignature, idsSignature, resolution, t_i18n]);
};

export default useVariableValueLabels;
