import { useMemo } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { FilterValuesContentQuery } from '../__generated__/FilterValuesContentQuery.graphql';
import { filterValuesContentQuery } from '../FilterValuesContent';
import { useBuildFilterKeysMapFromEntityType } from '../../utils/filters/filtersUtils';
import { FilterRepresentative } from './FiltersModel';

interface UseFilterRepresentativesArgs {
  filtersRepresentativesQueryRef: PreloadedQuery<FilterValuesContentQuery>;
  entityTypes?: string[];
  /** Explicit list of keys offered by the filter editors, defaults to every known key. */
  availableFilterKeys?: string[];
}

/**
 * Reads the preloaded filter representatives and exposes the lookup structures every
 * filter renderer needs: the representative map (id -> label/color) and the filter keys
 * available to the editors.
 */
const useFilterRepresentatives = ({
  filtersRepresentativesQueryRef,
  entityTypes,
  availableFilterKeys,
}: UseFilterRepresentativesArgs) => {
  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    filtersRepresentativesQueryRef,
  );
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);

  const filtersRepresentativesMap = useMemo(
    () => new Map<string, FilterRepresentative>(
      filtersRepresentatives.map((n: FilterRepresentative) => [n.representativeId, n]),
    ),
    [filtersRepresentatives],
  );

  const panelFilterKeys = useMemo(
    () => availableFilterKeys ?? Array.from(filterKeysMap.keys()),
    [availableFilterKeys, filterKeysMap],
  );

  return { filtersRepresentativesMap, filterKeysMap, panelFilterKeys };
};

export default useFilterRepresentatives;
