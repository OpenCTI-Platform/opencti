import { useMemo, useRef, useState } from 'react';
import { FilterGroup, handleFilterHelpers } from './filtersHelpers-types';
import createFilterHelpers, { FilterChangeResult, WhenNoFilters } from './createFilterHelpers';
import { cloneFilterGroup, emptyFilterGroup, ensureFilterIds } from './filtersUtils';

/**
 * Filter state held in React state only (widgets, dialogs, anything not persisted in the url or
 * the local storage). The edition semantics come from `createFilterHelpers`, shared with
 * `usePaginationLocalStorage`; what is specific here is where the filters live.
 */
const useFiltersState = (initFilters: FilterGroup | null = emptyFilterGroup, defaultClearFilters: FilterGroup = emptyFilterGroup): [FilterGroup, handleFilterHelpers] => {
  const [filtersState, setFiltersState] = useState<FilterGroup>(() => ensureFilterIds(cloneFilterGroup(initFilters ?? emptyFilterGroup)));

  const latestAddFilterIdRef = useRef<string | undefined>(undefined);

  // Memoize helpers to prevent unnecessary re-renders when filter state changes
  const helpers: handleFilterHelpers = useMemo(() => createFilterHelpers({
    // The change is computed inside the state updater, so it always sees the latest filters.
    applyChange: (compute: (filters: FilterGroup) => FilterChangeResult, _whenNoFilters: WhenNoFilters) => {
      setFiltersState((prevState) => {
        const result = compute(prevState ?? emptyFilterGroup);
        if (!result) return prevState;
        latestAddFilterIdRef.current = result.anchor?.id;
        return result.filters;
      });
    },
    getLatestAddFilterId: () => latestAddFilterIdRef.current,
    clearAllFilters: () => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState(ensureFilterIds(cloneFilterGroup(defaultClearFilters)));
    },
  }), [defaultClearFilters]);

  return [filtersState, helpers];
};

export default useFiltersState;
