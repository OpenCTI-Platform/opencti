import { useMemo, useRef, useState } from 'react';
import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from './filtersHelpers-types';
import {
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeOperatorFiltersUtil,
  handleChangeRepresentationFilterUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleReplaceFilterValuesUtil,
  handleSwitchLocalModeUtil,
} from './filtersManageStateUtil';
import { emptyFilterGroup } from './filtersUtils';

const useFiltersState = (initFilters: FilterGroup | null = emptyFilterGroup, defaultClearFilters: FilterGroup = emptyFilterGroup): [FilterGroup, handleFilterHelpers] => {
  const [filtersState, setFiltersState] = useState<FilterGroup>(initFilters ?? emptyFilterGroup);

  const latestAddFilterIdRef = useRef<string | undefined>(undefined);

  // Memoize helpers to prevent unnecessary re-renders when filter state changes
  const helpers: handleFilterHelpers = useMemo(() => ({
    getLatestAddFilterId: (): string | undefined => {
      return latestAddFilterIdRef.current;
    },
    handleAddFilterWithEmptyValue: (filter: Filter) => {
      latestAddFilterIdRef.current = filter.id;
      setFiltersState((prevState) => handleAddFilterWithEmptyValueUtil({ filters: prevState ?? emptyFilterGroup, filter }));
    },
    handleAddRepresentationFilter: (id: string, value: string | null) => {
      if (value === null) { // handle clicking on 'no label' in entities list
        setFiltersState((prevState) => {
          const findCorrespondingFilter = prevState?.filters.find((f) => id === f.id);
          if (findCorrespondingFilter && ['objectLabel'].includes(findCorrespondingFilter.key)) {
            latestAddFilterIdRef.current = id;
            return handleChangeOperatorFiltersUtil({
              filters: prevState,
              id,
              operator: findCorrespondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
            });
          }
          return prevState;
        });
      } else {
        latestAddFilterIdRef.current = undefined;
        setFiltersState((prevState) => handleAddRepresentationFilterUtil({ filters: prevState, id, value }));
      }
    },
    handleAddSingleValueFilter: (id: string, valueId?: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleAddSingleValueFilterUtil({ filters: prevState, id, valueId }));
    },
    handleReplaceFilterValues: (id: string, values: string[] | FilterGroup[]) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleReplaceFilterValuesUtil({ filters: prevState, id, values }));
    },
    handleChangeOperatorFilters: (id: string, operator: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleChangeOperatorFiltersUtil({ filters: prevState, id, operator }));
    },
    handleClearAllFilters: () => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState({ ...defaultClearFilters });
    },
    handleRemoveFilterById: (id: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleRemoveFilterUtil({ filters: prevState, id }));
    },
    handleRemoveRepresentationFilter: (id: string, value: string | Filter | undefined | null) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleRemoveRepresentationFilterUtil({ filters: prevState, id, value }));
    },
    handleSwitchGlobalMode: () => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => ({
        ...prevState,
        mode: prevState.mode === 'and' ? 'or' : 'and',
      }));
    },
    handleSwitchLocalMode: (filter: Filter) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleSwitchLocalModeUtil({ filters: prevState, filter }));
    },
    handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => {
      latestAddFilterIdRef.current = undefined;
      if (oldValue && newValue) {
        setFiltersState((prevState) => handleChangeRepresentationFilterUtil({ filters: prevState, id, oldValue, newValue }));
      } else if (oldValue) {
        setFiltersState((prevState) => handleRemoveRepresentationFilterUtil({ filters: prevState, id, value: oldValue }));
      } else if (newValue) {
        setFiltersState((prevState) => handleAddRepresentationFilterUtil({ filters: prevState, id, value: newValue }));
      }
    },
  }), [defaultClearFilters]);

  return [filtersState, helpers];
};

export default useFiltersState;
