import { useMemo, useRef, useState } from 'react';
import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from './filtersHelpers-types';
import {
  addFilterGroupUtil,
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeOperatorFiltersUtil,
  handleChangeRepresentationFilterUtil,
  removeFilterGroupUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleReplaceFilterValuesUtil,
  handleSwitchGlobalModeUtil,
  handleSwitchLocalModeUtil,
} from './filtersManageStateUtil';
import { cloneFilterGroup, emptyFilterGroup, ensureFilterGroupIds, extractAllFilters } from './filtersUtils';

const useFiltersState = (initFilters: FilterGroup | null = emptyFilterGroup, defaultClearFilters: FilterGroup = emptyFilterGroup): [FilterGroup, handleFilterHelpers] => {
  const [filtersState, setFiltersState] = useState<FilterGroup>(() => ensureFilterGroupIds(cloneFilterGroup(initFilters ?? emptyFilterGroup)));

  const latestAddFilterIdRef = useRef<string | undefined>(undefined);

  // Memoize helpers to prevent unnecessary re-renders when filter state changes
  const helpers: handleFilterHelpers = useMemo(() => ({
    getLatestAddFilterId: (): string | undefined => {
      return latestAddFilterIdRef.current;
    },
    handleAddFilterWithEmptyValue: (filter: Filter, groupId?: string) => {
      // when the filter is added in a non-root group, there is no chip in the root chip line to
      // anchor the popover on: reset the anchor.
      latestAddFilterIdRef.current = groupId ? undefined : filter.id;
      setFiltersState((prevState) => handleAddFilterWithEmptyValueUtil({ filters: prevState ?? emptyFilterGroup, filter, groupId }));
    },
    handleAddFilterGroup: (parentGroupId?: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => addFilterGroupUtil({ filters: prevState ?? emptyFilterGroup, parentGroupId }));
    },
    handleRemoveFilterGroup: (groupId: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => removeFilterGroupUtil({ filters: prevState ?? emptyFilterGroup, groupId }));
    },
    handleAddRepresentationFilter: (id: string, value: string | null) => {
      if (value === null) { // handle clicking on 'no label' in entities list
        setFiltersState((prevState) => {
          const findCorrespondingFilter = extractAllFilters(prevState ?? emptyFilterGroup).find((f) => id === f.id);
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
      setFiltersState(ensureFilterGroupIds(cloneFilterGroup(defaultClearFilters)));
    },
    handleRemoveFilterById: (id: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleRemoveFilterUtil({ filters: prevState, id }));
    },
    handleRemoveRepresentationFilter: (id: string, value: string | Filter | undefined | null) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleRemoveRepresentationFilterUtil({ filters: prevState, id, value }));
    },
    handleSwitchGlobalMode: (groupId?: string) => {
      latestAddFilterIdRef.current = undefined;
      setFiltersState((prevState) => handleSwitchGlobalModeUtil({ filters: prevState, groupId }));
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
