import { useState } from 'react';
import { emptyFilterGroup } from './filtersUtils';
import {
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeOperatorFiltersUtil,
  handleChangeRepresentationFilterUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleSwitchLocalModeUtil,
} from './filtersManageStateUtil';
import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from './filtersHelpers-types';

interface useFiltersStateProps {
  filters: FilterGroup,
  latestAddFilterId?: string
}
const useFiltersState = (initFilters: FilterGroup = emptyFilterGroup, defaultClearFilters: FilterGroup = emptyFilterGroup): [FilterGroup, handleFilterHelpers] => {
  const [filtersState, setFiltersState] = useState<useFiltersStateProps>({
    filters: initFilters,
    latestAddFilterId: undefined,
  });
  const helpers: handleFilterHelpers = {
    getLatestAddFilterId: (): string | undefined => {
      return filtersState.latestAddFilterId;
    },
    handleAddFilterWithEmptyValue: (filter: Filter) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleAddFilterWithEmptyValueUtil({ filters: prevState.filters ?? emptyFilterGroup, filter }),
        latestAddFilterId: filter.id,
      }));
    },
    handleAddRepresentationFilter: (id: string, value: string) => {
      if (value === null) { // handle clicking on 'no label' in entities list
        const findCorrespondingFilter = filtersState.filters?.filters.find((f) => id === f.id);
        if (findCorrespondingFilter && ['objectLabel'].includes(findCorrespondingFilter.key)) {
          setFiltersState((prevState) => ({
            ...prevState,
            filters: handleChangeOperatorFiltersUtil({
              filters: prevState.filters,
              id,
              operator: findCorrespondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
            }),
            latestAddFilterId: id,
          }));
        }
      } else {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: handleAddRepresentationFilterUtil({ filters: prevState.filters, id, value }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleAddSingleValueFilter: (id: string, valueId?: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleAddSingleValueFilterUtil({ filters: prevState.filters, id, valueId }),
        latestAddFilterId: undefined,
      }));
    },
    handleChangeOperatorFilters: (id: string, operator: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleChangeOperatorFiltersUtil({ filters: prevState.filters, id, operator }),
        latestAddFilterId: undefined,
      }));
    },
    handleClearAllFilters: () => {
      setFiltersState({
        filters: { ...defaultClearFilters },
        latestAddFilterId: undefined });
    },
    handleRemoveFilterById: (id: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleRemoveFilterUtil({ filters: prevState.filters, id }),
        latestAddFilterId: undefined,
      }));
    },
    handleRemoveRepresentationFilter: (id: string, value: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleRemoveRepresentationFilterUtil({ filters: prevState.filters, id, value }),
        latestAddFilterId: undefined,
      }));
    },
    handleSwitchGlobalMode: () => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: {
          ...filtersState.filters,
          mode: filtersState.filters.mode === 'and' ? 'or' : 'and',
        },
        latestAddFilterId: undefined,
      }));
    },
    handleSwitchLocalMode: (filter: Filter) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleSwitchLocalModeUtil({ filters: prevState.filters, filter }),
        latestAddFilterId: undefined,
      }));
    },
    handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => {
      if (oldValue && newValue) {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: handleChangeRepresentationFilterUtil({ filters: prevState.filters, id, oldValue, newValue }),
          latestAddFilterId: undefined,
        }));
      } else if (oldValue) {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: handleRemoveRepresentationFilterUtil({ filters: prevState.filters, id, value: oldValue }),
          latestAddFilterId: undefined,
        }));
      } else if (newValue) {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: handleAddRepresentationFilterUtil({ filters: prevState.filters, id, value: newValue }),
          latestAddFilterId: undefined,
        }));
      }
    },
  };

  return [filtersState.filters, helpers];
};

export default useFiltersState;
