import { useState } from 'react';
import { v4 as uuid } from 'uuid';
import { emptyFilterGroup, Filter, FilterGroup, FilterValue } from './filtersUtils';
import {
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeOperatorFiltersUtil,
  handleClearAllFiltersUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleSwitchLocalModeUtil,
} from './filtersManageStateUtil';
import { handleFilterHelpers } from '../hooks/useLocalStorage';

interface useFiltersStateProps {
  filters: FilterGroup,
  latestAddFilterId?: string
}
const useFiltersState = (initFilters: FilterGroup = emptyFilterGroup): [FilterGroup, handleFilterHelpers] => {
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
        filters: handleAddFilterWithEmptyValueUtil({ filters: prevState.filters, filter }),
        latestAddFilterId: filter.id,
      }));
    },
    handleAddRepresentationFilter: (id: string, valueId: string) => {
      if (valueId === null) { // handle clicking on 'no label' in entities list
        const findCorrespondingFilter = filtersState.filters?.filters.find((f) => id === f.id);
        if (findCorrespondingFilter && ['objectLabel', 'contextObjectLabel'].includes(findCorrespondingFilter.key)) {
          const noLabelFilter: Filter = {
            id: uuid(),
            key: 'objectLabel',
            operator: findCorrespondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
            values: [],
            mode: 'and',
          };
          setFiltersState((prevState) => ({
            ...prevState,
            filters: handleAddFilterWithEmptyValueUtil({ filters: prevState.filters, filter: noLabelFilter }),
            latestAddFilterId: noLabelFilter.id,
          }));
        }
      } else {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: handleAddRepresentationFilterUtil({ filters: prevState.filters, id, valueId }),
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
        filters: initFilters,
        latestAddFilterId: undefined });
    },
    handleRemoveFilterById: (id: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleRemoveFilterUtil({ filters: prevState.filters, id }),
        latestAddFilterId: undefined,
      }));
    },
    handleRemoveRepresentationFilter: (id: string, valueId: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleRemoveRepresentationFilterUtil({ filters: prevState.filters, id, valueId }),
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
          filters: {
            ...prevState.filters,
            filters: prevState.filters.filters.map((f) => (f.id === id
              ? { ...f, values: f.values.filter((val) => val !== oldValue).concat([newValue]) }
              : f)),
          },
        }));
      } else if (oldValue) {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: {
            ...prevState.filters,
            filters: prevState.filters.filters.map((f) => (f.id === id
              ? {
                ...f,
                values: f.values.filter((v) => v !== oldValue),
              }
              : f)),
          },
        }));
      } else if (newValue) {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: {
            ...prevState.filters,
            filters: prevState.filters.filters.map((f) => (f.id === id ? { ...f, values: [...f.values, newValue] } : f)),
          },
        }));
      }
    },
  };

  return [filtersState.filters, helpers];
};

export default useFiltersState;
