import { useState } from 'react';
import { v4 as uuid } from 'uuid';
import { emptyFilterGroup, Filter, FilterGroup } from './filtersUtils';
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
        filters: handleAddFilterWithEmptyValueUtil({ filters: filtersState.filters, filter }),
        latestAddFilterId: undefined,
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
            filters: handleAddFilterWithEmptyValueUtil({ filters: filtersState.filters, filter: noLabelFilter }),
            latestAddFilterId: noLabelFilter.id,
          }));
        }
      } else {
        setFiltersState((prevState) => ({
          ...prevState,
          filters: handleAddRepresentationFilterUtil({ filters: filtersState.filters, id, valueId }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleAddSingleValueFilter: (id: string, valueId?: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleAddSingleValueFilterUtil({ filters: filtersState.filters, id, valueId }),
        latestAddFilterId: undefined,
      }));
    },
    handleChangeOperatorFilters: (id: string, operator: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleChangeOperatorFiltersUtil({ filters: filtersState.filters, id, operator }),
        latestAddFilterId: undefined,
      }));
    },
    handleClearAllFilters: (clearFilters?: Filter[]) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleClearAllFiltersUtil(clearFilters),
        latestAddFilterId: undefined,
      }));
    },
    handleRemoveFilterById: (id: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleRemoveFilterUtil({ filters: filtersState.filters, id }),
        latestAddFilterId: undefined,
      }));
    },
    handleRemoveRepresentationFilter: (id: string, valueId: string) => {
      setFiltersState((prevState) => ({
        ...prevState,
        filters: handleRemoveRepresentationFilterUtil({ filters: filtersState.filters, id, valueId }),
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
        filters: handleSwitchLocalModeUtil({ filters: filtersState.filters, filter }),
        latestAddFilterId: undefined,
      }));
    },
  };

  return [filtersState.filters, helpers];
};

export default useFiltersState;
