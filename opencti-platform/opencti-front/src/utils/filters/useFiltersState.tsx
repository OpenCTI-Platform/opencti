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

const useFiltersState = (initFilters = emptyFilterGroup) => {
  const [filters, setFilters] = useState<FilterGroup>(initFilters);
  const [latestAddFilterId, setLatestAddFilterId] = useState<string | undefined>(undefined);
  const helpers = {
    handleAddFilterWithEmptyValue: (filter: Filter) => {
      setFilters(handleAddFilterWithEmptyValueUtil({ filters, filter }));
      setLatestAddFilterId(filter.id);
    },
    handleAddRepresentationFilter: (id: string, valueId: string) => {
      if (valueId === null) { // handle clicking on 'no label' in entities list
        const findCorrespondingFilter = filters?.filters.find((f) => id === f.id);
        if (findCorrespondingFilter && ['objectLabel', 'contextObjectLabel'].includes(findCorrespondingFilter.key)) {
          if (filters) {
            const noLabelFilter: Filter = {
              id: uuid(),
              key: 'objectLabel',
              operator: findCorrespondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
              values: [],
              mode: 'and',
            };
            setFilters(handleAddFilterWithEmptyValueUtil({ filters, filter: noLabelFilter }));
            setLatestAddFilterId(noLabelFilter.id);
          }
        }
      } else if (filters) {
        setFilters(handleAddRepresentationFilterUtil({ filters, id, valueId }));
        setLatestAddFilterId(undefined);
      }
    },
    handleAddSingleValueFilter: (id: string, valueId?: string) => {
      setFilters(handleAddSingleValueFilterUtil({ filters, id, valueId }));
      setLatestAddFilterId(undefined);
    },
    handleChangeOperatorFilters: (id: string, operator: string) => {
      setFilters(handleChangeOperatorFiltersUtil({ filters, id, operator }));
      setLatestAddFilterId(undefined);
    },
    handleRemoveFilterById: (id: string) => {
      setFilters(handleRemoveFilterUtil({ filters, id }));
      setLatestAddFilterId(undefined);
    },
    handleRemoveRepresentationFilter: (id: string, valueId: string) => {
      setFilters(handleRemoveRepresentationFilterUtil({ filters, id, valueId }));
      setLatestAddFilterId(undefined);
    },
    handleSwitchLocalMode: (filter: Filter) => {
      setFilters(handleSwitchLocalModeUtil({ filters, filter }));
      setLatestAddFilterId(undefined);
    },
    handleClearAllFilters: (clearFilters: Filter[]) => {
      setFilters(handleClearAllFiltersUtil(clearFilters));
      setLatestAddFilterId(undefined);
    },
    handleSwitchGlobalMode: () => {
      setFilters({
        ...filters,
        mode: filters.mode === 'and' ? 'or' : 'and',
      });
      setLatestAddFilterId(undefined);
    },
    getLatestAddFilterId: (): string | undefined => {
      return latestAddFilterId;
    },
  };

  return [filters, helpers];
};

export default useFiltersState;
