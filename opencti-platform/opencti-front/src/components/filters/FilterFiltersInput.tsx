import React, { FunctionComponent, useEffect, useRef } from 'react';
import Filters from '@components/common/lists/Filters';
import Box from '@mui/material/Box';
import { Filter, FilterGroup, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup, isFilterGroupNotEmpty, sanitizeFiltersStructure, useAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';
import useFiltersState from '../../utils/filters/useFiltersState';

import FilterIconButton from '../FilterIconButton';

interface BasicFilterInputProps {
  filter?: Filter;
  filterKey: string;
  childKey?: string;
  helpers?: handleFilterHelpers;
  filterValues: FilterGroup;
  disabled?: boolean;
}

const FilterFiltersInput: FunctionComponent<BasicFilterInputProps> = ({
  filter,
  childKey,
  helpers,
  filterValues,
  disabled = false,
}) => {
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object']);
  const [filters, filterHelpers] = useFiltersState(filterValues ?? emptyFilterGroup);
  const handleFiltersChange = (currentFilter: FilterGroup | undefined) => {
    if (currentFilter) {
      if (childKey) {
        const childFilters = filter?.values.filter((val) => val.key === childKey) as Filter[];
        const childFilter = childFilters && childFilters.length > 0 ? childFilters[0] : undefined;
        const sanitizedCurrentFilter = sanitizeFiltersStructure(currentFilter);
        if (isFilterGroupNotEmpty(sanitizedCurrentFilter)) {
          const representation = { key: childKey, values: [sanitizedCurrentFilter] };
          helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, representation);
        } else {
          helpers?.handleRemoveRepresentationFilter(filter?.id ?? '', childFilter);
        }
      } else {
        const sanitizedCurrentFilter = sanitizeFiltersStructure(currentFilter);
        helpers?.handleReplaceFilterValues(filter?.id ?? '', [sanitizedCurrentFilter]);
      }
    }
  };
  const isFirstRender = useRef(true);
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }
    handleFiltersChange(filters);
  }, [filters]);
  return (
    <>
      <Box sx={{
        paddingTop: 1,
        display: 'flex',
        gap: 1,
      }}
      >
        <Filters
          availableFilterKeys={availableFilterKeys}
          helpers={filterHelpers}
          searchContext={{ entityTypes: ['Stix-Core-Object'] }}
          disabled={disabled}
        />
      </Box>
      <FilterIconButton
        filters={filters}
        helpers={filterHelpers}
        styleNumber={2}
        redirection
        searchContext={{ entityTypes: ['Stix-Core-Object'] }}
      />
    </>
  );
};

export default FilterFiltersInput;
