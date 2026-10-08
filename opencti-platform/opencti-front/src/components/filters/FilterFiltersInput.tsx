import React, { FunctionComponent, useEffect, useRef } from 'react';
import Filters from '@components/common/lists/Filters';
import Box from '@mui/material/Box';
import { Filter, FilterGroup, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup, isFilterGroupNotEmptyShallow, sanitizeFiltersStructure, useAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';
import useFiltersState from '../../utils/filters/useFiltersState';
import FilterIconButton from '../FilterIconButton';
import { useTheme } from '@mui/material/styles';
import { WidgetHost } from '../../utils/widget/widget';

const STIX_CORE_OBJECT_TYPES = ['Stix-Core-Object'];
// dynamicRegardingOf can also target external references (via the 'external-reference' relationship type)
const DYNAMIC_REGARDING_OF_TYPES = ['Stix-Core-Object', 'External-Reference'];

interface BasicFilterInputProps {
  filter?: Filter;
  filterKey: string;
  childKey?: string;
  helpers?: handleFilterHelpers;
  filterValues: FilterGroup;
  host?: WidgetHost;
  disabled?: boolean;
}

const FilterFiltersInput: FunctionComponent<BasicFilterInputProps> = ({
  filter,
  filterKey,
  childKey,
  helpers,
  filterValues,
  host,
  disabled = false,
}) => {
  const theme = useTheme();
  const entityTypes = filterKey === 'dynamicRegardingOf' ? DYNAMIC_REGARDING_OF_TYPES : STIX_CORE_OBJECT_TYPES;
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(entityTypes);
  const [filters, filterHelpers] = useFiltersState(filterValues ?? emptyFilterGroup);
  const handleFiltersChange = (currentFilter: FilterGroup | undefined) => {
    if (currentFilter) {
      if (childKey) {
        const childFilters = filter?.values.filter((val) => val.key === childKey) as Filter[];
        const childFilter = childFilters && childFilters.length > 0 ? childFilters[0] : undefined;
        const sanitizedCurrentFilter = sanitizeFiltersStructure(currentFilter);
        // live-editing gate: keep shallow "is there structure" semantics, not "is this complete" —
        // a strict check would delete a filter/group the user just added but hasn't filled in yet.
        if (isFilterGroupNotEmptyShallow(sanitizedCurrentFilter)) {
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
        alignItems: 'center',
        gap: theme.spacing(1),
        marginBottom: theme.spacing(1),
      }}
      >
        <Filters
          availableFilterKeys={availableFilterKeys}
          helpers={filterHelpers}
          searchContext={{ entityTypes }}
          disabled={disabled}
          disableAddFilterGroup
        />
      </Box>
      <FilterIconButton
        filters={filters}
        helpers={filterHelpers}
        availableFilterKeys={availableFilterKeys}
        redirection
        entityTypes={entityTypes}
        searchContext={{ entityTypes }}
        host={host}
      />
    </>
  );
};

export default FilterFiltersInput;
