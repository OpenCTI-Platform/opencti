import React, { FunctionComponent, useRef } from 'react';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { DataColumns } from './list_lines';
import { Filter, FilterGroup, GqlFilterGroup, isFilterGroupNotEmpty, removeIdFromFilterGroupObject } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import FilterIconButtonContainer from './FilterIconButtonContainer';
import { UseLocalStorageHelpers } from '../utils/hooks/useLocalStorage';

interface FilterIconButtonProps {
  availableFilterKeys?: string[];
  filters?: FilterGroup;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  styleNumber?: number;
  chipColor?: ChipOwnProps['color'];
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
  helpers?: UseLocalStorageHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
  hasRenderedRef: boolean;
  setHasRenderedRef: () => void;
}

interface FilterIconButtonIfFiltersProps extends FilterIconButtonProps {
  filters: FilterGroup,
}
const FilterIconButtonWithRepresentativesQuery: FunctionComponent<FilterIconButtonIfFiltersProps> = ({
  filters,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  styleNumber,
  disabledPossible,
  redirection,
  chipColor,
  helpers,
  availableRelationFilterTypes,
  hasRenderedRef,
  setHasRenderedRef,
}) => {
  const filtersRepresentativesQueryRef = useQueryLoading<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    {
      filters: removeIdFromFilterGroupObject(filters) as unknown as GqlFilterGroup,
    },
  );
  return (
    <>
      {filtersRepresentativesQueryRef && (
        <React.Suspense fallback={<span />}>
          <FilterIconButtonContainer
            handleRemoveFilter={handleRemoveFilter}
            handleSwitchGlobalMode={handleSwitchGlobalMode}
            handleSwitchLocalMode={handleSwitchLocalMode}
            styleNumber={styleNumber}
            chipColor={chipColor}
            disabledPossible={disabledPossible}
            redirection={redirection}
            filters={filters}
            filtersRepresentativesQueryRef={filtersRepresentativesQueryRef}
            helpers={helpers}
            hasRenderedRef={hasRenderedRef}
            setHasRenderedRef={setHasRenderedRef}
            availableRelationFilterTypes={availableRelationFilterTypes}
          />
        </React.Suspense>
      )}
    </>
  );
};

const FilterIconButton: FunctionComponent<FilterIconButtonProps> = ({
  availableFilterKeys,
  filters,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  styleNumber,
  disabledPossible,
  redirection,
  chipColor,
  helpers,
  availableRelationFilterTypes,
}) => {
  const hasRenderedRef = useRef(false);
  const setHasRenderedRef = () => {
    hasRenderedRef.current = true;
  };
  const displayedFilters = filters ? {
    ...filters,
    filters:
      filters.filters.filter((f) => !availableFilterKeys || availableFilterKeys?.some((k) => f.key === k)),
  } : undefined;
  if (displayedFilters && isFilterGroupNotEmpty(displayedFilters)) { // to avoid running the FiltersRepresentatives query if filters are empty
    return (
      <FilterIconButtonWithRepresentativesQuery
        filters={displayedFilters}
        handleRemoveFilter={handleRemoveFilter}
        handleSwitchGlobalMode={handleSwitchGlobalMode}
        handleSwitchLocalMode={handleSwitchLocalMode}
        styleNumber={styleNumber}
        disabledPossible={disabledPossible}
        redirection={redirection}
        chipColor={chipColor}
        helpers={helpers}
        availableRelationFilterTypes={availableRelationFilterTypes}
        hasRenderedRef={hasRenderedRef.current}
        setHasRenderedRef={setHasRenderedRef}
      />
    );
  }
  return (<></>);
};

export default FilterIconButton;
