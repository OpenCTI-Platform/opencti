import React, { FunctionComponent, useEffect, useRef } from 'react';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { DataColumns } from './list_lines';
import { GqlFilterGroup, isFilterGroupNotEmpty, removeIdFromFilterGroupObject, FiltersRestrictions, FilterSearchContext } from '../utils/filters/filtersUtils';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import FilterIconButtonContainer from './FilterIconButtonContainer';
import { filterValuesContentQuery } from './FilterValuesContent';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { Filter, FilterGroup, handleFilterHelpers } from '../utils/filters/filtersHelpers-types';

export interface FilterIconButtonProps {
  availableFilterKeys?: string[];
  filters?: FilterGroup | null;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  styleNumber?: number;
  chipColor?: ChipOwnProps['color'];
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
  helpers?: handleFilterHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
  entityTypes?: string[];
  filtersRestrictions?: FiltersRestrictions;
  searchContext?: FilterSearchContext;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
}

interface FilterIconButtonIfFiltersProps extends FilterIconButtonProps {
  filters: FilterGroup,
  hasRenderedRef: boolean;
  setHasRenderedRef: () => void;
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
  entityTypes,
  filtersRestrictions,
  searchContext,
  availableEntityTypes,
  availableRelationshipTypes,
}) => {
  const filtersRepresentativesQueryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
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
            entityTypes={entityTypes}
            filtersRestrictions={filtersRestrictions}
            searchContext={searchContext}
            availableEntityTypes={availableEntityTypes}
            availableRelationshipTypes={availableRelationshipTypes}
          />
        </React.Suspense>
      )}
    </>
  );
};

const EmptyFilter: FunctionComponent<{ setHasRenderedRef: () => void }> = ({ setHasRenderedRef }) => {
  useEffect(() => {
    setHasRenderedRef();
  }, []);
  return null;
};

// availableEntityTypes
// availableRelationshipTypes

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
  entityTypes,
  filtersRestrictions,
  searchContext,
  availableEntityTypes,
  availableRelationshipTypes,
}) => {
  const hasRenderedRef = useRef(false);
  const setHasRenderedRef = () => {
    hasRenderedRef.current = true;
  };
  const displayedFilters = filters
    ? {
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
        entityTypes={entityTypes}
        filtersRestrictions={filtersRestrictions}
        searchContext={searchContext}
        availableEntityTypes={availableEntityTypes}
        availableRelationshipTypes={availableRelationshipTypes}
      />
    );
  }
  return (<EmptyFilter setHasRenderedRef={setHasRenderedRef}/>);
};

export default FilterIconButton;
