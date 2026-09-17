import { ChipOwnProps } from '@mui/material/Chip/Chip';
import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { FilterSearchContext, FiltersRestrictions, isFilterGroupNotEmpty, mapFilterGroupTree, normalizeFilterGroupForBackend } from '../utils/filters/filtersUtils';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import { DataColumns } from './list_lines';

import { Filter, FilterGroup, handleFilterHelpers } from '../utils/filters/filtersHelpers-types';
import type { WidgetHost } from '../utils/widget/widget';
import FilterIconButtonContainer, { FilterIconButtonVariant } from './FilterIconButtonContainer';
import { filterValuesContentQuery } from './FilterValuesContent';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { FilterChipsParameter } from './filters/FilterChipPopover';

export interface FilterIconButtonProps {
  availableFilterKeys?: string[];
  filters?: FilterGroup | null;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  variant?: FilterIconButtonVariant;
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
  host?: WidgetHost;
  hasSavedFilters?: boolean;
  inline?: boolean;
}

interface FilterIconButtonIfFiltersProps extends FilterIconButtonProps {
  filters: FilterGroup;
  hasRenderedRef: boolean;
  setHasRenderedRef: (value: boolean) => void;
  filterChipsParams: FilterChipsParameter;
  setFilterChipsParams: React.Dispatch<React.SetStateAction<FilterChipsParameter>>;
}
const FilterIconButtonWithRepresentativesQuery: FunctionComponent<FilterIconButtonIfFiltersProps> = ({
  filters,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  variant,
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
  host,
  hasSavedFilters,
  filterChipsParams,
  setFilterChipsParams,
  availableFilterKeys,
  inline,
}) => {
  const filtersRepresentativesQueryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
    {
      filters: normalizeFilterGroupForBackend(filters),
      isMeValueForbidden: searchContext?.elementType === 'Playbook-Stix-Component',
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
            variant={variant}
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
            host={host}
            hasSavedFilters={hasSavedFilters}
            filterChipsParams={filterChipsParams}
            setFilterChipsParams={setFilterChipsParams}
            availableFilterKeys={availableFilterKeys}
            inline={inline}
          />
        </React.Suspense>
      )}
    </>
  );
};

interface EmptyFilterProps {
  setHasRenderedRef: (value: boolean) => void;
}

const EmptyFilter: FunctionComponent<EmptyFilterProps> = ({ setHasRenderedRef }) => {
  useEffect(() => {
    setHasRenderedRef(true);
  }, []);
  return null;
};

const FilterIconButton: FunctionComponent<FilterIconButtonProps> = ({
  availableFilterKeys,
  filters,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  variant,
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
  host,
  hasSavedFilters,
  inline,
}) => {
  const hasRenderedRef = useRef(false);
  const setHasRenderedRef = (value: boolean) => {
    hasRenderedRef.current = value;
  };

  const [filterChipsParams, setFilterChipsParams] = useState<FilterChipsParameter>({
    filterId: undefined,
    anchorEl: undefined,
    anchorPosition: undefined,
  });

  const filterGroupOnAvailableKeys = (filterGroup: FilterGroup, keys?: string[]): FilterGroup => mapFilterGroupTree(filterGroup, (group) => ({
    ...group,
    filters: group.filters.filter((currentFilter) => !keys || keys.some((currentKey) => currentFilter.key === currentKey)),
  }));

  const displayedFilters = filters ? filterGroupOnAvailableKeys(filters, availableFilterKeys) : undefined;
  if (displayedFilters && isFilterGroupNotEmpty(displayedFilters)) { // to avoid running the FiltersRepresentatives query if filters are empty
    return (
      <FilterIconButtonWithRepresentativesQuery
        filters={displayedFilters}
        handleRemoveFilter={handleRemoveFilter}
        handleSwitchGlobalMode={handleSwitchGlobalMode}
        handleSwitchLocalMode={handleSwitchLocalMode}
        variant={variant}
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
        host={host}
        hasSavedFilters={hasSavedFilters}
        filterChipsParams={filterChipsParams}
        setFilterChipsParams={setFilterChipsParams}
        availableFilterKeys={availableFilterKeys}
        inline={inline}
      />
    );
  }
  return (<EmptyFilter setHasRenderedRef={setHasRenderedRef} />);
};

export default FilterIconButton;
