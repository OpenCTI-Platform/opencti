import React, { FunctionComponent, useDeferredValue, useEffect, useRef, useState } from 'react';
import { isFilterGroupNotEmptyShallow, mapFilterGroupTree, normalizeFilterGroupForBackend } from '../utils/filters/filtersUtils';
import useQueryLoading from '../utils/hooks/useQueryLoading';

import { FilterGroup } from '../utils/filters/filtersHelpers-types';
import FilterIconButtonContainer, { FilterIconButtonSharedProps } from './FilterIconButtonContainer';
import { filterValuesContentQuery } from './FilterValuesContent';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { FilterChipsParameter } from './filters/FilterChipPopover';

export interface FilterIconButtonProps extends FilterIconButtonSharedProps {
  filters?: FilterGroup | null;
}

interface FilterIconButtonIfFiltersProps extends FilterIconButtonProps {
  filters: FilterGroup;
  hasRendered: boolean;
  setHasRendered: (value: boolean) => void;
  filterChipsParams: FilterChipsParameter;
  setFilterChipsParams: React.Dispatch<React.SetStateAction<FilterChipsParameter>>;
}

/**
 * Only reason this is a separate component from `FilterIconButton`: `useQueryLoading` must not
 * fire while `filters` is empty, and a hook can't be called conditionally in the same body as
 * that early return. Every other prop here is pure passthrough, hence the `...shared` spread.
 */
const FilterIconButtonWithRepresentativesQuery: FunctionComponent<FilterIconButtonIfFiltersProps> = ({
  filters,
  hasRendered,
  setHasRendered,
  filterChipsParams,
  setFilterChipsParams,
  ...shared
}) => {
  const latestQueryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
    {
      filters: normalizeFilterGroupForBackend(filters),
      isMeValueForbidden: shared.searchContext?.elementType === 'Playbook-Stix-Component',
    },
  );

  const filtersRepresentativesQueryRef = useDeferredValue(latestQueryRef);

  return (
    <>
      {filtersRepresentativesQueryRef && (
        <React.Suspense fallback={<span />}>
          <FilterIconButtonContainer
            {...shared}
            filters={filters}
            filtersRepresentativesQueryRef={filtersRepresentativesQueryRef}
            hasRendered={hasRendered}
            setHasRendered={setHasRendered}
            filterChipsParams={filterChipsParams}
            setFilterChipsParams={setFilterChipsParams}
          />
        </React.Suspense>
      )}
    </>
  );
};

interface EmptyFilterProps {
  setHasRendered: (value: boolean) => void;
}

const EmptyFilter: FunctionComponent<EmptyFilterProps> = ({ setHasRendered }) => {
  useEffect(() => {
    setHasRendered(true);
  }, []);
  return null;
};

const FilterIconButton: FunctionComponent<FilterIconButtonProps> = ({
  availableFilterKeys,
  filters,
  ...shared
}) => {
  const hasRenderedRef = useRef(false);
  const setHasRendered = (value: boolean) => {
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
  if (displayedFilters && isFilterGroupNotEmptyShallow(displayedFilters)) { // to avoid running the FiltersRepresentatives query if filters are empty
    return (
      <FilterIconButtonWithRepresentativesQuery
        {...shared}
        availableFilterKeys={availableFilterKeys}
        filters={displayedFilters}
        hasRendered={hasRenderedRef.current}
        setHasRendered={setHasRendered}
        filterChipsParams={filterChipsParams}
        setFilterChipsParams={setFilterChipsParams}
      />
    );
  }
  return (<EmptyFilter setHasRendered={setHasRendered} />);
};

export default FilterIconButton;
