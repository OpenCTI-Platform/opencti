import React, { FunctionComponent } from 'react';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { DataColumns } from './list_lines';
import {
  Filter,
  FilterGroup,
  GqlFilterGroup,
  initialFilterGroup,
} from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import Loader from './Loader';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import FilterIconButtonContainer from './FilterIconButtonContainer';

interface FilterIconButtonProps {
  availableFilterKeys?: string[];
  filters?: FilterGroup;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  classNameNumber?: number;
  styleNumber?: number;
  chipColor?: ChipOwnProps['color'];
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
}

const FilterIconButton: FunctionComponent<FilterIconButtonProps> = ({
  availableFilterKeys,
  filters = initialFilterGroup,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  styleNumber,
  disabledPossible,
  redirection,
  chipColor,
}) => {
  const displayedFilters = {
    ...filters,
    filters:
      filters.filters.filter(
        (f) => !availableFilterKeys || availableFilterKeys?.some((k) => f.key === k),
      ) || [],
  };
  const parsedQueryFilters: FilterGroup = {
    ...filters,
    filters: filters.filters
      .filter((currentFilter) => !availableFilterKeys
        || availableFilterKeys?.some((k) => currentFilter.key === k))
      .map((filter) => {
        const removeIdFromFilter = { ...filter };
        delete removeIdFromFilter.id;
        return removeIdFromFilter;
      }),
  };
  const filtersRepresentativesQueryRef = useQueryLoading<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    { filters: parsedQueryFilters as unknown as GqlFilterGroup },
  );
  return (
    <>
      {filtersRepresentativesQueryRef && (
        <React.Suspense fallback={<Loader/>}>
          <FilterIconButtonContainer
            handleRemoveFilter={handleRemoveFilter}
            handleSwitchGlobalMode={handleSwitchGlobalMode}
            handleSwitchLocalMode={handleSwitchLocalMode}
            styleNumber={styleNumber}
            chipColor={chipColor}
            disabledPossible={disabledPossible}
            redirection={redirection}
            filters={displayedFilters}
            filtersRepresentativesQueryRef={filtersRepresentativesQueryRef}
          ></FilterIconButtonContainer>
        </React.Suspense>)
      }
    </>
  );
};

export default FilterIconButton;
