import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { DataColumns } from './list_lines';
import { Filter, FilterGroup } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import Loader from './Loader';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import FilterIconButtonContainer from './FilterIconButtonContainer';

const useStyles = makeStyles(() => ({
  filters1: {
    float: 'left',
    margin: '5px 0 0 10px',
  },
  filters2: {
    marginTop: 20,
  },
  filters3: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  filters4: {
    margin: '0 0 20px 0',
  },
  filters5: {
    float: 'left',
    margin: '2px 0 0 10px',
  },
  filters6: {
    float: 'left',
    margin: '2px 0 0 15px',
  },
  filters7: {
    marginTop: 10,
  },
  filters8: {
    float: 'left',
    margin: '3px 0 0 5px',
  },
}));

interface FilterIconButtonProps {
  availableFilterKeys?: string[];
  filters: FilterGroup;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  classNameNumber?: number;
  styleNumber?: number;
  chipColor?: string;
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
}

const FilterIconButton: FunctionComponent<FilterIconButtonProps> = ({
  availableFilterKeys,
  filters,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  classNameNumber,
  styleNumber,
  dataColumns,
  disabledPossible,
  redirection,
  chipColor,
}) => {
  const classes = useStyles();

  let finalClassName = classes.filters1;
  if (classNameNumber === 2) {
    finalClassName = classes.filters2;
  } else if (classNameNumber === 3) {
    finalClassName = classes.filters3;
  } else if (classNameNumber === 4) {
    finalClassName = classes.filters4;
  } else if (classNameNumber === 5) {
    finalClassName = classes.filters5;
  } else if (classNameNumber === 6) {
    finalClassName = classes.filters6;
  } else if (classNameNumber === 7) {
    finalClassName = classes.filters7;
  } else if (classNameNumber === 8) {
    finalClassName = classes.filters8;
  }

  const displayedFilters = {
    ...filters,
    filters: filters.filters
      .filter((currentFilter) => !availableFilterKeys
        || availableFilterKeys?.some((k) => currentFilter.key === k)),
  };

  const filtersRepresentativesQueryRef = useQueryLoading<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    { filters: displayedFilters },
  );

  return (
    <div
      className={finalClassName}
      style={{ width: dataColumns?.filters.width }}
    >
    {filtersRepresentativesQueryRef && (
      <React.Suspense fallback={<Loader />}>
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
    </div>
  );
};

export default FilterIconButton;
