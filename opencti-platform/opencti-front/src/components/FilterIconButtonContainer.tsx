import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { Fragment, FunctionComponent, useEffect, useRef } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import Box from '@mui/material/Box';
import { truncate } from '../utils/String';
import { DataColumns } from './list_lines';
import { useFormatter } from './i18n';
import { Theme } from './Theme';
import { Filter, FilterGroup } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import FilterValues from './filters/FilterValues';
import {
  FilterChipPopover,
  FilterChipsParameter,
} from './filters/FilterChipPopover';
import DisplayFilterGroup from './filters/DisplayFilterGroup';
import { UseLocalStorageHelpers } from '../utils/hooks/useLocalStorage';

const useStyles = makeStyles<Theme>((theme) => ({
  filter3: {
    fontSize: 12,
    height: 20,
    marginRight: 7,
    borderRadius: 10,
    lineHeight: '32px',
  },
  operator1: {
    borderRadius: 5,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.action?.disabled,
      textDecorationLine: 'underline',
    },
  },
  operator2: {
    borderRadius: 5,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.action?.disabled,
      textDecorationLine: 'underline',
    },
  },
  operator3: {
    borderRadius: 5,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    height: 20,
    padding: '0 8px',
    marginRight: 10,
    marginLeft: 10,
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.action?.disabled,
      textDecorationLine: 'underline',
    },
  },
  chipLabel: {
    lineHeight: '32px',
    maxWidth: 400,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    alignItems: 'center',
    gap: 4,
  },
}));

interface FilterIconButtonContainerProps {
  filters: FilterGroup;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  classNameNumber?: number;
  styleNumber?: number;
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
  filtersRepresentativesQueryRef: PreloadedQuery<FilterIconButtonContentQuery>;
  chipColor?: ChipOwnProps['color'];
  helpers?: UseLocalStorageHelpers;
  hasRenderedRef: boolean;
  setHasRenderedRef: () => void;
}

const FilterIconButtonContainer: FunctionComponent<
FilterIconButtonContainerProps
> = ({
  filters,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  styleNumber,
  disabledPossible,
  redirection,
  filtersRepresentativesQueryRef,
  chipColor,
  handleRemoveFilter,
  helpers,
  hasRenderedRef,
  setHasRenderedRef,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { filtersRepresentatives } = usePreloadedQuery<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    filtersRepresentativesQueryRef,
  );
  const displayedFilters = filters.filters;
  const globalMode = filters.mode;
  let classFilter = classes.filter1;
  let classOperator = classes.operator1;
  if (styleNumber === 2) {
    classFilter = classes.filter2;
    classOperator = classes.operator2;
  } else if (styleNumber === 3) {
    classFilter = classes.filter3;
    classOperator = classes.operator3;
  }
  const latestItemRef = useRef(null);
  const nbDisplayFilter = useRef(0);

  const filtersRepresentativesMap = new Map(
    filtersRepresentatives.map((n) => [n.id, n.value]),
  );
  const [filterChipsParams, setFilterChipsParams] = React.useState<FilterChipsParameter>({
    filter: undefined,
    anchorEl: undefined,
  } as FilterChipsParameter);
  const open = Boolean(filterChipsParams.anchorEl);
  if (helpers) {
    // activate popover feature on chip only when "helper" is defined, not the best way to handle but
    // it means that the new filter feature is activated. Will be removed in the next version when we generalize the feature on every filter.
    useEffect(() => {
      if (
        hasRenderedRef
        && latestItemRef.current
        && nbDisplayFilter.current < displayedFilters.length
      ) {
        setFilterChipsParams({
          filterId: displayedFilters[displayedFilters.length - 1].id,
          anchorEl: latestItemRef.current as unknown as HTMLElement,
        });
      } else {
        setHasRenderedRef();
      }
      nbDisplayFilter.current = displayedFilters.length;
    }, [displayedFilters]);
  }
  const handleClose = () => {
    setFilterChipsParams({
      filterId: undefined,
      anchorEl: undefined,
    });
  };

  const handleChipClick = (
    event: React.MouseEvent<HTMLButtonElement>,
    filterId?: string,
  ) => {
    if (helpers) {
      setFilterChipsParams({
        filterId,
        anchorEl: event.currentTarget,
      });
    }
  };

  const manageRemoveFilter = (
    currentFilterId: string | undefined,
    filterKey: string,
    filterOperator: string,
  ) => {
    if (helpers) {
      helpers?.handleRemoveFilterById(currentFilterId);
    } else if (handleRemoveFilter) {
      handleRemoveFilter(filterKey, filterOperator ?? undefined);
    }
  };

  const convertOperatorToIcon = (operator: string) => {
    switch (operator) {
      case 'lt':
        return <>&nbsp;&#60;</>;
      case 'lte':
        return <>&nbsp;&#8804;</>;
      case 'gt':
        return <>&nbsp;&#62;</>;
      case 'gte':
        return <>&nbsp;&#8805;</>;
      default:
        return null;
    }
  };
  const isReadonlyFilter = helpers || handleRemoveFilter;
  return (
    <Box
      sx={
        !isReadonlyFilter
          ? {
            display: 'flex',
            overflow: 'hidden',
          }
          : {
            marginTop: displayedFilters.length === 0 ? 0 : '10px',
            gap: '10px',
            display: 'flex',
            flexWrap: 'wrap',
          }
      }
    >
      {displayedFilters.map((currentFilter, index) => {
        const filterKey = currentFilter.key;
        const filterOperator = currentFilter.operator;
        const isOperatorNegative = filterOperator.startsWith('not_') && filterOperator !== 'not_nil';
        const isOperatorDisplayed = ![
          'eq',
          'not_eq',
          'nil',
          'not_nil',
          'contains',
          'not_contains',
          'starts_with',
          'not_starts_with',
          'not_ends_with',
          'ends_with',
        ].includes(filterOperator);
        const keyLabel = (
          <>
            {truncate(t(filterKey), 20)}
            {isOperatorDisplayed
              ? convertOperatorToIcon(filterOperator)
              : currentFilter.values.length > 0 && ':'}
          </>
        );
        const label = (
          <>
            {isOperatorNegative ? `${t('NOT')} ` : ''} {keyLabel}
          </>
        );
        const isNotLastFilter = index < displayedFilters.length - 1;
        return (
          <Fragment key={currentFilter.id}>
            <Tooltip
              title={
                <FilterValues
                  label={label}
                  tooltip={true}
                  currentFilter={currentFilter}
                  handleSwitchLocalMode={handleSwitchLocalMode}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  helpers={helpers}
                  redirection={redirection}
                />
              }
            >
              <Chip
                color={chipColor}
                ref={isNotLastFilter ? null : latestItemRef}
                classes={{ root: classFilter, label: classes.chipLabel }}
                variant={
                  currentFilter.values.length === 0
                  && !['nil', 'not_nil'].includes(filterOperator)
                    ? 'outlined'
                    : 'filled'
                }
                label={
                  <FilterValues
                    label={label}
                    tooltip={false}
                    currentFilter={currentFilter}
                    handleSwitchLocalMode={handleSwitchLocalMode}
                    filtersRepresentativesMap={filtersRepresentativesMap}
                    redirection={redirection}
                    helpers={helpers}
                    onClickLabel={(event) => handleChipClick(event, currentFilter?.id)
                    }
                  />
                }
                disabled={
                  disabledPossible ? displayedFilters.length === 1 : undefined
                }
                onDelete={
                  isReadonlyFilter
                    ? () => manageRemoveFilter(
                      currentFilter.id,
                      filterKey,
                      filterOperator,
                    )
                    : undefined
                }
              />
            </Tooltip>
            {isNotLastFilter && (
              <div className={classOperator} onClick={handleSwitchGlobalMode}>
                {t(globalMode.toUpperCase())}
              </div>
            )}
          </Fragment>
        );
      })}
      {filterChipsParams.anchorEl && (
        <FilterChipPopover
          filters={filters.filters}
          params={filterChipsParams}
          handleClose={handleClose}
          open={open}
          helpers={helpers}
        />
      )}
      {filters.filterGroups
        && filters.filterGroups.length > 0 && ( // if there are filterGroups, we display a warning box // TODO display correctly filterGroups
          <Chip
            classes={{ root: classFilter, label: classes.chipLabel }}
            color="warning"
            label={
              <>
                {t('Filters are not fully displayed')}
                <DisplayFilterGroup
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  filterObj={filters}
                  filterMode={filters.mode}
                />
              </>
            }
          />
      )}
    </Box>
  );
};

export default FilterIconButtonContainer;
