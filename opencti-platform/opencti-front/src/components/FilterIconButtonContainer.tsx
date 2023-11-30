import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { Fragment, FunctionComponent, useEffect, useRef } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import classNames from 'classnames';
import { truncate } from '../utils/String';
import { DataColumns } from './list_lines';
import { useFormatter } from './i18n';
import { Theme } from './Theme';
import { Filter, FilterGroup } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import FilterValues from './filters/FilterValues';
import { FilterChipPopover, FilterChipsParameter } from './filters/FilterChipPopover';
import DisplayFilterGroup from './filters/DisplayFilterGroup';
import { UseLocalStorageHelpers } from '../utils/hooks/useLocalStorage';

const useStyles = makeStyles<Theme>((theme) => ({
  filter3: {
    fontSize: 12,
    height: 20,
    marginRight: 7,
    borderRadius: 10,
    lineHeight: 32,
  },
  operator1: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
  },
  operator2: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
  },
  operator3: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    height: 20,
    marginRight: 10,
  },
  chipLabel: {
    lineHeight: '32px',
    maxWidth: 400,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
  chipLabelNoValues: {
    outline: '2px solid currentColor',
    backgroundColor: 'transparent',
    color: '#FFFFFF29',
    transition: 'all 130ms ease-in-out',
    '&:hover': {
      backgroundColor: '#FFFFFF29',
      color: 'white',
      outline: 'none',
    },
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
  helpers?: UseLocalStorageHelpers
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
  handleRemoveFilter,
  helpers,
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
  const hasRenderedRef = useRef(false);
  const filtersRepresentativesMap = new Map(filtersRepresentatives.map((n) => [n.id, n.value]));
  const [filterChipsParams, setFilterChipsParams] = React.useState<FilterChipsParameter>({
    filter: undefined,
    anchorEl: undefined,
  } as FilterChipsParameter);
  const open = Boolean(filterChipsParams.anchorEl);

  useEffect(() => {
    if (hasRenderedRef.current && latestItemRef.current && nbDisplayFilter.current < displayedFilters.length) {
      setFilterChipsParams({
        filterId: displayedFilters[displayedFilters.length - 1].id,
        anchorEl: latestItemRef.current as unknown as HTMLElement,
      });
    }
    nbDisplayFilter.current = displayedFilters.length;
    hasRenderedRef.current = true;
  }, [displayedFilters]);
  const handleClose = () => {
    setFilterChipsParams({
      filterId: undefined,
      anchorEl: undefined,
    });
  };
  const handleChipClick = (event: React.MouseEvent<HTMLButtonElement>, filterId?: string) => {
    if (helpers) {
      setFilterChipsParams({
        filterId,
        anchorEl: event.currentTarget,
      });
    }
  };

  const manageRemoveFilter = (currentFilterId: string | undefined, filterKey: string, filterOperator: string) => {
    if (helpers) {
      helpers?.handleRemoveFilterById(currentFilterId);
    } else if (handleRemoveFilter) {
      handleRemoveFilter(filterKey, filterOperator ?? undefined);
    }
  };

  const convertOperatorToIcon = (operator: string) => {
    switch (operator) {
      case 'lt':
        return <>&#60;</>;
      case 'lte':
        return <>&#8804;</>;
      case 'gt':
        return <>&#62;</>;
      case 'gte':
        return <>&#8805;</>;
      default:
        return null;
    }
  };
  return (
    <div style={{
      marginTop: '10px',
      gap: '10px',
      display: 'flex',
      flexWrap: 'wrap',
    }}>
      {displayedFilters
        .map((currentFilter, index) => {
          const filterKey = currentFilter.key;
          const filterOperator = currentFilter.operator;
          const isOperatorNegative = filterOperator.startsWith('not_') && filterOperator !== 'not_nil';
          const isOperatorDisplayed = !['eq', 'not_eq', 'nil', 'not_nil'].includes(filterOperator);
          const keyLabel = <>{truncate(t(filterKey), 20)} {isOperatorDisplayed ? convertOperatorToIcon(filterOperator) : (currentFilter.values.length > 0 && ':')}</>;
          const label = <>{isOperatorNegative ? `${t('NOT')} ` : ''} {keyLabel} </>;
          const isNotLastFilter = index < displayedFilters.length - 1;
          return (
            <Fragment key={currentFilter.id}>
              <Tooltip
                title={
                  <FilterValues label={label}
                                tooltip={true}
                                currentFilter={currentFilter}
                                handleSwitchLocalMode={handleSwitchLocalMode}
                                filtersRepresentativesMap={filtersRepresentativesMap}
                                helpers={helpers}
                                redirection={redirection}/>
                }
              >
                <Chip
                  ref={isNotLastFilter ? null : latestItemRef}
                  classes={{ root: classNames(classFilter, currentFilter.values.length === 0 && !['nil', 'not_nil'].includes(filterOperator) ? classes.chipLabelNoValues : ''), label: classes.chipLabel }}
                  label={
                    <FilterValues
                      label={label}
                      tooltip={false} currentFilter={currentFilter}
                      handleSwitchLocalMode={handleSwitchLocalMode}
                      filtersRepresentativesMap={filtersRepresentativesMap}
                      redirection={redirection}
                      helpers={helpers}
                      onClickLabel={(event) => handleChipClick(event, currentFilter?.id)}
                    />
                  }
                  disabled={
                    disabledPossible ? displayedFilters.length === 1 : undefined
                  }
                  onDelete={() => manageRemoveFilter(currentFilter.id, filterKey, filterOperator)}
                />
              </Tooltip>
              {isNotLastFilter && (
                <Chip
                  classes={{ root: classOperator }}
                  label={t(globalMode.toUpperCase())}
                  onClick={handleSwitchGlobalMode}
                />
              )}
            </Fragment>
          );
        })}
      {
        filterChipsParams.anchorEl
        && <FilterChipPopover filters={filters.filters}
                              params={filterChipsParams}
                              handleClose={handleClose}
                              open={open}
                              helpers={helpers}/>
      }
      {filters.filterGroups && filters.filterGroups.length > 0 // if there are filterGroups, we display a warning box // TODO display correctly filterGroups
        && (
          <Chip
            classes={{ root: classFilter, label: classes.chipLabel }}
            color={'warning'}
            label={
              <>
                {t('Filters are not fully displayed')}
                <DisplayFilterGroup
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  filterObj={filters}
                                    filterMode={filters.mode}/>
              </>
            }
          />)
      }
    </div>
  );
};

export default FilterIconButtonContainer;
