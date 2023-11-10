import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { Fragment, FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
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
import { getFilterHelpers } from '../utils/filters/FiltersHelpers.util';

const useStyles = makeStyles<Theme>((theme) => ({
  filter2: {
    margin: '0 10px 10px 0',
    lineHeight: 32,
  },
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
    margin: '0 10px 10px 0',
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
    lineHeight: '32px',
    maxWidth: 400,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    opacity: 0.5,
    '&:hover': {
      opacity: 1,
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
  const [filterChipsParams, setFilterChipsParams] = React.useState<FilterChipsParameter>({
    filter: undefined,
    anchorEl: undefined,
  } as FilterChipsParameter);
  const open = Boolean(filterChipsParams.anchorEl);

  const handleClose = () => {
    setFilterChipsParams({
      filterId: undefined,
      anchorEl: undefined,
    });
  };
  const handleChipClick = (event: React.MouseEvent<HTMLButtonElement>, filterId?: string) => {
    setFilterChipsParams({
      filterId,
      anchorEl: event.currentTarget,
    });
  };

  return (
    <div style={{
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
          const keyLabel = isOperatorDisplayed
            ? truncate(t(`filter_${filterKey}_${filterOperator}`), 20)
            : truncate(t(`filter_${filterKey}`), 20);
          const label = `${isOperatorNegative ? `${t('NOT')} ` : ''}${keyLabel}`;
          const isNotLastFilter = index < displayedFilters.length - 1;
          return (
            <Fragment key={filterKey}>
              <Tooltip
                title={
                  <FilterValues label={label}
                                tooltip={true}
                                currentFilter={currentFilter}
                                handleSwitchLocalMode={handleSwitchLocalMode}
                                filtersRepresentatives={filtersRepresentatives}
                                redirection={redirection}/>
                }
              >
                <Chip
                  classes={{ root: classFilter, label: currentFilter.values.length === 0 && !['nil', 'not_nil'].includes(filterOperator) ? classes.chipLabelNoValues : classes.chipLabel }}
                  label={
                    <FilterValues
                      label={label}
                      tooltip={false} currentFilter={currentFilter}
                      handleSwitchLocalMode={handleSwitchLocalMode}
                      filtersRepresentatives={filtersRepresentatives}
                      redirection={redirection}
                      onClickLabel={(event) => handleChipClick(event, currentFilter?.id)}
                    />
                  }
                  disabled={
                    disabledPossible
                      ? displayedFilters.length === 1
                      : undefined
                  }
                  onDelete={
                    () => getFilterHelpers()?.handleRemoveFilterNew(currentFilter.id)
                  }
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
        filterChipsParams?.anchorEl
        && <FilterChipPopover filters={filters.filters} params={filterChipsParams} handleClose={handleClose} open={open}/>
      }
      {filters.filterGroups && filters.filterGroups.length > 0 // if there are filterGroups, we display a warning box // TODO display correctly filterGroups
        && (
          <Chip
            classes={{ root: classFilter, label: classes.chipLabel }}
            color={'warning'}
            label={
              <>
                {t('Filters are not fully displayed')}
                <DisplayFilterGroup filterGroups={filters.filterGroups} filterMode={filters.mode}/>
              </>
            }
          />)
      }
    </div>
  );
};

export default FilterIconButtonContainer;
