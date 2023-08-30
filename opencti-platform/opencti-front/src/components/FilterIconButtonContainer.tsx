import { last } from 'ramda';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { truncate } from '../utils/String';
import { DataColumns } from './list_lines';
import { useFormatter } from './i18n';
import { Theme } from './Theme';
import { Filter } from '../utils/filters/filtersUtils';
import FilterIconButtonContent, { filterIconButtonContentQuery } from './FilterIconButtonContent';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  filter1: {
    marginRight: 10,
    lineHeight: 32,
    marginBottom: 10,
  },
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
    marginRight: 10,
    marginBottom: 10,
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
  inlineOperator: {
    display: 'inline-block',
    height: '100%',
    borderRadius: 0,
    margin: '0 5px 0 5px',
    padding: '0 5px 0 5px',
    backgroundColor: 'rgba(255, 255, 255, .1)',
    fontFamily: 'Consolas, monaco, monospace',
  },
  chipLabel: {
    lineHeight: '32px',
    maxWidth: 400,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
}));

interface FilterIconButtonContainerProps {
  globalMode: string;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  classNameNumber?: number;
  styleNumber?: number;
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
  filtersRepresentativesQueryRef: PreloadedQuery<FilterIconButtonContentQuery>;
  chipColor?: string;
}

const FilterIconButtonContainer: FunctionComponent<FilterIconButtonContainerProps> = ({
  globalMode,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  styleNumber,
  disabledPossible,
  redirection,
  filtersRepresentativesQueryRef,
  chipColor,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const { filtersRepresentatives } = usePreloadedQuery<FilterIconButtonContentQuery>(filterIconButtonContentQuery, filtersRepresentativesQueryRef);
  const displayedFilters = filtersRepresentatives?.filters.map((f) => ({ ...f, key: f.key[0] })) ?? [];
  let classFilter = classes.filter1;
  let classOperator = classes.operator1;
  if (styleNumber === 2) {
    classFilter = classes.filter2;
    classOperator = classes.operator2;
  } else if (styleNumber === 3) {
    classFilter = classes.filter3;
    classOperator = classes.operator3;
  }
  const lastKey = last(displayedFilters)?.key;
  const lastOperator = last(displayedFilters)?.operator;

  return (
    <>
      {displayedFilters
        .map((currentFilter) => {
          const filterKey = currentFilter.key;
          const filterValues = currentFilter.values;
          const negative = currentFilter.operator === 'not_eq';
          const operatorDisplay = currentFilter.operator !== 'eq' && currentFilter.operator !== 'not_eq';
          const keyLabel = operatorDisplay
            ? truncate(t(`filter_${filterKey}_${currentFilter.operator}`), 20)
            : truncate(t(`filter_${filterKey}`), 20);
          const label = `${negative ? `${t('NOT')} ` : ''}${keyLabel}`;
          const isNotLastFilter = lastKey !== filterKey || lastOperator !== currentFilter.operator;
          const values = (
            <>
              {filterValues.map((id) => {
                const value = currentFilter.representatives.filter((n) => n?.id === id)[0]?.value;
                const dissocCurrentFilter = {
                  key: currentFilter.key,
                  values: currentFilter.values,
                  operator: currentFilter.operator,
                  mode: currentFilter.mode,
                };
                return (
                  <span key={id}>
                    <FilterIconButtonContent
                      redirection={redirection}
                      filterKey={filterKey}
                      id={id}
                      value={value}
                    ></FilterIconButtonContent>
                    {last(filterValues) !== id && (
                      <Chip
                        className={classes.inlineOperator}
                        label={t((currentFilter.mode ?? 'or').toUpperCase())}
                        onClick={() => handleSwitchLocalMode?.(dissocCurrentFilter)}
                      />
                    )}{' '}
                  </span>
                );
              })}
            </>
          );
          return (
            <span key={filterKey}>
              <Tooltip
                title={
                  <>
                    <strong>{label}</strong>: {values}
                  </>
                }
              >
                <Chip
                  classes={{ root: classFilter, label: classes.chipLabel }}
                  color={chipColor}
                  label={
                    <>
                      <strong>{label}</strong>: {values}
                    </>
                  }
                  disabled={
                    disabledPossible
                      ? displayedFilters.length === 1
                      : undefined
                  }
                  onDelete={
                    handleRemoveFilter
                      ? () => handleRemoveFilter(filterKey, currentFilter.operator ?? undefined)
                      : undefined
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
            </span>
          );
        })}
    </>
  );
};

export default FilterIconButtonContainer;
