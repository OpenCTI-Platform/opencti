import { last } from 'ramda';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { InformationOutline } from 'mdi-material-ui';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { truncate } from '../utils/String';
import { DataColumns } from './list_lines';
import { useFormatter } from './i18n';
import { Theme } from './Theme';
import { Filter, FilterGroup } from '../utils/filters/filtersUtils';
import FilterIconButtonContent, {
  filterIconButtonContentQuery,
} from './FilterIconButtonContent';
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
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
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
  const { filtersRepresentatives } = usePreloadedQuery<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    filtersRepresentativesQueryRef,
  );
  const filtersRepresentativesMap = new Map(
    filtersRepresentatives.map((n) => [n.id, n.value]),
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
  const lastKey = last(displayedFilters)?.key;
  const lastOperator = last(displayedFilters)?.operator;
  return (
    <>
      {displayedFilters.map((currentFilter) => {
        const filterKey = currentFilter.key;
        const filterValues = currentFilter.values;
        const filterOperator = currentFilter.operator;
        const isOperatorNegative = filterOperator.startsWith('not_');
        const isOperatorDisplayed = ![
          'eq',
          'not_eq',
          'nil',
          'not_nil',
        ].includes(filterOperator);
        const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator);
        const keyLabel = isOperatorDisplayed
          ? truncate(t(`filter_${filterKey}_${filterOperator}`), 20)
          : truncate(t(`filter_${filterKey}`), 20);
        const label = `${isOperatorNegative ? `${t('NOT')} ` : ''}${keyLabel}`;
        const isNotLastFilter = lastKey !== filterKey || lastOperator !== filterOperator;
        const values = (tooltip: boolean) => (
          <>
            {isOperatorNil ? (
              <span>{t('No value')}</span>
            ) : (
              filterValues.map((id) => {
                return (
                  <span key={id}>
                    {filtersRepresentativesMap.has(id) && (
                      <FilterIconButtonContent
                        redirection={tooltip ? false : redirection}
                        isFilterTooltip={!!tooltip}
                        filterKey={filterKey}
                        id={id}
                        value={filtersRepresentativesMap.get(id)}
                      />
                    )}
                    {last(filterValues) !== id && (
                      <Chip
                        className={classes.inlineOperator}
                        label={t((currentFilter.mode ?? 'or').toUpperCase())}
                        onClick={() => handleSwitchLocalMode?.(currentFilter)}
                      />
                    )}{' '}
                  </span>
                );
              })
            )}
          </>
        );
        return (
          <span key={filterKey}>
            <Tooltip
              title={
                <>
                  <strong>{label}</strong>: {values(true)}
                </>
              }
            >
              <Chip
                classes={{ root: classFilter, label: classes.chipLabel }}
                color={chipColor}
                label={
                  <>
                    <strong>{label}</strong>: {values(false)}
                  </>
                }
                disabled={
                  disabledPossible ? displayedFilters.length === 1 : undefined
                }
                onDelete={
                  handleRemoveFilter
                    ? () => handleRemoveFilter(
                      filterKey,
                      filterOperator ?? undefined,
                    )
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
      {filters.filterGroups
        && filters.filterGroups.length > 0 && ( // if there are filterGroups, we display a warning box // TODO display correctly filterGroups
          <Chip
            classes={{ root: classFilter, label: classes.chipLabel }}
            color={'warning'}
            label={
              <>
                {t('Filters are not fully displayed')}
                <Tooltip
                  title={`This filter contains imbricated filter groups, that are not fully supported yet in the platform display and can only be edited via the API.
            They might have been created via the API or a migration from a previous filter format.
            For your information, here is the content of the filter object: ${JSON.stringify(filters.filterGroups)}`}
                >
                  <InformationOutline
                    fontSize="small"
                    color="secondary"
                    style={{ cursor: 'default' }}
                  />
                </Tooltip>
              </>
            }
          />
      )}
    </>
  );
};

export default FilterIconButtonContainer;
