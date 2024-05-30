import * as R from 'ramda';
import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import FilterValuesContent, { filterValuesContentQuery } from './FilterValuesContent';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { useFormatter } from './i18n';
import { convertOperatorToIcon } from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import type { Theme } from './Theme';
import DisplayFilterGroup from './filters/DisplayFilterGroup';
import { FilterGroup } from '../utils/filters/filtersHelpers-types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  filter: {
    margin: '5px 10px 5px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '5px 10px 5px 0',
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

const TaskFilterValue = ({
  filters,
  queryRef,
}: {
  filters: FilterGroup;
  queryRef: PreloadedQuery<FilterValuesContentQuery>;
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    queryRef,
  );
  const filtersRepresentativesMap = new Map(
    (filtersRepresentatives ?? []).map((n) => [n?.id, n]),
  );
  const globalFilterMode = t_i18n(filters.mode.toUpperCase());
  return (
    <>
      {(filters.filters ?? []).map((currentFilter) => {
        const label = `${truncate(
          currentFilter.key.startsWith('rel_')
            ? t_i18n(
              `relationship_${currentFilter.key
                .replace('rel_', '')
                .replace('.*', '')}`,
            )
            : t_i18n(currentFilter.key),
          20,
        )}`;
        const isOperatorNil = ['nil', 'not_nil'].includes(
          currentFilter.operator ?? 'eq',
        );
        const DisplayNilLabel = () => {
          if (currentFilter.operator === 'nil') {
            return <span>{t_i18n('is empty')}</span>;
          }
          if (currentFilter.operator === 'not_nil') {
            return <span>{t_i18n('is not empty')}</span>;
          }
          return null;
        };
        if (currentFilter.key === 'regardingOf') {
          const sortedFilterValues = [...currentFilter.values].sort((a, b) => -a.key.localeCompare(b.key)); // display type first, then id
          return (
            <span key={currentFilter.key}>
              <Chip
                classes={{ root: classes.filter }}
                label={
                  <div>
                    <strong>{label}</strong>:{' '}
                    <TaskFilterValue filters={{ mode: 'and', filters: sortedFilterValues, filterGroups: [] }} queryRef={queryRef} />
                  </div>
              }
              />
            </span>
          );
        }
        return (
          <span key={currentFilter.key}>
            <Chip
              classes={{ root: classes.filter }}
              label={
                <div>
                  <strong>{label}</strong>{convertOperatorToIcon(currentFilter.operator ?? 'eq')}{' '}
                  {isOperatorNil ? (
                    <DisplayNilLabel/>
                  ) : (
                    currentFilter.values.map((o) => {
                      const localFilterMode = t_i18n(
                        (currentFilter.mode ?? 'or').toUpperCase(),
                      );
                      return (
                        <Tooltip
                          key={o}
                          title={
                            <FilterValuesContent
                              filterKey={currentFilter.key}
                              id={o}
                              value={filtersRepresentativesMap.get(o)?.value ?? o}
                              isFilterTooltip={true}
                            />
                          }
                        >
                          <span key={o}>
                            <FilterValuesContent
                              filterKey={currentFilter.key}
                              id={o}
                              value={filtersRepresentativesMap.get(o)?.value ?? o}
                            />
                            {R.last(currentFilter.values) !== o && (
                            <code>{localFilterMode}</code>
                            )}{' '}
                          </span>
                        </Tooltip>
                      );
                    })
                  )}
                </div>
              }
            />
            {R.last(filters.filters)?.key !== currentFilter.key && (
              <Chip
                classes={{ root: classes.operator }}
                label={globalFilterMode}
              />
            )}
          </span>
        );
      })}
      {filters.filterGroups
        && filters.filterGroups.length > 0 && (
        <DisplayFilterGroup
          filtersRepresentativesMap={filtersRepresentativesMap}
          filterObj={filters}
          filterMode={filters.mode}
          classFilter={classes.filter}
          classChipLabel={classes.chipLabel}
        />
      )}
    </>
  );
};

export default TaskFilterValue;
