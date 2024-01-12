import * as R from 'ramda';
import React from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import FilterValuesContent, { filterValuesContentQuery } from './FilterValuesContent';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { useFormatter } from './i18n';
import { FilterGroup } from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import type { Theme } from './Theme';
import DisplayFilterGroup from './filters/DisplayFilterGroup';

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
  const { t } = useFormatter();
  const classes = useStyles();
  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    queryRef,
  );
  const filtersRepresentativesMap = new Map(
    (filtersRepresentatives ?? []).map((n) => [n?.id, n?.value]),
  );
  const globalFilterMode = t(filters.mode.toUpperCase());
  return (
    <>
      {(filters.filters ?? []).map((currentFilter) => {
        const label = `${truncate(
          currentFilter.key.startsWith('rel_')
            ? t(
              `relationship_${currentFilter.key
                .replace('rel_', '')
                .replace('.*', '')}`,
            )
            : t(currentFilter.key),
          20,
        )}`;
        const isOperatorNil = ['nil', 'not_nil'].includes(
          currentFilter.operator ?? 'eq',
        );
        const DisplayNilLabel = () => {
          if (currentFilter.operator === 'nil') {
            return <span>{t('is empty')}</span>;
          }
          if (currentFilter.operator === 'not_nil') {
            return <span>{t('is not empty')}</span>;
          }
          return null;
        };
        return (
          <span key={currentFilter.key}>
            <Chip
              classes={{ root: classes.filter }}
              label={
                <div>
                  <strong>{label}</strong>:{' '}
                  {isOperatorNil ? (
                    <DisplayNilLabel/>
                  ) : (
                    currentFilter.values.map((o) => {
                      const localFilterMode = t(
                        (currentFilter.mode ?? 'eq').toUpperCase(),
                      );
                      return (
                        <span key={o}>
                          <FilterValuesContent
                            filterKey={currentFilter.key}
                            id={o}
                            value={filtersRepresentativesMap.get(o)}
                          />
                          {R.last(currentFilter.values) !== o && (
                            <code>{localFilterMode}</code>
                          )}{' '}
                        </span>
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
