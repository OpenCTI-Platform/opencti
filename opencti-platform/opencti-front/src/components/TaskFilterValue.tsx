import * as R from 'ramda';
import React from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import FilterIconButtonContent, { filterIconButtonContentQuery } from './FilterIconButtonContent';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import { useFormatter } from './i18n';
import { FilterGroup } from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import { Theme } from './Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  filter: {
    margin: '5px 10px 5px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '5px 10px 5px 0',
  },
}));

const TaskFilterValue = ({ filters, queryRef }:
{
  filters: FilterGroup,
  queryRef: PreloadedQuery<FilterIconButtonContentQuery>,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { filtersRepresentatives } = usePreloadedQuery<FilterIconButtonContentQuery>(filterIconButtonContentQuery, queryRef);
  const globalFilterMode = t(filters.mode.toUpperCase());
  return (
    <>
      {filters.filters.map((currentFilter) => {
        const label = `${truncate(
          currentFilter.key.startsWith('rel_')
            ? t(
              `relationship_${currentFilter.key
                .replace('rel_', '')
                .replace('.*', '')}`,
            )
            : t(`filter_${currentFilter.key}`),
          20,
        )}`;
        return (
          <span key={currentFilter.key}>
            <Chip
              classes={{ root: classes.filter }}
              label={
                <div>
                  <strong>{label}</strong>: {currentFilter.values.map(
                    (o) => {
                      const localFilterMode = t(currentFilter.mode.toUpperCase());
                      return (
                      <span key={o}>
                        <FilterIconButtonContent
                          filterKey={currentFilter.key}
                          id={o}
                          filtersRepresentatives={filtersRepresentatives}
                        ></FilterIconButtonContent>
                        {R.last(currentFilter.values) !== o
                          && (<code>{localFilterMode}</code>)
                        }{' '}
                      </span>
                      );
                    },
                  )}
                </div>
              }
            />
            {R.last(filters.filters)?.key
              !== currentFilter.key && (
                <Chip
                  classes={{ root: classes.operator }}
                  label={globalFilterMode}
                />
            )}
          </span>
        );
      })}
    </>
  );
};

export default TaskFilterValue;
