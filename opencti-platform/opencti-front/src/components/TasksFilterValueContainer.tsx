import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { FilterGroup, GqlFilterGroup } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import TaskFilterValue from './TaskFilterValue';
import Loader from './Loader';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import { Theme } from './Theme';

const useStyles = makeStyles<Theme>(() => ({
  filter: {
    marginRight: 10,
    marginTop: 10,
    lineHeight: 32,
    marginBottom: 10,
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

const TasksFilterValueContainer = ({ filters, isFiltersInOldFormat }: { filters: FilterGroup, isFiltersInOldFormat?: boolean }) => {
  const classes = useStyles();
  const queryRef = useQueryLoading<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    { filters: filters as unknown as GqlFilterGroup },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <TaskFilterValue
            filters={filters}
            queryRef={queryRef}
          ></TaskFilterValue>
        </React.Suspense>
      )}
      {isFiltersInOldFormat
        && <Chip
          classes={{ root: classes.filter, label: classes.chipLabel }}
          color={'warning'}
          label={'Filters are stored in a deprecated format'} />
      }
    </>
  );
};

export default TasksFilterValueContainer;
