import React from 'react';
import { FilterGroup, GqlFilterGroup, removeIdFromFilterObject } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import TaskFilterValue from './TaskFilterValue';
import Loader from './Loader';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';

const TasksFilterValueContainer = ({ filters }: { filters: FilterGroup }) => {
  const cleanUpFilters = removeIdFromFilterObject(filters) as FilterGroup;
  const queryRef = useQueryLoading<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    { filters: cleanUpFilters as unknown as GqlFilterGroup },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <TaskFilterValue
            filters={cleanUpFilters}
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default TasksFilterValueContainer;
