import React from 'react';
import { GqlFilterGroup, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../utils/filters/filtersUtils';
import { filterValuesContentQuery } from './FilterValuesContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import TaskFilterValue from './TaskFilterValue';
import Loader from './Loader';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { FilterGroup } from '../utils/filters/filtersHelpers-types';

const TasksFilterValueContainer = ({ filters, entityTypes }: { filters: FilterGroup, entityTypes?: string[] }) => {
  const cleanUpFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, entityTypes) as FilterGroup;
  const queryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
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
