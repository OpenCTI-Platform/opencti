import React, { FunctionComponent, Suspense, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { Badge } from '@mui/material';
import CircularProgress from '@mui/material/CircularProgress';
import { interval } from 'rxjs';
import { StixCoreObjectActiveBackgroundTasksQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectActiveBackgroundTasksQuery.graphql';
import { TEN_SECONDS } from '../../../../utils/Time';

const stixCoreObjectActiveBackgroundTasksQuery = graphql`
  query StixCoreObjectActiveBackgroundTasksQuery($id: ID!) {
    stixCoreBackgroundActiveOperations(id: $id) {
      id
      description
      actions {
        type
      }
    }
  }
`;

const interval$ = interval(TEN_SECONDS);

interface StixCoreObjectBackgroundTaskComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectActiveBackgroundTasksQuery>;
  refetch: () => void;
  actionsFilter: string[];
}

const StixCoreObjectBackgroundTasksComponent: FunctionComponent<StixCoreObjectBackgroundTaskComponentProps> = ({ actionsFilter, queryRef, refetch }) => {
  const { stixCoreBackgroundActiveOperations } = usePreloadedQuery(stixCoreObjectActiveBackgroundTasksQuery, queryRef);
  const filteredActiveTasks = stixCoreBackgroundActiveOperations?.filter((t) => t?.actions?.some((a) => actionsFilter.includes(a?.type ?? ''))) ?? [];
  const currenActiveTasksCount = filteredActiveTasks?.length ?? 0;
  const hasCurrentActiveTask = currenActiveTasksCount > 0;
  const tooltip = filteredActiveTasks.map((task) => task.description).join('\n');

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  return (
    <div style={{ display: 'flex', alignItems: 'center', padding: '0 12px' }}>
      {hasCurrentActiveTask && (
        <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{tooltip}</span>}>
          <Badge
            badgeContent={currenActiveTasksCount}
            color="warning"
          >
            <CircularProgress
              variant={'indeterminate'}
              size={25}
              style={{ cursor: 'pointer' }}
            />
          </Badge>
        </Tooltip>)}
    </div>
  );
};

type StixCoreObjectBackgroundTaskProps = {
  id: string,
  actionsFilter: string[],
};

const StixCoreObjectBackgroundTasks: FunctionComponent<StixCoreObjectBackgroundTaskProps> = ({ id, actionsFilter }) => {
  const [queryRef, loadQuery] = useQueryLoader<StixCoreObjectActiveBackgroundTasksQuery>(stixCoreObjectActiveBackgroundTasksQuery);

  useEffect(() => {
    loadQuery({ id }, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({ id }, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);
  return (
    <>
      {queryRef && (
        <Suspense>
          <StixCoreObjectBackgroundTasksComponent actionsFilter={actionsFilter} queryRef={queryRef} refetch={refetch} />
        </Suspense>
      )}
    </>
  );
};

export default StixCoreObjectBackgroundTasks;
