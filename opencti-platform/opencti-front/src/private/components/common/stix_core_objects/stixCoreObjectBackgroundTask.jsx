import React, { Suspense, useEffect, useState } from 'react';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { CheckCircleOutlined } from '@mui/icons-material';
import { Badge } from '@mui/material';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { interval } from 'rxjs';
import Drawer from '../drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { ONE_SECOND } from '../../../../utils/Time';

const stixCoreObjectBackgroundTaskQuery = graphql`
    query stixCoreObjectBackgroundTaskQuery($id: ID!) {
        stixCoreBackgroundActiveOperations(id: $id) {
          id
          initiator {
            id
            name
            representative {
              main
            }
          }
          type
          actions {
            type
            context {
              field
              type
              values
            }
          }
          created_at
          last_execution_date
          completed
          task_expected_number
          task_processed_number
            actions {
                type
            }
          work {
            id
            connector {
              name
            }
            user {
              name
            }
            completed_time
            received_time
            tracking {
              import_expected_number
              import_processed_number
            }
            messages {
              timestamp
              message
            }
            errors {
              timestamp
              message
            }
            status
            timestamp
            draft_context
          }
        }
    }
`;

const LOCAL_STORAGE_KEY = 'active_tasks';

const interval$ = interval(ONE_SECOND);

const StixCoreObjectBackgroundTaskComponent = ({ entityId, queryRef, refetch }) => {
  const { t_i18n } = useFormatter();
  const [displayTasks, setDisplayTasks] = useState(false);
  const { stixCoreBackgroundActiveOperations } = usePreloadedQuery(stixCoreObjectBackgroundTaskQuery, queryRef);
  const currenActiveTasksCount = stixCoreBackgroundActiveOperations.length;
  const hasCurrentActiveTask = currenActiveTasksCount > 0;

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  const dataColumns = {
    initiator: {
      id: 'Initiator',
      label: 'Initiator',
      percentWidth: 25,
      isSortable: false,
      render: ({ initiator }) => defaultRender(initiator.representative.main),
    },
    created_at: {
      percentWidth: 25,
      isSortable: true,
      render: ({ created_at }, h) => defaultRender(h.nsdt(created_at)),
    },
    task_expected_number: {
      id: 'Impacted elements',
      label: 'Impacted elements',
      percentWidth: 25,
      isSortable: false,
      render: ({ task_expected_number }) => defaultRender(task_expected_number),
    },
    completed: {
      id: 'Completed',
      label: 'Completed',
      percentWidth: 25,
      isSortable: false,
      render: ({ completed }, h) => defaultRender(completed ? h.t_i18n('Yes') : h.t_i18n('No')),
    },
  };
  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      {!hasCurrentActiveTask && (
        <Tooltip title={t_i18n('No background tasks running')}>
          <CheckCircleOutlined
            onClick={() => { setDisplayTasks(true); }}
            color="success"
            style={{ cursor: 'pointer' }}
          />
        </Tooltip>
      )}
      {hasCurrentActiveTask && (
        <Tooltip title={t_i18n('Background tasks currently running')}>
          <Badge
            badgeContent={currenActiveTasksCount}
            color="warning"
          >
            <CircularProgress
              onClick={() => { setDisplayTasks(true); }}
              variant={'indeterminate'}
              size={25}
              style={{ cursor: 'pointer' }}
            />
          </Badge>
        </Tooltip>)}
      <Drawer
        title={t_i18n('Active background tasks')}
        open={displayTasks}
        onClose={() => { refetch(); setDisplayTasks(false); }}
      >
        <>
          <Alert severity="info">{t_i18n('This page lists all active tasks targeting the current entity')}</Alert>
          <div data-testid="active-tasks-page">
            <DataTableWithoutFragment
              dataColumns={dataColumns}
              data={stixCoreBackgroundActiveOperations}
              storageKey={`${LOCAL_STORAGE_KEY}-${entityId}`}
              isLocalStorageEnabled={false}
              globalCount={currenActiveTasksCount}
              variant={DataTableVariant.inline}
              disableNavigation
            />
          </div>
        </>
      </Drawer>
    </div>
  );
};
const StixCoreObjectBackgroundTask = ({ id }) => {
  const [queryRef, loadQuery] = useQueryLoader(stixCoreObjectBackgroundTaskQuery);

  useEffect(() => {
    loadQuery({ id }, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({ id }, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <StixCoreObjectBackgroundTaskComponent entityId={id} queryRef={queryRef} refetch={refetch} />
        </Suspense>
      )}
    </>
  );
};

export default StixCoreObjectBackgroundTask;
