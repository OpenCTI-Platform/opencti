import React, { FunctionComponent } from 'react';
import { NotificationsLines_data$data } from '@components/profile/notifications/__generated__/NotificationsLines_data.graphql';
import { notificationLineFragment } from '@components/profile/notifications/NotificationLine';
import { Tooltip } from '@mui/material';
import Chip from '@mui/material/Chip';
import { deepPurple, green, indigo, red } from '@mui/material/colors';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { notificationsLinesFragment, notificationsLinesQuery } from './notifications/NotificationsLines';
import { NotificationsLinesPaginationQuery, NotificationsLinesPaginationQuery$variables } from './notifications/__generated__/NotificationsLinesPaginationQuery.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useGetDefaultFilterObject, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import { hexToRGB } from '../../../utils/Colors';

export const LOCAL_STORAGE_KEY = 'notifiers';

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Notifications'));
  const {
    me,
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    operation: {
      label: 'Operation',
      percentWidth: 20,
      isSortable: isRuntimeSort,
      render: ({ notification_content, notification_type }) => {
        const events = notification_content.map((n: any) => n.events).flat();
        const firstEvent = events.at(0);
        const isDigest = notification_type === 'digest';
        const firstOperation = isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
        const eventTypes: Record<string, string> = {
          create: t_i18n('Creation'),
          update: t_i18n('Modification'),
          delete: t_i18n('Deletion'),
          none: t_i18n('Unknown'),
        };
        const colors: Record<string, string> = {
          none: green[500],
          create: green[500],
          update: deepPurple[500],
          delete: red[500],
          multiple: indigo[500],
        };
        return (<div style={{ height: 20, fontSize: 13, float: 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: 10 }}>
          <Chip
            style={{ fontSize: 12,
              height: 20,
              float: 'left',
              width: 150,
              textTransform: 'uppercase',
              borderRadius: 4,
              backgroundColor: hexToRGB(colors[firstOperation] ?? indigo[500], 0.08),
              color: colors[firstOperation] ?? indigo[500],
              border: `1px solid ${colors[firstOperation] ?? indigo[500]}`,
            }}
            label={
              events.length > 1
                ? t_i18n('Multiple')
                : (eventTypes[firstEvent?.operation ?? 'none'] ?? firstEvent?.operation)
            }
          />
        </div>);
      },
    },
    message: {
      label: 'Message',
      percentWidth: 48,
      isSortable: isRuntimeSort,
      render: ({ notification_content }) => {
        const events = notification_content.map((n: any) => n.events).flat();
        const firstEvent = events.at(0);

        return (<div style={{ height: 20, fontSize: 13, float: 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: 10 }}>
          {events.length > 1 ? (
            <i>{t_i18n('Digest with multiple notifiers')}</i>
          ) : (
            <Tooltip title={firstEvent?.message ?? '-'}>
              <span>
                <MarkdownDisplay content={firstEvent?.message ?? '-'} remarkGfmPlugin commonmark removeLinks/>
              </span>
            </Tooltip>
          )}
        </div>);
      },
    },
    created: {
      label: 'Original creation date',
      percentWidth: 20,
      isSortable: isRuntimeSort,
    },
    name: {
      label: 'Trigger name',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
  };
  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['is_read', 'trigger_id'], ['Notification']),
    },
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<NotificationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Notification']);
  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['Notification'],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: 'user_id',
        values: [me.id],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as NotificationsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<NotificationsLinesPaginationQuery>(
    notificationsLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: notificationsLinesQuery,
    linesFragment: notificationsLinesFragment,
    queryRef,
    nodePath: ['myNotifications', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<NotificationsLinesPaginationQuery>;

  return (
    <div>
      <Breadcrumbs elements={[{ label: t_i18n('Notifications'), current: true }]} />
      {queryRef && (
      <DataTable
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        preloadedPaginationProps={preloadedPaginationProps}
        resolvePath={(data: NotificationsLines_data$data) => data.myNotifications?.edges?.map((n) => n?.node)}
        dataColumns={dataColumns}
        lineFragment={notificationLineFragment}
        toolbarFilters={contextFilters}
        exportContext={{ entity_type: 'Notification' }}
        availableEntityTypes={['Notification']}
      />
      )}
    </div>
  );
};

export default Notifications;
