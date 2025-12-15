import React, { FunctionComponent, useState } from 'react';
import { Badge, Tooltip } from '@mui/material';
import Chip from '@mui/material/Chip';
import { indigo } from '@mui/material/colors';
import IconButton from '@common/button/IconButton';
import { CheckCircleOutlined, DeleteOutlined, UnpublishedOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import { NotificationsLine_node$data } from '@components/profile/__generated__/NotificationsLine_node.graphql';
import { NotificationsLinesPaginationQuery, NotificationsLinesPaginationQuery$variables } from '@components/profile/__generated__/NotificationsLinesPaginationQuery.graphql';
import { NotificationsLines_data$data } from '@components/profile/__generated__/NotificationsLines_data.graphql';
import DigestNotificationDrawer from '@components/profile/notifications/DigestNotificationDrawer';
import { useNavigate } from 'react-router-dom';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
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
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Transition from '../../../components/Transition';
import { deleteNode } from '../../../utils/store';
import { isNotEmptyField } from '../../../utils/utils';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { colors, getFirstOperation, iconSelector } from './notifications/notificationUtils';
import { chipInListBasicStyle } from '../../../utils/chipStyle';

export const LOCAL_STORAGE_KEY = 'notifiers';

const notificationsLineFragment = graphql`
  fragment NotificationsLine_node on Notification {
    id
    entity_type
    name
    created
    notification_type
    is_read
    notification_content {
      title
      events {
        message
        operation
        instance_id
      }
    }
  }
`;

const notificationsLinesQuery = graphql`
  query NotificationsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NotificationsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...NotificationsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const notificationsLinesFragment = graphql`
  fragment NotificationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotificationsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NotificationsLinesRefetchQuery") {
    myNotifications(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_myNotifications") {
      edges {
        node {
          id
          ...NotificationsLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const notificationLineNotificationMarkReadMutation = graphql`
  mutation NotificationsNotificationMarkReadMutation(
    $id: ID!
    $read: Boolean!
  ) {
    notificationMarkRead(id: $id, read: $read) {
      ...NotificationsLine_node
    }
  }
`;

const notificationLineNotificationDeleteMutation = graphql`
  mutation NotificationsNotificationDeleteMutation($id: ID!) {
    notificationDelete(id: $id)
  }
`;

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const navigate = useNavigate();
  const [commitMarkRead] = useApiMutation(
    notificationLineNotificationMarkReadMutation,
  );
  const [commitDelete] = useApiMutation(
    notificationLineNotificationDeleteMutation,
  );
  const [notificationToDelete, setNotificationToDelete] = useState<NotificationsLine_node$data>();
  const [notificationDigestToOpen, setNotificationDigestToOpen] = useState<NotificationsLine_node$data>();

  setTitle(t_i18n('Notifications'));

  const handleLineClick = (data: NotificationsLine_node$data) => {
    const events = data.notification_content.map((n) => n.events).flat();
    const isDigest = events.length > 1;
    if (isDigest) {
      setNotificationDigestToOpen(data);
    }

    const firstEvent = events.at(0);
    const firstOperation = isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
    const isLinkAvailable = events.length === 1 && isNotEmptyField(firstEvent?.instance_id) && firstOperation !== 'delete';
    if (isLinkAvailable && firstEvent.instance_id) {
      navigate(`/dashboard/id/${firstEvent.instance_id}`);
    }
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

  const {
    me,
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<NotificationsLinesPaginationQuery$variables>(
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

  const handleCloseDelete = () => {
    setNotificationToDelete(undefined);
  };
  const handleDelete = (id: string) => {
    return commitDelete({
      variables: {
        id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_myNotifications', queryPaginationOptions, id);
      },
      onCompleted: () => {
        handleCloseDelete();
      },
    });
  };

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    operation: {
      id: 'operation',
      label: 'Operation',
      percentWidth: 10,
      isSortable: false,
      render: ({ notification_content, notification_type }: NotificationsLine_node$data) => {
        const firstOperation = getFirstOperation({ notification_content, notification_type });
        const events = notification_content.map((n) => n.events).flat();
        const eventTypes: Record<string, string> = {
          create: t_i18n('Creation'),
          update: t_i18n('Modification'),
          delete: t_i18n('Deletion'),
          none: t_i18n('Unknown'),
        };
        return (
          <div style={{ height: 20, fontSize: 13, float: 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: 10 }}>
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
                  : (eventTypes[firstOperation] ?? firstOperation)
              }
            />
          </div>
        );
      },
    },
    message: {
      id: 'message',
      label: 'Message',
      percentWidth: 48,
      isSortable: false,
      render: (data: NotificationsLine_node$data) => {
        const events = data.notification_content.map((n) => n.events).flat();
        const firstEvent = events.at(0);
        const multipleEvents = events.length > 1;

        return (
          <div style={{ height: 20, fontSize: 13, float: 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: 10 }}>
            {multipleEvents ? (
              <i>{t_i18n('Digest with multiple notifiers')}</i>
            ) : (
              <Tooltip title={firstEvent?.message ?? '-'}>
                <span>
                  <MarkdownDisplay content={firstEvent?.message ?? '-'} remarkGfmPlugin commonmark removeLinks />
                </span>
              </Tooltip>
            )}
          </div>
        );
      },
    },
    created: {
      label: 'Original creation date',
      percentWidth: 25,
      isSortable: isRuntimeSort,
      render: ({ created }, item) => defaultRender(item.fldt(created)),
    },
    name: {
      id: 'name',
      label: 'Trigger name',
      percentWidth: 17,
      isSortable: isRuntimeSort,
      render: ({ notification_type, name }, { storageHelpers: { handleAddFilter } }) => {
        return (
          <div style={{
            height: 20,
            fontSize: 13,
            float: 'left',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            paddingRight: 10,
          }}
          >
            <Tooltip title={name ?? '-'}>
              <Chip
                style={{
                  ...chipInListBasicStyle,
                  width: 100,
                  marginRight: 10,
                }}
                color={notification_type === 'live'
                  ? 'warning'
                  : 'secondary'}
                variant="outlined"
                label={name ?? '-'}
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  handleAddFilter('name', name, 'eq');
                }}
              />
            </Tooltip>
          </div>
        );
      },
    },
  };

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

  const renderActions = (data: NotificationsLine_node$data) => {
    const [updating, setUpdating] = useState<boolean>(false);

    const handleRead = (id: string, read: boolean) => {
      setUpdating(true);
      return commitMarkRead({
        variables: {
          id,
          read,
        },
        onCompleted: () => {
          setUpdating(false);
        },
      });
    };

    const handleOpenDelete = () => {
      setUpdating(true);
      setNotificationToDelete(data);
    };

    return (
      <div style={{ marginLeft: -40 }}>
        <Tooltip title={data.is_read ? t_i18n('Mark as unread') : t_i18n('Mark as read')}>
          <IconButton
            disabled={updating}
            onClick={(event) => {
              event.stopPropagation();
              event.preventDefault();
              handleRead(data.id, !data.is_read);
            }}
            size="small"
            color={data.is_read ? 'warning' : 'success'}
          >
            {data.is_read ? <UnpublishedOutlined /> : <CheckCircleOutlined />}
          </IconButton>
        </Tooltip>
        <Tooltip title={t_i18n('Delete this notification')}>
          <span>
            <IconButton
              disabled={updating}
              onClick={(event) => {
                event.stopPropagation();
                event.preventDefault();
                handleOpenDelete();
              }}
              size="small"
              color="primary"
            >
              <DeleteOutlined />
            </IconButton>
          </span>
        </Tooltip>
      </div>
    );
  };
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
          onLineClick={handleLineClick}
          icon={(data) => {
            const operation = getFirstOperation(data);
            return (
              <Badge color="warning" variant="dot" invisible={data.is_read}>
                {iconSelector(operation)}
              </Badge>
            );
          }}
          taskScope="USER_NOTIFICATION"
          lineFragment={notificationsLineFragment}
          contextFilters={contextFilters}
          exportContext={{ entity_type: 'Notification' }}
          availableEntityTypes={['Notification']}
          actions={renderActions}
          markAsReadEnabled={true}
        />
      )}
      {notificationToDelete && (
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={!!notificationToDelete}
          slots={{ transition: Transition }}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this notification?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button variant="secondary" onClick={handleCloseDelete}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={() => handleDelete(notificationToDelete.id)}
            >
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
      {!!notificationDigestToOpen && (
        <DigestNotificationDrawer
          notification={notificationDigestToOpen}
          open={!!notificationDigestToOpen}
          onClose={() => {
            setNotificationDigestToOpen(undefined);
          }}
        />
      )}
    </div>
  );
};

export default Notifications;
