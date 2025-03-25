import React, { FunctionComponent, useState } from 'react';
import { NotificationsLines_data$data } from '@components/profile/notifications/__generated__/NotificationsLines_data.graphql';
import { notificationLineFragment } from '@components/profile/notifications/NotificationLine';
import { Badge, Tooltip } from '@mui/material';
import Chip from '@mui/material/Chip';
import { deepPurple, green, indigo, red } from '@mui/material/colors';
import { BellCogOutline, BellOutline, BellPlusOutline, BellRemoveOutline, FileTableBoxMultipleOutline } from 'mdi-material-ui';
import { NotificationLine_node$data } from '@components/profile/notifications/__generated__/NotificationLine_node.graphql';
import IconButton from '@mui/material/IconButton';
import { CheckCircleOutlined, DeleteOutlined, UnpublishedOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Button from '@mui/material/Button';
import DialogActions from '@mui/material/DialogActions';
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
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Transition from '../../../components/Transition';
import { deleteNode } from '../../../utils/store';

export const LOCAL_STORAGE_KEY = 'notifiers';

export const notificationLineNotificationMarkReadMutation = graphql`
  mutation NotificationsNotificationMarkReadMutation(
    $id: ID!
    $read: Boolean!
  ) {
    notificationMarkRead(id: $id, read: $read) {
      ...NotificationLine_node
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
  setTitle(t_i18n('Notifications'));
  const {
    me,
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
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

  const [commitMarkRead] = useApiMutation(
    notificationLineNotificationMarkReadMutation,
  );
  const [commitDelete] = useApiMutation(
    notificationLineNotificationDeleteMutation,
  );
  // const [displayDelete, setDisplayDelete] = useState(false);
  // const [open, setOpen] = useState<boolean>(false);
  const [notificationToDelete, setNotificationToDelete] = useState<NotificationLine_node$data>();
  const handleCloseDelete = () => {
    setNotificationToDelete(undefined);
  };
  const handleDelete = (id: string) => {
    return commitDelete({
      variables: {
        id,
      },
      updater: (store) => {
        console.log({ store, id });
        deleteNode(store, 'Pagination_myNotifications', queryPaginationOptions, id);
      },
      onCompleted: () => {
        handleCloseDelete();
      },
    });
  };
  const colors: Record<string, string> = {
    none: green[500],
    create: green[500],
    update: deepPurple[500],
    delete: red[500],
    multiple: indigo[500],
  };
  const getFirstOperation = ({ notification_content, notification_type }: Pick<NotificationLine_node$data, 'notification_content' | 'notification_type'>) => {
    const events = notification_content.map((n: any) => n.events).flat();
    const firstEvent = events.at(0);
    const isDigest = notification_type === 'digest';
    return isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
  };
  const iconSelector = (notification: NotificationLine_node$data) => {
    const operation = getFirstOperation(notification);
    switch (operation) {
      case 'create':
        return <BellPlusOutline style={{ color: colors[operation] }} />;
      case 'update':
        return <BellCogOutline style={{ color: colors[operation] }} />;
      case 'delete':
        return <BellRemoveOutline style={{ color: colors[operation] }} />;
      case 'multiple':
        return (
          <FileTableBoxMultipleOutline style={{ color: colors[operation] }} />
        );
      default:
        return <BellOutline style={{ color: colors[operation] }} />;
    }
  };
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    operation: {
      label: 'Operation',
      percentWidth: 20,
      isSortable: isRuntimeSort,
      render: ({ notification_content, notification_type }: NotificationLine_node$data) => {
        const firstOperation = getFirstOperation({ notification_content, notification_type });
        const events = notification_content.map((n) => n.events).flat();
        const eventTypes: Record<string, string> = {
          create: t_i18n('Creation'),
          update: t_i18n('Modification'),
          delete: t_i18n('Deletion'),
          none: t_i18n('Unknown'),
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
                : (eventTypes[firstOperation] ?? firstOperation)
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
      // render: ({ notification_content }) => {
      //   console.log('NOTIFICATION', fldt(notification_content));
      //   return (<div style={{ height: 20,
      //     fontSize: 13,
      //     float: 'left',
      //     whiteSpace: 'nowrap',
      //     overflow: 'hidden',
      //     textOverflow: 'ellipsis',
      //     paddingRight: 10 }}
      //           >
      //     {fldt(notification_content.map((n: any) => n.creationDate))}
      //   </div>);
      // },
    },
    name: {
      label: 'Trigger name',
      percentWidth: 12,
      isSortable: isRuntimeSort,
      // render: ({ notification_content }) => {
      //   <div style={{ height: 20,
      //     fontSize: 13,
      //     float: 'left',
      //     whiteSpace: 'nowrap',
      //     overflow: 'hidden',
      //     textOverflow: 'ellipsis',
      //     paddingRight: 10 }}
      //   >
      //     <Tooltip title={data.name}>
      //       <Chip
      //         style={{     fontSize: 12,
      //           height: 20,
      //           float: 'left',
      //           width: 100,
      //           marginRight: 10,}
      //         color={
      //           data.notification_type === 'live'
      //             ? 'warning'
      //             : 'secondary'
      //         }
      //         variant="outlined"
      //         label={data.name}
      //         onClick={(e) => {
      //           e.preventDefault();
      //           e.stopPropagation();
      //           onLabelClick('name', data.name, 'eq', e);
      //         }}
      //       />
      //     </Tooltip>
      //   </div>;
      // },
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

  const renderActions = (data: NotificationLine_node$data) => {
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
      <div style={{ marginLeft: -30 }}>
        <IconButton
          disabled={updating}
          onClick={(event) => {
            event.stopPropagation();
            event.preventDefault();
            handleRead(data.id, !data.is_read);
          }}
          size="small"
          color={data.is_read ? 'success' : 'warning'}
        >
          {data.is_read ? <CheckCircleOutlined /> : <UnpublishedOutlined />}
        </IconButton>
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
              <DeleteOutlined/>
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
        icon={ (data) => (
          <Badge color="warning" variant="dot" invisible={data.is_read}>
            {iconSelector(data)}
          </Badge>
        )}
        lineFragment={notificationLineFragment}
        toolbarFilters={contextFilters}
        exportContext={{ entity_type: 'Notification' }}
        availableEntityTypes={['Notification']}
        actions={renderActions}
      />
      )}
      {notificationToDelete && (
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={notificationToDelete}
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this notification?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseDelete}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={() => handleDelete(notificationToDelete.id)}
              color="secondary"
            >
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>)}
    </div>
  );
};

export default Notifications;
