import React, { FunctionComponent, useState } from 'react';
import { Link } from 'react-router-dom';
import Badge from '@mui/material/Badge';
import Tooltip from '@mui/material/Tooltip';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { BellCogOutline, BellOutline, BellPlusOutline, BellRemoveOutline, FileTableBoxMultipleOutline } from 'mdi-material-ui';
import { CheckCircleOutlined, DeleteOutlined, UnpublishedOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import Checkbox from '@mui/material/Checkbox';
import { deepPurple, green, indigo, red } from '@mui/material/colors';
import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import Chip from '@mui/material/Chip';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import DialogContentText from '@mui/material/DialogContentText';
import { DataColumns } from '../../../../components/list_lines';
import { NotificationLine_node$data, NotificationLine_node$key } from './__generated__/NotificationLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';
import { NotificationsLinesPaginationQuery$variables } from './__generated__/NotificationsLinesPaginationQuery.graphql';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { isNotEmptyField } from '../../../../utils/utils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 100,
    marginRight: 10,
  },
  chipInList2: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 150,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

export const notificationLineNotificationMarkReadMutation = graphql`
  mutation NotificationLineNotificationMarkReadMutation(
    $id: ID!
    $read: Boolean!
  ) {
    notificationMarkRead(id: $id, read: $read) {
      ...NotificationLine_node
    }
  }
`;

const notificationLineNotificationDeleteMutation = graphql`
  mutation NotificationLineNotificationDeleteMutation($id: ID!) {
    notificationDelete(id: $id)
  }
`;

interface NotificationLineProps {
  node: NotificationLine_node$key;
  dataColumns: DataColumns;
  paginationOptions?: NotificationsLinesPaginationQuery$variables;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
  selectedElements: Record<string, NotificationLine_node$data>;
  deSelectedElements: Record<string, NotificationLine_node$data>;
  onToggleEntity: (
    entity: NotificationLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: NotificationLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  index: number;
}

const notificationLineFragment = graphql`
  fragment NotificationLine_node on Notification {
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

export const NotificationLineComponent: FunctionComponent<
NotificationLineProps
> = ({
  dataColumns,
  node,
  selectedElements,
  deSelectedElements,
  onToggleEntity,
  selectAll,
  onToggleShiftEntity,
  index,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [updating, setUpdating] = useState<boolean>(false);
  const data = useFragment(notificationLineFragment, node);
  const events = data.notification_content.map((n) => n.events).flat();
  const isDigest = data.notification_type === 'digest';
  const firstEvent = events.at(0);
  const [commitMarkRead] = useApiMutation(
    notificationLineNotificationMarkReadMutation,
  );
  const [commitDelete] = useApiMutation(
    notificationLineNotificationDeleteMutation,
  );
  const [displayDelete, setDisplayDelete] = useState(false);
  const handleRead = (read: boolean) => {
    setUpdating(true);
    return commitMarkRead({
      variables: {
        id: data.id,
        read,
      },
      onCompleted: () => {
        setUpdating(false);
      },
    });
  };
  const handleDelete = () => {
    setUpdating(true);
    return commitDelete({
      variables: {
        id: data.id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_myNotifications', paginationOptions, data.id);
      },
      onCompleted: () => {
        setUpdating(false);
      },
    });
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
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
  const iconSelector = (operation: string) => {
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
  const firstOperation = isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
  const isLinkAvailable = events.length === 1 && isNotEmptyField(firstEvent?.instance_id) && firstOperation !== 'delete';
  const isClickableLine = isDigest || isLinkAvailable;
  return (
    <div>
      {/* eslint-disable-next-line @typescript-eslint/ban-ts-comment */}
      {/* @ts-ignore */}
      <ListItem classes={{ root: classes.item }} divider={true} button={isClickableLine}
        component={isLinkAvailable ? Link : 'div'}
        to={isLinkAvailable ? `/dashboard/id/${firstEvent?.instance_id}` : undefined}
        onClick={() => { if (isDigest) { setOpen(true); } }}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }} style={{ minWidth: 40 }}
          onClick={(event) => (event.shiftKey ? onToggleShiftEntity(index, data, event) : onToggleEntity(data, event))}
        >
          <Checkbox edge="start"
            checked={(selectAll && !(data.id in (deSelectedElements || {}))) || data.id in (selectedElements || {})}
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Badge color="warning" variant="dot" invisible={data.is_read}>
            {iconSelector(firstOperation)}
          </Badge>
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={{ width: dataColumns.operation.width }}>
                <Chip
                  classes={{ root: classes.chipInList2 }}
                  style={{
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
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.message.width }}>
                {events.length > 1 ? (
                  <i>{t_i18n('Digest with multiple notifiers')}</i>
                ) : (
                  <MarkdownDisplay content={firstEvent?.message ?? '-'} remarkGfmPlugin={true} commonmark={true}/>
                )}
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.created.width }}>
                {fldt(data.created)}
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
                <Tooltip title={data.name}>
                  <Chip
                    classes={{ root: classes.chipInList }}
                    color={
                      data.notification_type === 'live'
                        ? 'warning'
                        : 'secondary'
                    }
                    variant="outlined"
                    label={data.name}
                  />
                </Tooltip>
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <IconButton
            disabled={updating}
            onClick={() => handleRead(!data.is_read)}
            size="large"
            color={data.is_read ? 'success' : 'warning'}
          >
            {data.is_read ? <CheckCircleOutlined /> : <UnpublishedOutlined />}
          </IconButton>
          <Tooltip title={t_i18n('Delete this notification')}>
            <span>
              <IconButton
                disabled={updating}
                onClick={() => handleOpenDelete()}
                size="large"
                color="primary"
              >
                <DeleteOutlined/>
              </IconButton>
            </span>
          </Tooltip>
        </ListItemSecondaryAction>
      </ListItem>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
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
            onClick={handleDelete}
            color="secondary"
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={open}
        TransitionComponent={Transition}
        PaperProps={{ elevation: 1 }}
        fullWidth={true}
        maxWidth="md"
        onClose={() => setOpen(false)}
      >
        <DialogTitle>{data.name}</DialogTitle>
        <DialogContent>
          <List component="div" disablePadding>
            {events.map((event, i) => (
              <ListItemButton key={i} divider={true} component={Link} to={`/dashboard/id/${event.instance_id}`}>
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <Badge color="warning" variant="dot" invisible={data.is_read}>
                    {iconSelector(event.operation ?? 'none')}
                  </Badge>
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div className={classes.bodyItem} style={{ width: '30%' }}>
                        <Chip
                          classes={{ root: classes.chipInList }}
                          color="primary"
                          variant="outlined"
                          label={eventTypes[event.operation ?? 'none']}
                        />
                      </div>
                      <div className={classes.bodyItem} style={{ width: '70%' }}>
                        {event.message}
                      </div>
                    </div>
                  }
                />
              </ListItemButton>
            ))}
          </List>
          <DialogActions>
            <Button onClick={() => setOpen(false)}>{t_i18n('Close')}</Button>
          </DialogActions>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export const NotificationLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
    </ListItem>
  );
};
