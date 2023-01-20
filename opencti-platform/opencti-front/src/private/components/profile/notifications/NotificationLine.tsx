import React, { FunctionComponent, useState } from 'react';
import { Link } from 'react-router-dom';
import Badge from '@mui/material/Badge';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  BellPlusOutline,
  BellRemoveOutline,
  BellCogOutline,
  BellOutline,
  FileTableBoxMultipleOutline,
} from 'mdi-material-ui';
import {
  CheckCircleOutlined,
  UnpublishedOutlined,
  DeleteOutlined,
} from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment, useMutation } from 'react-relay';
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
import { DataColumns } from '../../../../components/list_lines';
import {
  NotificationLine_node$data,
  NotificationLine_node$key,
} from './__generated__/NotificationLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';
import { NotificationsLinesPaginationQuery$variables } from './__generated__/NotificationsLinesPaginationQuery.graphql';

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
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
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
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

const notificationLineNotificationMarkReadMutation = graphql`
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
    content {
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
  const { t, fldt } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [updating, setUpdating] = useState<boolean>(false);
  const data = useFragment(notificationLineFragment, node);
  const events = data.content.map((n) => n.events).flat();
  const firstEvent = events.at(0);
  const [commitMarkRead] = useMutation(
    notificationLineNotificationMarkReadMutation,
  );
  const [commitDelete] = useMutation(
    notificationLineNotificationDeleteMutation,
  );
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
        deleteNode(
          store,
          'Pagination_myNotifications',
          paginationOptions,
          data.id,
        );
      },
      onCompleted: () => {
        setUpdating(false);
      },
    });
  };
  const eventTypes: Record<string, string> = {
    create: t('Creation'),
    update: t('Modification'),
    delete: t('Deletion'),
    none: t('Unknown'),
  };
  const colors: Record<string, string> = {
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
  const firstOperation = events.length > 1 ? 'multiple' : firstEvent?.operation ?? 'none';
  return (
    <div>
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={events.length > 1 ? 'div' : Link}
        to={
          events.length > 1
            ? undefined
            : `/dashboard/id/${firstEvent?.instance_id}`
        }
        onClick={() => setOpen(true)}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={(event) => (event.shiftKey
            ? onToggleShiftEntity(index, data, event)
            : onToggleEntity(data, event))
          }
        >
          <Checkbox
            edge="start"
            checked={
              (selectAll && !(data.id in (deSelectedElements || {})))
              || data.id in (selectedElements || {})
            }
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
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.operation.width }}
              >
                <Chip
                  classes={{ root: classes.chipInList2 }}
                  style={{
                    backgroundColor: hexToRGB(colors[firstOperation], 0.08),
                    color: colors[firstOperation],
                    border: `1px solid ${colors[firstOperation]}`,
                  }}
                  label={
                    events.length > 1
                      ? t('Multiple')
                      : eventTypes[firstEvent?.operation ?? 'none']
                  }
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.message.width }}
              >
                {events.length > 1 ? (
                  <i>{t('Digest with multiple notifications')}</i>
                ) : (
                  firstEvent?.message
                )}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fldt(data.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Chip
                  classes={{ root: classes.chipInList }}
                  color={
                    data.notification_type === 'live' ? 'warning' : 'secondary'
                  }
                  variant="outlined"
                  label={data.name}
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <IconButton
            disabled={updating}
            onClick={() => handleRead(!data.is_read)}
            size="large"
            color={data.is_read ? 'warning' : 'success'}
          >
            {data.is_read ? <UnpublishedOutlined /> : <CheckCircleOutlined />}
          </IconButton>
          <IconButton
            disabled={updating}
            onClick={() => handleDelete()}
            size="large"
            color="primary"
          >
            <DeleteOutlined />
          </IconButton>
        </ListItemSecondaryAction>
      </ListItem>
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
              <ListItemButton
                key={i}
                component={Link}
                divider={true}
                to={`/dashboard/id/${event.instance_id}`}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <Badge color="warning" variant="dot" invisible={data.is_read}>
                    {iconSelector(event.operation ?? 'none')}
                  </Badge>
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={{ width: '30%' }}
                      >
                        <Chip
                          classes={{ root: classes.chipInList }}
                          color="primary"
                          variant="outlined"
                          label={eventTypes[event.operation ?? 'none']}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={{ width: '70%' }}
                      >
                        {event.message}
                      </div>
                    </div>
                  }
                />
              </ListItemButton>
            ))}
          </List>
          <DialogActions>
            <Button onClick={() => setOpen(false)}>{t('Close')}</Button>
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
