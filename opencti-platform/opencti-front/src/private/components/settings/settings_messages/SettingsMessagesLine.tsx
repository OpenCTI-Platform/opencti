import { MessageOutlined, MoreVert } from '@mui/icons-material';
import { ListItemSecondaryAction } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { makeStyles } from '@mui/styles';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import IconButton from '@mui/material/IconButton';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import { SettingsMessagesLine_settingsMessage$key } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import SettingsMessagesPopover from './SettingsMessagesPopover';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: theme.spacing(1),
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    fontSize: theme.typography.h3.fontSize,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: theme.spacing(1),
  },
  goIcon: {
    position: 'absolute',
    right: theme.spacing(-1.5),
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

const settingsMessageFragment = graphql`
  fragment SettingsMessagesLine_settingsMessage on SettingsMessage {
    id
    message
    activated
    dismissible
    updated_at
    color
  }
`;

const SettingsMessagesLine = ({
  entityId,
  node,
  dataColumns,
}: {
  entityId: string;
  node: SettingsMessagesLine_settingsMessage$key;
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();

  const message = useFragment(settingsMessageFragment, node);

  if (!node || !message) {
    return <ErrorNotFound />;
  }

  return (
    <ListItem key={message.id} divider={true} classes={{ root: classes.item }}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <MessageOutlined />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns ?? {}).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(message)}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <SettingsMessagesPopover settingsId={entityId} message={message} />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export default SettingsMessagesLine;

export const SettingsMessagesLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem divider={true} classes={{ root: classes.item }}>
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
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <IconButton disabled={true} aria-haspopup="true" size="large">
          <MoreVert />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
