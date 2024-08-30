import React from 'react';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import MoreVert from '@mui/icons-material/MoreVert';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { useFormatter } from '../../../components/i18n';
import WorkspacePopover from './WorkspacePopover';
import ItemIcon from '../../../components/ItemIcon';
import Security from '../../../utils/Security';
import { EXPLORE, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import ItemBoolean from '../../../components/ItemBoolean';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
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
    color: theme.palette.grey[700],
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    marginRight: 7,
    borderRadius: 10,
    width: 90,
  },
}));

const WorkspaceLineComponent = ({ dataColumns, node, paginationOptions }) => {
  const classes = useStyles();
  const { fd, t_i18n } = useFormatter();

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/workspaces/${node.type}s/${node.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        {node.type === 'dashboard' ? (
          <ItemIcon type="Dashboard" />
        ) : (
          <ItemIcon type="Investigation" />
        )}
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {node.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.tags.width }}
            >
              {node.tags
                && node.tags.map((tag) => (
                  <Chip className={classes.chip} key={tag} label={tag} />
                ))}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.creator.width }}
            >
              {node.owner?.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.updated_at.width }}
            >
              {fd(node.updated_at)}
            </div>
            {node.type === 'dashboard' && (
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.isShared.width }}
              >
                <ItemBoolean
                  status={node.isShared}
                  label={node.isShared ? t_i18n('Yes') : t_i18n('No')}
                  variant="inList"
                />
              </div>
            )}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <Security needs={node.type === 'dashboard' ? [EXPLORE] : [INVESTIGATION_INUPDATE]}>
          <WorkspacePopover
            workspace={node}
            paginationOptions={paginationOptions}
          />
        </Security>
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const workspaceLineFragment = graphql`
  fragment WorkspaceLine_node on Workspace {
    id
    name
    tags
    created_at
    updated_at
    type
    manifest
    isShared
    entity_type
    owner {
      id
      name
      entity_type
    }
    currentUserAccessRight
  }
`;

export const WorkspaceLine = createFragmentContainer(WorkspaceLineComponent, {
  node: workspaceLineFragment,
});

export const WorkspaceLineDummy = ({ dataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.tags.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.creator.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.updated_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <IconButton disabled={true} size="large">
          <MoreVert />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
