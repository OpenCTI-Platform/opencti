import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  KeyboardArrowRightOutlined,
  WorkOutlineOutlined,
} from '@mui/icons-material';
import { compose } from 'ramda';
import Chip from '@mui/material/Chip';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
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
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
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
});

class WorkspaceLineComponent extends Component {
  render() {
    const { fd, classes, dataColumns, node } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/workspaces/${node.type}s/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <WorkOutlineOutlined />
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
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

WorkspaceLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const WorkspaceLineFragment = createFragmentContainer(WorkspaceLineComponent, {
  node: graphql`
    fragment WorkspaceLine_node on Workspace {
      id
      name
      tags
      created_at
      updated_at
      type
      owner {
        id
        name
      }
    }
  `,
});

export const WorkspaceLine = compose(
  inject18n,
  withStyles(styles),
)(WorkspaceLineFragment);

class WorkspaceLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
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
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

WorkspaceLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const WorkspaceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(WorkspaceLineDummyComponent);
