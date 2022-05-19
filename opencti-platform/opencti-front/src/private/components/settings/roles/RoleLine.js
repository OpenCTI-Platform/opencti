import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert, Security, Check } from '@mui/icons-material';
import { compose } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import RolePopover from './RolePopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
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
});

class RoleLineComponent extends Component {
  render() {
    const { fd, classes, dataColumns, node, paginationOptions } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true} button={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Security />
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
                style={{ width: dataColumns.default_assignation.width }}
              >
                {node.default_assignation ? <Check /> : '-'}
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
        <ListItemSecondaryAction>
          <RolePopover roleId={node.id} paginationOptions={paginationOptions} />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

RoleLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const RoleLineFragment = createFragmentContainer(RoleLineComponent, {
  node: graphql`
    fragment RoleLine_node on Role {
      id
      name
      default_assignation
      created_at
      updated_at
    }
  `,
});

export const RoleLine = compose(
  inject18n,
  withStyles(styles),
)(RoleLineFragment);

class RoleLineDummyComponent extends Component {
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
                style={{ width: dataColumns.default_assignation.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={80}
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
                  width={80}
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
                  width={80}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

RoleLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const RoleLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RoleLineDummyComponent);
