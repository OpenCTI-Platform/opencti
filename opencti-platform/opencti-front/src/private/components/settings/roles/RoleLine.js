import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { KeyboardArrowRightOutlined, Security } from '@mui/icons-material';
import { compose } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router-dom';
import inject18n from '../../../../components/i18n';
import { groupsSearchQuery } from '../Groups';
import { QueryRenderer } from '../../../../relay/environment';

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
});

class RoleLineComponent extends Component {
  render() {
    const { fd, classes, dataColumns, node } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/settings/accesses/roles/${node.id}`}
      >
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
              <QueryRenderer
                query={groupsSearchQuery}
                variables={{
                  count: 50,
                  orderBy: 'name',
                  orderMode: 'asc',
                }}
                render={({ props }) => {
                  if (props) {
                    const groupIds = props.groups.edges
                      .map((group) => (((group.node.roles
                        .map((role) => role.id)).includes(node.id)) ? group.node.id : null));
                    const numberOfGroups = groupIds.filter((id) => id !== null).length;
                    return (
                      <div
                        className={classes.bodyItem}
                        style={{ width: dataColumns.groups.width }}
                      >
                        {numberOfGroups}
                      </div>
                    );
                  }
                  return (
                    <div
                      className={classes.bodyItem}
                      style={{ width: dataColumns.groups.width }}
                    >
                    </div>
                  );
                }}
              />
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
                style={{ width: dataColumns.groups.width }}
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
          <KeyboardArrowRightOutlined />
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
