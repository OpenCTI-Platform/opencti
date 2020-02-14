import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert, Person, PermIdentity } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import UserPopover from './UserPopover';

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
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
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

class UserLineComponent extends Component {
  render() {
    const {
      fd, classes, dataColumns, node, paginationOptions,
    } = this.props;
    const external = node.external === true;
    return (
      <ListItem classes={{ root: classes.item }} divider={true} button={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          {external ? <PermIdentity /> : <Person />}
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
                style={{ width: dataColumns.user_email.width }}
              >
                {node.user_email}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.firstname.width }}
              >
                {node.firstname}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.lastname.width }}
              >
                {node.lastname}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <UserPopover userId={node.id} paginationOptions={paginationOptions} />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

UserLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const UserLineFragment = createFragmentContainer(UserLineComponent, {
  node: graphql`
    fragment UserLine_node on User {
      id
      name
      user_email
      firstname
      external
      lastname
      created
    }
  `,
});

export const UserLine = compose(
  inject18n,
  withStyles(styles),
)(UserLineFragment);

class UserLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Person />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.user_email.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.firstname.width }}
              >
                <div className="fakeItem" style={{ width: '60%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.lastname.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
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

UserLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const UserLineDummy = compose(
  inject18n,
  withStyles(styles),
)(UserLineDummyComponent);
