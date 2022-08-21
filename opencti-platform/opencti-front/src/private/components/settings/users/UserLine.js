import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  PersonOutlined,
  PermIdentityOutlined,
  KeyboardArrowRightOutlined,
  HorizontalRule,
  Security,
} from '@mui/icons-material';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';

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

class UserLineComponent extends Component {
  render() {
    const { fd, classes, dataColumns, node } = this.props;
    const external = node.external === true;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/settings/accesses/users/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          {external ? <PermIdentityOutlined /> : <PersonOutlined />}
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
                style={{ width: dataColumns.otp.width }}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  {node.otp_activated ? (
                    <Security fontSize="small" />
                  ) : (
                    <HorizontalRule fontSize="small" />
                  )}
                </ListItemIcon>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
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
      otp_activated
      created_at
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
                style={{ width: dataColumns.user_email.width }}
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
                style={{ width: dataColumns.firstname.width }}
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
                style={{ width: dataColumns.lastname.width }}
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
                style={{ width: dataColumns.otp.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={40}
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
                  width={100}
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

UserLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const UserLineDummy = compose(
  inject18n,
  withStyles(styles),
)(UserLineDummyComponent);
