import React, { Component, FunctionComponent } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer, useFragment } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  PersonOutlined,
  AccountCircleOutlined,
  KeyboardArrowRightOutlined,
  HorizontalRule,
  Security, MoreVertOutlined,
} from '@mui/icons-material';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import inject18n, { useFormatter } from '../../../../components/i18n';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import { SettingsOrganizationUserLine_node$key } from '@components/settings/users/__generated__/SettingsOrganizationUserLine_node.graphql';

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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

interface SettingsOrganizationUserLineComponentProps {
  dataColumns: DataColumns;
  node: SettingsOrganizationUserLine_node$key;
  isOrganizationAdmin: boolean;
}

export const SettingsOrganizationUserLine: FunctionComponent<SettingsOrganizationUserLineComponentProps> = ({dataColumns, node, isOrganizationAdmin}) => {
  const classes = useStyles();
  const { fd } = useFormatter();

  const data = useFragment(UserLineFragment, node);
  const external = data.external === true;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={isOrganizationAdmin ? 'div' : Link}
      to={isOrganizationAdmin ? undefined : `/dashboard/settings/accesses/users/${data.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        {external ? <AccountCircleOutlined /> : <PersonOutlined />}
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.user_email.width }}
            >
              {data.user_email}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.firstname.width }}
            >
              {data.firstname}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.lastname.width }}
            >
              {data.lastname}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.otp.width }}
            >
              {data.otp_activated ? (
                <Security fontSize="small" color="secondary" />
              ) : (
                <HorizontalRule fontSize="small" color="primary" />
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(data.created_at)}
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        { isOrganizationAdmin ?
        <KeyboardArrowRightOutlined />
          :
          <MoreVertOutlined/>
        }
      </ListItemIcon>
    </ListItem>
  );
}



const UserLineFragment = graphql`
    fragment SettingsOrganizationUserLine_node on User {
      id
      name
      user_email
      firstname
      external
      lastname
      otp_activated
      created_at
    }
  `;

export const SettingsOrganizationUserLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
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
};
