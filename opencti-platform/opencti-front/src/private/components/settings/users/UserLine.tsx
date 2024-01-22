import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { PersonOutlined, AccountCircleOutlined, KeyboardArrowRightOutlined, HorizontalRule, Security, ReportGmailerrorred } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { UserLine_node$data } from '@components/settings/users/__generated__/UserLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';

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
}));

interface UserLineComponentProps {
  dataColumns: DataColumns,
  node: UserLine_node$data,
}

const UserLineComponent: React.FC<UserLineComponentProps> = (props) => {
  const { dataColumns, node } = props;
  const external = node.external === true;

  const classes = useStyles();
  const { t_i18n, fd } = useFormatter();

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/settings/accesses/users/${node.id}`}
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
              style={{ width: dataColumns.effective_confidence_level.width }}
            >
              {node.effective_confidence_level?.max_confidence ?? (
                <Tooltip
                  title={t_i18n("No confidence level found in this user's groups and organizations, and no confidence level defined at the user level.")}
                >
                  <ReportGmailerrorred color={'error'}/>
                </Tooltip>
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.otp.width }}
            >
              {node.otp_activated ? (
                <Security fontSize="small" color="secondary"/>
              ) : (
                <HorizontalRule fontSize="small" color="primary"/>
              )}
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
        <KeyboardArrowRightOutlined/>
      </ListItemIcon>
    </ListItem>
  );
};

export const UserLine = createFragmentContainer(UserLineComponent, {
  node: graphql`
    fragment UserLine_node on User {
      id
      name
      user_email
      firstname
      external
      lastname
      effective_confidence_level {
        max_confidence 
      }
      otp_activated
      created_at
    }
  `,
});

export const UserLineDummy: React.FC<Pick<UserLineComponentProps, 'dataColumns'>> = (props) => {
  const { dataColumns } = props;

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
              style={{ width: dataColumns.effective_confidence_level.width }}
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
        <KeyboardArrowRightOutlined/>
      </ListItemIcon>
    </ListItem>
  );
};
