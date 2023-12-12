import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { AccountCircleOutlined, AdminPanelSettingsOutlined, KeyboardArrowRightOutlined, PersonOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { SettingsOrganizationUserLine_node$key } from '@components/settings/users/__generated__/SettingsOrganizationUserLine_node.graphql';
import { ListItemSecondaryAction } from '@mui/material';
import Tooltip from '@mui/material/Tooltip';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

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
    administrated_organizations {
      id
      name
      authorized_authorities
    }
  }
`;

interface SettingsOrganizationUserLineComponentProps {
  dataColumns: DataColumns
  node: SettingsOrganizationUserLine_node$key
  entityId: string
}

export const SettingsOrganizationUserLine: FunctionComponent<SettingsOrganizationUserLineComponentProps> = ({ dataColumns, node, entityId: organizationId }) => {
  const classes = useStyles();
  const { fd, t } = useFormatter();

  const user = useFragment(UserLineFragment, node);
  const memberIsOrganizationAdmin = (user.administrated_organizations ?? []).map(({ id }) => id).includes(organizationId);
  const external = user.external === true;

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/settings/accesses/users/${user.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        {external && <AccountCircleOutlined />}
        {!external && (memberIsOrganizationAdmin ? <Tooltip title={t('Organization administrator')}><AdminPanelSettingsOutlined color="success" /></Tooltip> : <Tooltip title={t('Member')}><PersonOutlined /></Tooltip>)}
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
                {value.render?.(user, { fd })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <KeyboardArrowRightOutlined />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

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
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
