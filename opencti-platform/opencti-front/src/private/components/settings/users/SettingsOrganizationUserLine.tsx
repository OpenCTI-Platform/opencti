import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { AccountCircleOutlined, AdminPanelSettingsOutlined, KeyboardArrowRightOutlined, MoreVertOutlined, PersonOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { SettingsOrganizationUserLine_node$key } from '@components/settings/users/__generated__/SettingsOrganizationUserLine_node.graphql';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { ListItemSecondaryAction } from '@mui/material';
import { SettingsOrganization_organization$data } from '@components/settings/organizations/__generated__/SettingsOrganization_organization.graphql';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { BYPASS, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';

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
export const organizationMutationAdminAdd = graphql`
  mutation SettingsOrganizationUserLineAdminAddMutation(
    $id: ID!
    $memberId: String!
    $userEmail: String!
  ) {
    organizationAdminAdd(id: $id, memberId: $memberId) {
      id
      members (filters: [{ key: user_email, values: [$userEmail] }] ) {
        edges {
          node {
            id
            ...SettingsOrganizationUserLine_node
          }
        }
      }
    }
  }
`;
export const organizationMutationAdminRemove = graphql`
  mutation SettingsOrganizationUserLineAdminRemoveMutation(
    $id: ID!
    $memberId: String!
    $userEmail: String!
  ) {
    organizationAdminRemove(id: $id, memberId: $memberId) {
      id
      members (filters: [{ key: user_email, values: [$userEmail] }] ) {
        edges {
          node {
            id
            ...SettingsOrganizationUserLine_node
          }
        }
      }
    }
  }
`;

interface SettingsOrganizationUserLineComponentProps {
  dataColumns: DataColumns
  node: SettingsOrganizationUserLine_node$key
  organization: SettingsOrganization_organization$data
}

export const SettingsOrganizationUserLine: FunctionComponent<SettingsOrganizationUserLineComponentProps> = ({ dataColumns, node, organization }) => {
  const classes = useStyles();
  const { fd, t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);

  const user = useFragment(UserLineFragment, node);
  const { me } = useAuth();
  const memberIsOrganizationAdmin = (user.administrated_organizations ?? []).map(({ id }) => id).includes(organization.id);
  const userCapabilities = (me.capabilities ?? []).map((c) => c.name);
  const userHasSettingsAcesses = userCapabilities.includes(SETTINGS_SETACCESSES) || userCapabilities.includes(BYPASS);
  const external = user.external === true;

  const [promoteMemberMutation] = useMutation(organizationMutationAdminAdd);
  const [demoteMemberMutation] = useMutation(organizationMutationAdminRemove);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  const promoteMember = () => {
    promoteMemberMutation({
      variables: {
        id: organization.id,
        memberId: user.id,
        userEmail: user.user_email,
      },
      onCompleted: handleClose,
    });
  };

  const demoteMember = () => {
    demoteMemberMutation({
      variables: {
        id: organization.id,
        memberId: user.id,
        userEmail: user.user_email,
      },
      onCompleted: handleClose,
    });
  };

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
        {!external && (memberIsOrganizationAdmin ? <AdminPanelSettingsOutlined color="success" /> : <PersonOutlined />)}
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
        {userHasSettingsAcesses
          ? (
            <>
              <IconButton
                onClick={handleOpen}
                aria-haspopup="true"
                style={{ marginTop: 3 }}
                size="large"
              >
                <MoreVertOutlined />
              </IconButton>
              <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
                {memberIsOrganizationAdmin
                  ? <MenuItem onClick={demoteMember}>{t('Demote as simple member')}</MenuItem>
                  : <MenuItem onClick={promoteMember}>{t('Promote as Organization Admin')}</MenuItem>
                }
              </Menu>
            </>
          ) : <KeyboardArrowRightOutlined />
        }
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
