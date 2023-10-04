import React, { Component, FunctionComponent, useState } from 'react';
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
  Security, MoreVertOutlined, AdminPanelSettingsOutlined,
} from '@mui/icons-material';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { SettingsOrganizationUserLine_node$key } from '@components/settings/users/__generated__/SettingsOrganizationUserLine_node.graphql';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { externalReferenceEditionOverviewFocus } from '@components/analyses/external_references/ExternalReferenceEditionOverview';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import inject18n, { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
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
  ) {
    organizationAdminAdd(id: $id, memberId: $memberId) {
      id
      authorized_authorities
    }
  }
`;
export const organizationMutationAdminRemove = graphql`
  mutation SettingsOrganizationUserLineAdminRemoveMutation(
    $id: ID!
    $memberId: String!
  ) {
    organizationAdminRemove(id: $id, memberId: $memberId) {
      id
      authorized_authorities
    }
  }
`;

interface SettingsOrganizationUserLineComponentProps {
  dataColumns: DataColumns;
  node: SettingsOrganizationUserLine_node$key;
  organizationId: string;
}

export const SettingsOrganizationUserLine: FunctionComponent<SettingsOrganizationUserLineComponentProps> = ({ dataColumns, node, organizationId }) => {
  const classes = useStyles();
  const { fd, t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);

  const data = useFragment(UserLineFragment, node);
  const { me } = useAuth();
  const memberIsOrganizationAdmin = data.administrated_organizations?.length > 0;
  const userIsOrganizationAdmin = me.administrated_organizations.map((orga) => orga?.id).includes(organizationId);
  const userCapabilities = (me.capabilities ?? []).map((c) => c.name);
  const userHasSettingsAcesses = userCapabilities.includes(SETTINGS_SETACCESSES) || userCapabilities.includes(BYPASS);
  const external = data.external === true;

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  function promoteMember() {
    commitMutation({
      mutation: organizationMutationAdminAdd,
      variables: {
        id: organizationId,
        memberId: data.id,
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
    handleClose();
  }

  function demoteMember() {
    commitMutation({
      mutation: organizationMutationAdminRemove,
      variables: {
        id: organizationId,
        memberId: data.id,
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
    handleClose();
  }

  function removeMemberFromOrganization() {
    handleClose();
  }
  function editMember() {
    handleClose();
  }

  return (
    <ListItem>
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/settings/accesses/users/${data.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          {external ? <AccountCircleOutlined /> : (memberIsOrganizationAdmin ? <AdminPanelSettingsOutlined/> : <PersonOutlined />)}
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
      </ListItem>
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          {userHasSettingsAcesses && (
            memberIsOrganizationAdmin
              ? <MenuItem onClick={demoteMember}>{t('Demote as simple member')}</MenuItem>
              : <MenuItem onClick={promoteMember}>{t('Promote as Organization Admin')}</MenuItem>
            )
          }
          {(userIsOrganizationAdmin || userHasSettingsAcesses) &&
            <MenuItem onClick={editMember}>{t('Edit Member')}</MenuItem>
          }

          {(userIsOrganizationAdmin || userHasSettingsAcesses) && !memberIsOrganizationAdmin &&
              <MenuItem onClick={removeMemberFromOrganization}>{t('Remove from the Organization')}</MenuItem>
          }

        </Menu>
      </ListItemIcon>
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
