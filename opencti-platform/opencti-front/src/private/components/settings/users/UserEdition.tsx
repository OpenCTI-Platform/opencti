import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import UserEditionOrganizationsAdmin from '@components/settings/users/UserEditionOrganizationsAdmin';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import UserEditionOverview from './UserEditionOverview';
import UserEditionPassword from './UserEditionPassword';
import UserEditionGroups from './UserEditionGroups';
import { useFormatter } from '../../../../components/i18n';
import { UserEdition_user$data } from './__generated__/UserEdition_user.graphql';
import { Theme } from '../../../../components/Theme';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

interface UserEditionProps {
  handleClose: () => void,
  user: UserEdition_user$data,
}

const UserEdition: FunctionComponent<UserEditionProps> = ({ handleClose, user }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const { editContext } = user;
  const external = user.external === true;
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };

  return (
    <>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a user')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={(event, value) => handleChangeTab(value)}
          >
            <Tab label={t('Overview')} />
            <Tab disabled={external} label={t('Password')} />
            <Tab label={t('Groups')} />
            { hasSetAccess && <Tab label={t('Organizations admin')} /> }
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <UserEditionOverview user={user} context={editContext} />
        )}
        {currentTab === 1 && (
          <UserEditionPassword user={user} context={editContext} />
        )}
        {currentTab === 2 && (
          <UserEditionGroups user={user} />
        )}
        {hasSetAccess && currentTab === 3 && (
          <UserEditionOrganizationsAdmin user={user} />
        )}
      </div>
    </>
  );
};

const UserEditionFragment = createFragmentContainer(UserEdition, {
  user: graphql`
    fragment UserEdition_user on User
    @argumentDefinitions(
      rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
      rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
      groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
      groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
      organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
      organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
    ) {
      id
      external
      ...UserEditionOverview_user
      @arguments(
        rolesOrderBy: $rolesOrderBy
        rolesOrderMode: $rolesOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
      ...UserEditionPassword_user
      ...UserEditionGroups_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
      ...UserEditionOrganizationsAdmin_user
      @arguments(
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default UserEditionFragment;
