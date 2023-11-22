import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import UserEditionOrganizationsAdmin from '@components/settings/users/UserEditionOrganizationsAdmin';
import EEChip from '@components/common/entreprise_edition/EEChip';
import UserEditionOverview from './UserEditionOverview';
import UserEditionPassword from './UserEditionPassword';
import UserEditionGroups from './UserEditionGroups';
import { useFormatter } from '../../../../components/i18n';
import { UserEdition_user$data } from './__generated__/UserEdition_user.graphql';
import useGranted, {
  SETTINGS_SETACCESSES,
} from '../../../../utils/hooks/useGranted';

interface UserEditionProps {
  handleClose?: () => void;
  user: UserEdition_user$data;
  open?: boolean;
}

const UserEdition: FunctionComponent<UserEditionProps> = ({
  handleClose = () => {},
  user,
  open,
}) => {
  const { t } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const { editContext } = user;
  const external = user.external === true;
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  return (
    <Drawer
      title={t('Update a user')}
      variant={open == null ? DrawerVariant.updateWithPanel : undefined}
      open={open}
      onClose={handleClose}
      context={editContext}
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={(event, value) => handleChangeTab(value)}
          >
            <Tab label={t('Overview')} />
            <Tab disabled={external} label={t('Password')} />
            <Tab label={t('Groups')} />
            {hasSetAccess && <Tab label={<div>{t('Organizations admin')}<EEChip /></div>} />}
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <UserEditionOverview user={user} context={editContext} />
        )}
        {currentTab === 1 && (
          <UserEditionPassword user={user} context={editContext} />
        )}
        {currentTab === 2 && <UserEditionGroups user={user} />}
        {hasSetAccess && currentTab === 3 && (
          <UserEditionOrganizationsAdmin user={user} />
        )}
      </>
    </Drawer>
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
      organizationsOrderBy: {
        type: "OrganizationsOrdering"
        defaultValue: name
      }
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
