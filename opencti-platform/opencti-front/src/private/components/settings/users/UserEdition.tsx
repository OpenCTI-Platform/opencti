import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useNavigate } from 'react-router-dom';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import UserEditionConfidence from './edition/UserEditionConfidence';
import UserEditionOrganizationsAdmin from './edition/UserEditionOrganizationsAdmin';
import UserEditionOverview from './edition/UserEditionOverview';
import UserEditionPassword from './edition/UserEditionPassword';
import UserEditionGroups from './edition/UserEditionGroups';
import { useFormatter } from '../../../../components/i18n';
import { UserEdition_user$key } from './__generated__/UserEdition_user.graphql';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { UserPopoverEditionQuery$data } from './__generated__/UserPopoverEditionQuery.graphql';
import Loader from '../../../../components/Loader';
import useHelper from '../../../../utils/hooks/useHelper';
import UpdateUserControlledDial from '../../../../components/UpdateEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

const UserEditionFragment = graphql`
  fragment UserEdition_user on User
  @argumentDefinitions(
    groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
    groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
    organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
    organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    external
    user_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
      }
    }
    effective_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
        source {
          type
          object {
            ... on User { entity_type id name }
            ... on Group { entity_type id name }
          }
        }
      }
      source {
        type
        object {
          ... on User { entity_type id name }
          ... on Group { entity_type id name }
        }
      }
    }
    groups(orderBy: $groupsOrderBy, orderMode: $groupsOrderMode) {
      edges {
        node {
          id
          name
        }
      }
    }
    ...UserEditionOverview_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
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
`;

const userDeletionMutation = graphql`
  mutation UserEditionDeletionMutation($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

interface UserDeletionDialogProps {
  userId: string,
  handleClose: () => void;
}

const UserDeletionDialog: FunctionComponent<UserDeletionDialogProps> = ({
  userId,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('User') },
  });
  const [commit] = useApiMutation(
    userDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleOpenDelete = () => setDisplayDelete(true);
  const handleCloseDelete = () => setDisplayDelete(false);
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: userId },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/settings/accesses/users');
      },
    });
  };

  return (
    <>
      <Button
        onClick={handleOpenDelete}
        variant='contained'
        color='error'
        disabled={deleting}
        sx={{ marginTop: 2 }}
      >
        {t_i18n('Delete')}
      </Button>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogTitle>{t_i18n('Do you want to delete this user?')}</DialogTitle>
        <DialogContent dividers>
          <ul>
            <li>{t_i18n('All notifications, triggers and digests associated with the user will be deleted.')}</li>
            <li>{t_i18n('All investigations and dashboard where the user is the only admin, will be deleted.')}</li>
          </ul>
          {t_i18n('If you want to keep the associated information, we recommend deactivating the user instead.')}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

interface UserEditionDrawerProps {
  handleClose?: () => void;
  userRef: UserPopoverEditionQuery$data['user'];
  open?: boolean;
}

const UserEditionDrawer: FunctionComponent<UserEditionDrawerProps> = ({
  handleClose = () => {},
  userRef,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const user = useFragment<UserEdition_user$key>(UserEditionFragment, userRef);
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  return (
    <Drawer
      title={t_i18n('Update a user')}
      variant={open == null && !isFABReplaced
        ? DrawerVariant.updateWithPanel
        : undefined}
      open={open}
      onClose={handleClose}
      context={user?.editContext}
      controlledDial={isFABReplaced
        ? UpdateUserControlledDial
        : undefined
      }
    >
      {user ? (<>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={(event, value) => handleChangeTab(value)}
          >
            <Tab label={t_i18n('Overview')} />
            <Tab disabled={!!user.external} label={t_i18n('Password')} />
            <Tab label={t_i18n('Groups')} />
            {hasSetAccess
              && <Tab label={
                <div style={{ alignItems: 'center', display: 'flex' }}>
                  {t_i18n('Organizations admin')}<EEChip />
                </div>}
                 />
            }
            {hasSetAccess && <Tab label={t_i18n('Confidences')} />}
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <UserEditionOverview user={user} context={user.editContext} />
        )}
        {currentTab === 1 && (
          <UserEditionPassword user={user} context={user.editContext} />
        )}
        {currentTab === 2 && <UserEditionGroups user={user} />}
        {hasSetAccess && currentTab === 3 && (
          <UserEditionOrganizationsAdmin user={user} />
        )}
        {hasSetAccess && currentTab === 4 && (
          <UserEditionConfidence user={user} context={user.editContext} />
        )}
        <UserDeletionDialog userId={user.id} handleClose={handleClose} />
      </>)
        : (<Loader />)}
    </Drawer>
  );
};

interface UserEditionProps {
  userEditionData?: UserPopoverEditionQuery$data;
  handleClose?: () => void;
  open?: boolean;
}

const UserEdition: FunctionComponent<UserEditionProps> = ({
  userEditionData,
  handleClose,
  open,
}) => {
  if (!userEditionData) return <Loader />;
  return (
    <UserEditionDrawer
      handleClose={handleClose}
      open={open}
      userRef={userEditionData.user}
    />
  );
};

export default UserEdition;
