import React, { FunctionComponent, useState } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { usersLinesSearchQuery } from '@components/settings/users/UsersLines';
import { UsersLinesSearchQuery, UsersLinesSearchQuery$variables } from '@components/settings/users/__generated__/UsersLinesSearchQuery.graphql';
import { GroupUsersLinesQuery$variables } from '@components/settings/users/__generated__/GroupUsersLinesQuery.graphql';
import { initialStaticPaginationForGroupUsers } from '@components/settings/users/GroupUsers';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import GroupEditionConfidence from './GroupEditionConfidence';
import GroupEditionOverview from './GroupEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import GroupEditionRoles, { groupEditionRolesLinesSearchQuery } from './GroupEditionRoles';
import GroupEditionUsers from './GroupEditionUsers';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GroupEditionRolesLinesSearchQuery } from './__generated__/GroupEditionRolesLinesSearchQuery.graphql';
import { GroupEditionContainerQuery } from './__generated__/GroupEditionContainerQuery.graphql';
import { GroupEditionContainer_group$key } from './__generated__/GroupEditionContainer_group.graphql';
import GroupEditionMarkings from './GroupEditionMarkings';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { PaginationLocalStorage, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import { useDataTablePaginationLocalStorage } from '../../../../components/dataGrid/dataTableHooks';
import useHelper from '../../../../utils/hooks/useHelper';
import UpdateGroupControlledDial from '../../../../components/UpdateEntityControlledDial';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const groupEditionContainerQuery = graphql`
  query GroupEditionContainerQuery($id: String!) {
    group(id: $id) {
      ...GroupEditionContainer_group
    }
  }
`;

const GroupEditionContainerFragment = graphql`
  fragment GroupEditionContainer_group on Group
  @argumentDefinitions(
    rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
    rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    members(first: 500) {
      edges {
        node {
          id
          name
        }
      }
    }
    ...GroupEditionOverview_group
    ...GroupEditionMarkings_group
    ...GroupEditionConfidence_group
    ...GroupEditionRoles_group
    @arguments(
      orderBy: $rolesOrderBy
      orderMode: $rolesOrderMode
    )
    editContext {
      name
      focusOn
    }
  }
`;

const groupDeletionMutation = graphql`
  mutation GroupEditionContainerDeletionMutation($id: ID!) {
    groupEdit(id: $id) {
      delete
    }
  }
`;

interface GroupDeletionDialogProps {
  groupId: string,
}

const GroupDeletionDialog: FunctionComponent<GroupDeletionDialogProps> = ({
  groupId,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully delete',
    values: { entity_type: t_i18n('Group') },
  });
  const [commitDeleteMutation] = useApiMutation(
    groupDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleOpenDelete = () => setDisplayDelete(true);
  const handleCloseDelete = () => setDisplayDelete(false);
  const submitDelete = () => {
    setDeleting(true);
    commitDeleteMutation({
      variables: { id: groupId },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        navigate('/dashboard/settings/accesses/groups');
      },
    });
  };

  return (
    <div>
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
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this group?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

interface GroupEditionContainerProps {
  groupQueryRef: PreloadedQuery<GroupEditionContainerQuery>
  handleClose?: () => void
  open?: boolean
  disabled?: boolean
}

const GroupEditionContainer: FunctionComponent<GroupEditionContainerProps> = ({
  groupQueryRef,
  handleClose = () => {},
  open,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [currentTab, setTab] = useState(0);

  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const groupData = usePreloadedQuery<GroupEditionContainerQuery>(groupEditionContainerQuery, groupQueryRef);
  const roleQueryRef = useQueryLoading<GroupEditionRolesLinesSearchQuery>(groupEditionRolesLinesSearchQuery);

  const group = useFragment<GroupEditionContainer_group$key>(
    GroupEditionContainerFragment,
    groupData.group,
  );

  if (!group) {
    return <ErrorNotFound />;
  }

  const { viewStorage: { searchTerm }, paginationOptions: paginationOptionsForUserEdition, helpers } = usePaginationLocalStorage<GroupUsersLinesQuery$variables>(
    `group-${group.id}-users`,
    {
      id: group.id,
      ...initialStaticPaginationForGroupUsers,
    },
    true,
  );
  const LOCAL_STORAGE_KEY = `group-${group.id}-users`;
  const paginationLocalStorage: PaginationLocalStorage<UsersLinesSearchQuery$variables> = useDataTablePaginationLocalStorage(LOCAL_STORAGE_KEY, {});
  const { orderMode, orderBy } = paginationLocalStorage.paginationOptions;
  const userQueryRef = useQueryLoading<UsersLinesSearchQuery>(
    usersLinesSearchQuery,
    { search: searchTerm, orderBy, orderMode },
  );

  const { editContext } = group;
  return (
    <Drawer
      title={t_i18n('Update a group')}
      variant={open == null && !isFABReplaced
        ? DrawerVariant.updateWithPanel
        : undefined}
      context={editContext}
      onClose={handleClose}
      open={open}
      disabled={disabled}
      controlledDial={isFABReplaced
        ? UpdateGroupControlledDial
        : undefined
      }
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Roles')} />
            <Tab label={t_i18n('Markings')} />
            <Tab label={t_i18n('Members')} />
            <Tab label={t_i18n('Confidences')} />
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <GroupEditionOverview group={group} context={editContext} />
        )}
        {currentTab === 1 && roleQueryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inline} />}
          >
            <GroupEditionRoles group={group} queryRef={roleQueryRef} />
          </React.Suspense>
        )}
        {currentTab === 2 && <GroupEditionMarkings group={group} />}
        {currentTab === 3 && userQueryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inline} />}
          >
            <GroupEditionUsers
              group={group}
              queryRef={userQueryRef}
              paginationOptionsForUpdater={paginationOptionsForUserEdition}
              storageKey={LOCAL_STORAGE_KEY}
            >
              <SearchInput
                variant="thin"
                onSubmit={helpers.handleSearch}
                keyword={searchTerm}
                sx={{
                  marginTop: 2,
                  marginBottom: 2,
                }}
              />
            </GroupEditionUsers>
          </React.Suspense>
        )}
        {hasSetAccess && currentTab === 4 && (
          <GroupEditionConfidence group={group} context={editContext} />
        )}
        <GroupDeletionDialog groupId={group.id} />
      </>
    </Drawer>
  );
};

export default GroupEditionContainer;
