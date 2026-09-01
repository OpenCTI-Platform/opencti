import React, { FunctionComponent, useState } from 'react';
import Box from '@mui/material/Box';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';

import { GroupUsersLinesQuery$variables } from '@components/settings/users/__generated__/GroupUsersLinesQuery.graphql';
import { initialStaticPaginationForGroupUsers } from '@components/settings/users/GroupUsers';
import { toolBarUsersLinesSearchQuery } from '@components/data/DataTableToolBar';
import {
  DataTableToolBarUsersLinesSearchQuery,
  DataTableToolBarUsersLinesSearchQuery$variables,
} from '@components/data/__generated__/DataTableToolBarUsersLinesSearchQuery.graphql';
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
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

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
    standard_id
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

interface GroupEditionContainerProps {
  groupQueryRef: PreloadedQuery<GroupEditionContainerQuery>;
  handleClose?: () => void;
  open?: boolean;
  disabled?: boolean;
}

const GroupEditionContainer: FunctionComponent<GroupEditionContainerProps> = ({
  groupQueryRef,
  handleClose = () => {},
  open,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();

  const [currentTab, setTab] = useState('overview');

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
  const paginationLocalStorage: PaginationLocalStorage<DataTableToolBarUsersLinesSearchQuery$variables> = useDataTablePaginationLocalStorage(LOCAL_STORAGE_KEY, {});
  const { orderMode, orderBy } = paginationLocalStorage.paginationOptions;
  const userQueryRef = useQueryLoading<DataTableToolBarUsersLinesSearchQuery>(
    toolBarUsersLinesSearchQuery,
    { search: searchTerm, orderBy, orderMode },
  );
  const UpdateGroupControlledDial = (props: DrawerControlledDialProps) => (
    <EditEntityControlledDial
      style={{ float: 'right' }}
      disabled={disabled}
      {...props}
    />
  );

  const { editContext } = group;
  return (
    <Drawer
      title={t_i18n('Update a group')}
      context={editContext}
      onClose={handleClose}
      open={open}
      disabled={disabled}
      controlledDial={UpdateGroupControlledDial}
    >
      <Box sx={{
        display: 'flex',
        flexDirection: 'column',
        flex: 1,
        minHeight: 0,
        overflowY: 'auto',
        overflowX: 'hidden',
        scrollbarWidth: 'none',
      }}
      >
        <Tabs value={currentTab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="overview">{t_i18n('Overview')}</TabsTrigger>
            <TabsTrigger value="roles">{t_i18n('Roles')}</TabsTrigger>
            <TabsTrigger value="markings">{t_i18n('Markings')}</TabsTrigger>
            <TabsTrigger value="members">{t_i18n('Members')}</TabsTrigger>
            <TabsTrigger value="confidences">{t_i18n('Confidences')}</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <GroupEditionOverview group={group} context={editContext} />
          </TabsContent>
          <TabsContent value="roles">
            {roleQueryRef && (
              <React.Suspense
                fallback={<Loader variant={LoaderVariant.inline} />}
              >
                <GroupEditionRoles group={group} queryRef={roleQueryRef} />
              </React.Suspense>
            )}
          </TabsContent>
          <TabsContent value="markings">
            <GroupEditionMarkings group={group} />
          </TabsContent>
          <TabsContent value="members">
            {userQueryRef && (
              <Box sx={{ flex: 1, minHeight: 0, overflow: 'hidden' }}>
                <React.Suspense
                  fallback={<Loader variant={LoaderVariant.inline} />}
                >
                  <GroupEditionUsers
                    group={group}
                    queryRef={userQueryRef}
                    paginationOptionsForUpdater={paginationOptionsForUserEdition}
                    storageKey={LOCAL_STORAGE_KEY}
                  >
                    <Box sx={{ marginTop: 2, marginBottom: 2 }}>
                      <SearchInput
                        variant="thin"
                        onSubmit={helpers.handleSearch}
                        keyword={searchTerm}
                      />
                    </Box>
                  </GroupEditionUsers>
                </React.Suspense>
              </Box>
            )}
          </TabsContent>
          <TabsContent value="confidences">
            {hasSetAccess && (
              <GroupEditionConfidence group={group} context={editContext} />
            )}
          </TabsContent>
        </Tabs>
      </Box>
    </Drawer>
  );
};

export default GroupEditionContainer;
