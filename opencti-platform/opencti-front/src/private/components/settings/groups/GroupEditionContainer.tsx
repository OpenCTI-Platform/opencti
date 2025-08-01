import React, { FunctionComponent, useState } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
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

interface GroupEditionContainerProps {
  groupQueryRef: PreloadedQuery<GroupEditionContainerQuery>
  handleClose?: () => void
  open?: boolean
  disabled?: boolean
}

const UpdateGroupControlledDial = (props: DrawerControlledDialProps) => (
  <EditEntityControlledDial
    style={{ float: 'right' }}
    {...props}
  />
);

const GroupEditionContainer: FunctionComponent<GroupEditionContainerProps> = ({
  groupQueryRef,
  handleClose = () => {},
  open,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();

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
  const paginationLocalStorage: PaginationLocalStorage<DataTableToolBarUsersLinesSearchQuery$variables> = useDataTablePaginationLocalStorage(LOCAL_STORAGE_KEY, {});
  const { orderMode, orderBy } = paginationLocalStorage.paginationOptions;
  const userQueryRef = useQueryLoading<DataTableToolBarUsersLinesSearchQuery>(
    toolBarUsersLinesSearchQuery,
    { search: searchTerm, orderBy, orderMode },
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
      </>
    </Drawer>
  );
};

export default GroupEditionContainer;
