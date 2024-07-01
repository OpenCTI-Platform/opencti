import React, { FunctionComponent, useState } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { usersLinesSearchQuery } from '@components/settings/users/UsersLines';
import { UsersLinesSearchQuery } from '@components/settings/users/__generated__/UsersLinesSearchQuery.graphql';
import { GroupUsersLinesQuery$variables } from '@components/settings/users/__generated__/GroupUsersLinesQuery.graphql';
import { initialStaticPaginationForGroupUsers } from '@components/settings/users/GroupUsers';
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
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';

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
    members {
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
}

const GroupEditionContainer: FunctionComponent<GroupEditionContainerProps> = ({
  groupQueryRef, handleClose = () => {
  }, open,
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
  const userQueryRef = useQueryLoading<UsersLinesSearchQuery>(usersLinesSearchQuery, { search: searchTerm });

  const { editContext } = group;
  return (
    <Drawer
      title={t_i18n('Update a group')}
      variant={open == null ? DrawerVariant.updateWithPanel : undefined}
      context={editContext}
      onClose={handleClose}
      open={open}
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
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <GroupEditionRoles group={group} queryRef={roleQueryRef} />
          </React.Suspense>
        )}
        {currentTab === 2 && <GroupEditionMarkings group={group} />}
        {currentTab === 3 && userQueryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <GroupEditionUsers group={group} queryRef={userQueryRef} paginationOptionsForUpdater={paginationOptionsForUserEdition}>
              <SearchInput
                variant="thin"
                onSubmit={helpers.handleSearch}
                keyword={searchTerm}
                sx={{
                  marginTop: 2,
                  marginBottom: 1,
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
