import React, { FunctionComponent, useState } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import GroupEditionOverview from './GroupEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import GroupEditionRoles, { groupEditionRolesLinesSearchQuery } from './GroupEditionRoles';
import GroupEditionUsers from './GroupEditionUsers';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GroupEditionRolesLinesSearchQuery } from './__generated__/GroupEditionRolesLinesSearchQuery.graphql';
import { GroupEditionContainerQuery } from './__generated__/GroupEditionContainerQuery.graphql';
import { GroupEditionContainer_group$key } from './__generated__/GroupEditionContainer_group.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import GroupEditionMarkings from './GroupEditionMarkings';

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
    ...GroupEditionOverview_group
    ...GroupEditionMarkings_group
    ...GroupEditionUsers_group
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

const GroupEditionContainer: FunctionComponent<GroupEditionContainerProps> = ({ groupQueryRef, handleClose = () => {}, open }) => {
  const { t } = useFormatter();
  const [currentTab, setTab] = useState(0);
  const groupData = usePreloadedQuery<GroupEditionContainerQuery>(groupEditionContainerQuery, groupQueryRef);
  const roleQueryRef = useQueryLoading<GroupEditionRolesLinesSearchQuery>(groupEditionRolesLinesSearchQuery);
  if (groupData.group) {
    const group = useFragment<GroupEditionContainer_group$key>(
      GroupEditionContainerFragment,
      groupData.group,
    );
    const { editContext } = group;
    return (
      <Drawer
        title={t('Update a group')}
        variant={open == null ? DrawerVariant.updateWithPanel : undefined}
        context={editContext}
        onClose={handleClose}
        open={open}
      >
        <>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
              <Tab label={t('Overview')} />
              <Tab label={t('Roles')} />
              <Tab label={t('Markings')} />
              <Tab label={t('Members')} />
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
          {currentTab === 3 && <GroupEditionUsers group={group} />}
        </>
      </Drawer>
    );
  }
  return <ErrorNotFound />;
};

export default GroupEditionContainer;
