// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent, useMemo, useState } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import AccessesMenu from '@components/settings/AccessesMenu';
import Typography from '@mui/material/Typography';
import { Box, styled } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import GroupDeletionDialog from '@components/settings/groups/GroupDeletionDialog';
import GroupEdition from '@components/settings/groups/GroupEdition';
import { useTheme } from '@mui/styles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Group from './Group';
import { RootGroupsSubscription } from './__generated__/RootGroupsSubscription.graphql';
import { RootGroupQuery } from './__generated__/RootGroupQuery.graphql';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import PopoverMenu from '../../../../components/PopoverMenu';
import type { Theme } from '../../../../components/Theme';

const subscription = graphql`
    subscription RootGroupsSubscription($id: ID!) {
        group(id: $id) {
            ...Group_group
        }
    }
`;

const groupQuery = graphql`
  query RootGroupQuery(
    $id: String!
    $rolesOrderBy: RolesOrdering
    $rolesOrderMode: OrderingMode
  ) {
    group(id: $id) {
      id
      name
      standard_id
      ...Group_group
      @arguments(
        rolesOrderBy: $rolesOrderBy
        rolesOrderMode: $rolesOrderMode
      )
    }
  }
`;

interface RootGroupComponentProps {
  queryRef: PreloadedQuery<RootGroupQuery>,
  groupId: string,
}

const RootGroupComponent: FunctionComponent<RootGroupComponentProps> = ({ queryRef, groupId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootGroupsSubscription>>(
    () => ({
      subscription,
      variables: { id: groupId },
    }),
    [groupId],
  );
  useSubscription(subConfig);
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const [openDelete, setOpenDelete] = useState(false);

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  const data = usePreloadedQuery(groupQuery, queryRef);
  const { group } = data;

  const { isAllowed, isSensitive } = useSensitiveModifications('groups', group.standard_id);

  const GroupHeader = styled('div')({
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 24,
  });

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      <>
        <AccessesMenu/>
        <Breadcrumbs
          isSensitive={isSensitive}
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Security') },
            { label: t_i18n('Groups'), link: '/dashboard/settings/accesses/groups' },
            { label: group.name, current: true },
          ]}
        />
        <GroupHeader>
          <div>
            <Typography
              variant="h1"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {group.name}
            </Typography>
            <div className="clearfix"/>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', paddingRight: 200 }}>
            <div style={{ display: 'flex' }}>
              <div style={{ marginRight: theme.spacing(0.5) }}>
                {canDelete && (
                <PopoverMenu>
                  {({ closeMenu }) => (
                    <Box>
                      <MenuItem
                        disabled={!isAllowed && isSensitive}
                        onClick={() => {
                          handleOpenDelete();
                          closeMenu();
                        }}
                      >
                        {t_i18n('Delete')}
                      </MenuItem>
                    </Box>
                  )}
                </PopoverMenu>
                )}
              </div>
              <GroupDeletionDialog
                groupId={group.id}
                isOpen={openDelete}
                handleClose={handleCloseDelete}
              />
              <GroupEdition
                groupId={group.id}
                disabled={!isAllowed && isSensitive}
              />
            </div>
          </div>
        </GroupHeader>
        <Routes>
          <Route
            path="/"
            element={
              <Group groupData={group}/>
            }
          />
        </Routes>
      </>
    </Security>
  );
};

const RootGroup = () => {
  const { groupId } = useParams() as { groupId: string };
  const queryRef = useQueryLoading<RootGroupQuery>(groupQuery, { id: groupId, rolesOrderBy: 'name', rolesOrderMode: 'asc' });
  return (
    <div>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootGroupComponent queryRef={queryRef} groupId={groupId} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </div>
  );
};

export default RootGroup;
