import React, { useEffect, useMemo, useState } from 'react';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePreloadedQuery, useQueryLoader, useSubscription } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Stack } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import type { RootUserQuery, RootUserQuery$variables } from './__generated__/RootUserQuery.graphql';
import type { RootUserEditionQuery } from './__generated__/RootUserEditionQuery.graphql';
import ConvertUser from './ConvertUser';
import UserDeletionDialog from './UserDeletionDialog';
import UserEmailSend from './UserEmailSend';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import User from './User';
import UserAnalytics from './UserAnalytics';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import UserEdition from './UserEdition';
import PopoverMenu from '../../../../components/PopoverMenu';
import UserHistoryTab from './UserHistoryTab';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';

const userEditionQuery = graphql`
  query RootUserEditionQuery($id: String!) {
    user(id: $id) {
      ...UserEdition_user
    }
  }
`;

const subscription = graphql`
  subscription RootUsersSubscription(
    $id: ID!
    $groupsOrderBy: GroupsOrdering
    $groupsOrderMode: OrderingMode
    $organizationsOrderBy: OrganizationsOrdering
    $organizationsOrderMode: OrderingMode
  ) {
    user(id: $id) {
      ...User_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
      ...UserEdition_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
    }
  }
`;

const userQuery = graphql`
  query RootUserQuery(
    $id: String!
    $groupsOrderBy: GroupsOrdering
    $groupsOrderMode: OrderingMode
    $organizationsOrderBy: OrganizationsOrdering
    $organizationsOrderMode: OrderingMode
  ) {
    user(id: $id) {
      id
      name
      user_email
      user_service_account
      ...User_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
      ...UserAnalytics_user
      ...UserHistoryTab_user
    }
  }
`;

interface RootUserComponentProps {
  queryRef: PreloadedQuery<RootUserQuery>;
  userId: string;
  refetch: () => void;
}

const RootUserComponent = ({ queryRef, userId, refetch }: RootUserComponentProps) => {
  const subConfig = useMemo(
    () => ({
      subscription,
      variables: { id: userId },
    }),
    [userId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const theme = useTheme<Theme>();

  useSubscription(subConfig);
  const { user: data } = usePreloadedQuery<RootUserQuery>(userQuery, queryRef);
  const userEditionData = useLazyLoadQuery<RootUserEditionQuery>(
    userEditionQuery,
    { id: userId },
  );
  const [openDelete, setOpenDelete] = useState(false);
  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  return (
    <Security needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}>
      {data ? (
        <div style={{ paddingRight: 200 }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Security') },
            { label: t_i18n('Users'), link: '/dashboard/settings/accesses/users' },
            { label: data.name || data.user_email, current: true },
          ]}
          />
          <Stack direction="row" alignItems="center" marginBottom={3}>
            <TitleMainEntity sx={{ flex: 1 }}>
              {data.name}
            </TitleMainEntity>
            <div style={{ display: 'flex', gap: theme.spacing(0.5) }}>
              <UserEmailSend
                outlined
                userId={userId}
                onClose={() => {}}
              />
              {canDelete && (
                <PopoverMenu>
                  {({ closeMenu }) => (
                    <Box>
                      <MenuItem onClick={() => {
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
              <ConvertUser
                userId={data.id}
                userServiceAccount={data.user_service_account ?? false}
              />
              <UserDeletionDialog
                userId={data.id}
                isOpen={openDelete}
                handleClose={handleCloseDelete}
              />
              <UserEdition userEditionData={userEditionData} />
            </div>
          </Stack>

          <div className="clearfix" />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 3 }}
          >
            <Tabs value={location.pathname}>
              <Tab
                component={Link}
                to={`/dashboard/settings/accesses/users/${data.id}`}
                value={`/dashboard/settings/accesses/users/${data.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/settings/accesses/users/${data.id}/analytics`}
                value={`/dashboard/settings/accesses/users/${data.id}/analytics`}
                label={t_i18n('Analytics')}
              />
              <Tab
                component={Link}
                to={`/dashboard/settings/accesses/users/${data.id}/history`}
                value={`/dashboard/settings/accesses/users/${data.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={
                <User data={data} refetch={refetch} />
              }
            />
            <Route
              path="/analytics"
              element={(
                <UserAnalytics data={data} />
              )}
            />
            <Route
              path="/history"
              element={(
                <UserHistoryTab data={data} />
              )}
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </Security>
  );
};

const RootUser = () => {
  const { userId } = useParams();
  const queryParams: RootUserQuery$variables = {
    id: userId ?? '',
    groupsOrderBy: 'name',
    groupsOrderMode: 'asc',
    organizationsOrderBy: 'name',
    organizationsOrderMode: 'asc',
  };
  const [queryRef, loadQuery] = useQueryLoader<RootUserQuery>(userQuery);
  useEffect(() => {
    loadQuery(queryParams, { fetchPolicy: 'store-and-network' });
  }, []);
  const refetch = React.useCallback(() => {
    loadQuery(queryParams, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);
  if (!userId) return <ErrorNotFound />;
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootUserComponent
            queryRef={queryRef}
            userId={userId}
            refetch={refetch}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RootUser;
