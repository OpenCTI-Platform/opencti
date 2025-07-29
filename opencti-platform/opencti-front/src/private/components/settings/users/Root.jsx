import React, { useEffect, useMemo, useState } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Route, Routes, useParams, useLocation } from 'react-router-dom';
import { graphql, useLazyLoadQuery, usePreloadedQuery, useQueryLoader, useSubscription } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import makeStyles from '@mui/styles/makeStyles';
import { styled } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/styles';
import ConvertUser from './ConvertUser';
import useHelper from '../../../../utils/hooks/useHelper';
import UserDeletionDialog from './UserDeletionDialog';
import AccessesMenu from '../AccessesMenu';
import Security from '../../../../utils/Security';
import useGranted, { VIRTUAL_ORGANIZATION_ADMIN, SETTINGS_SETACCESSES, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import User from './User';
import UserAnalytics from './UserAnalytics';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import UserEdition from './UserEdition';
import PopoverMenu from '../../../../components/PopoverMenu';
import UserHistoryTab from './UserHistoryTab';

const userEditionQuery = graphql`
  query RootUserEditionQuery($id: String!) {
    user(id: $id) {
      ...UserEdition_user
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
}));

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

const RootUserComponent = ({ queryRef, userId, refetch }) => {
  const subConfig = useMemo(
    () => ({
      subscription,
      variables: { id: userId },
    }),
    [userId],
  );
  const location = useLocation();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const theme = useTheme();

  useSubscription(subConfig);
  const { user: data } = usePreloadedQuery(userQuery, queryRef);
  const userEditionData = useLazyLoadQuery(
    userEditionQuery,
    { id: userId },
  );
  const { isFeatureEnable } = useHelper();
  const isUserHistoryTab = isFeatureEnable('USER_HISTORY_TAB');
  const serviceAccountFeatureFlag = isFeatureEnable('SERVICE_ACCOUNT');
  const [openDelete, setOpenDelete] = useState(false);
  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  const UserHeader = styled('div')({
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 24,
  });

  return (
    <Security needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}>
      {data ? (
        <div style={{ paddingRight: 200 }}>
          <AccessesMenu />
          <Breadcrumbs elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Security') },
            { label: t_i18n('Users'), link: '/dashboard/settings/accesses/users' },
            { label: data.name || data.user_email, current: true },
          ]}
          />
          <UserHeader>
            <div>
              <Typography
                variant="h1"
                gutterBottom={true}
                classes={{ root: classes.title }}
              >
                {data.name}
              </Typography>
              <div className="clearfix"/>
            </div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{ display: 'flex' }}>
                <div style={{ marginRight: theme.spacing(1.5) }}>
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
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {serviceAccountFeatureFlag
                    && < ConvertUser
                      userId={data.id}
                      userServiceAccount={data.user_service_account}
                       />
                  }
                  <UserDeletionDialog
                    userId={data.id}
                    isOpen={openDelete}
                    handleClose={handleCloseDelete}
                  />
                  <UserEdition userEditionData={userEditionData} />
                </div>
              </div>
            </div>
          </UserHeader>

          <div className="clearfix" />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
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
              {isUserHistoryTab && <Tab
                component={Link}
                to={`/dashboard/settings/accesses/users/${data.id}/history`}
                value={`/dashboard/settings/accesses/users/${data.id}/history`}
                label={t_i18n('History')}
                                   />}
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
              element={ (
                <UserAnalytics data={data} refetch={refetch} />
              )}
            />
            <Route
              path="/history"
              element={(
                <UserHistoryTab data={data} refetch={refetch} />
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
  const queryParams = {
    id: userId,
    rolesOrderBy: 'name',
    rolesOrderMode: 'asc',
    groupsOrderBy: 'name',
    groupsOrderMode: 'asc',
    organizationsOrderBy: 'name',
    organizationsOrderMode: 'asc',
  };
  const [queryRef, loadQuery] = useQueryLoader(userQuery);
  useEffect(() => {
    loadQuery(queryParams, { fetchPolicy: 'store-and-network' });
  }, []);
  const refetch = React.useCallback(() => {
    loadQuery(queryParams, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);
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

RootUser.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default RootUser;
