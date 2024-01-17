import React, { useEffect, useMemo } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useQueryLoader, useSubscription } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useLocation } from 'react-router-dom-v5-compat';
import makeStyles from '@mui/styles/makeStyles';
import UserPopover from './UserPopover';
import AccessesMenu from '../AccessesMenu';
import Security from '../../../../utils/Security';
import { VIRTUAL_ORGANIZATION_ADMIN, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import User from './User';
import UserAnalytics from './UserAnalytics';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles((theme) => ({
  title: {
    float: 'left',
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
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
      ...User_user
        @arguments(
          groupsOrderBy: $groupsOrderBy
          groupsOrderMode: $groupsOrderMode
          organizationsOrderBy: $organizationsOrderBy
          organizationsOrderMode: $organizationsOrderMode
        )
      ...UserAnalytics_user
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
  useSubscription(subConfig);
  const { me } = useAuth();
  const { user: data } = usePreloadedQuery(userQuery, queryRef);
  return (
    <Security needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}>
      {data ? (
        <div style={{ paddingRight: 200 }}>
          <AccessesMenu />
          <>
            <Typography
              variant="h1"
              gutterBottom={true}
              classes={{ root: classes.title }}
            >
              {data.name}
            </Typography>
            <div className={classes.popover}>
              <UserPopover userId={data.id} disabled={data.id === me.id} />
            </div>
            <div className="clearfix" />
          </>
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
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/settings/accesses/users/:userId"
              render={(routeProps) => (
                <User {...routeProps} data={data} refetch={refetch} />
              )}
            />
            <Route
              exact
              path="/dashboard/settings/accesses/users/:userId/analytics"
              render={(routeProps) => (
                <UserAnalytics {...routeProps} data={data} refetch={refetch} />
              )}
            />
          </Switch>
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
