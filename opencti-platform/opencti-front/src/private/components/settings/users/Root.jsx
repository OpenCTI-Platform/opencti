import React, { useEffect, useMemo } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, useParams } from 'react-router-dom';
import {
  graphql,
  usePreloadedQuery,
  useQueryLoader,
  useSubscription,
} from 'react-relay';
import TopBar from '../../nav/TopBar';
import User, { userQuery } from './User';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const subscription = graphql`
  subscription RootUsersSubscription(
    $id: ID!
    $rolesOrderBy: RolesOrdering
    $rolesOrderMode: OrderingMode
    $groupsOrderBy: GroupsOrdering
    $groupsOrderMode: OrderingMode
    $organizationsOrderBy: OrganizationsOrdering
    $organizationsOrderMode: OrderingMode
  ) {
    user(id: $id) {
      ...User_user
        @arguments(
          rolesOrderBy: $rolesOrderBy
          rolesOrderMode: $rolesOrderMode
          groupsOrderBy: $groupsOrderBy
          groupsOrderMode: $groupsOrderMode
          organizationsOrderBy: $organizationsOrderBy
          organizationsOrderMode: $organizationsOrderMode
        )
      ...UserEdition_user
        @arguments(
          rolesOrderBy: $rolesOrderBy
          rolesOrderMode: $rolesOrderMode
          groupsOrderBy: $groupsOrderBy
          groupsOrderMode: $groupsOrderMode
          organizationsOrderBy: $organizationsOrderBy
          organizationsOrderMode: $organizationsOrderMode
        )
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
  useSubscription(subConfig);
  const data = usePreloadedQuery(userQuery, queryRef);
  const { user } = data;

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      {user ? (
        <Switch>
          <Route
            exact
            path="/dashboard/settings/accesses/users/:userId"
            render={(routeProps) => (
              <User {...routeProps} userData={user} refetch={refetch} />
            )}
          />
        </Switch>
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
    <div>
      <TopBar />
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootUserComponent
            queryRef={queryRef}
            userId={userId}
            refetch={refetch}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </div>
  );
};

RootUser.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default RootUser;
