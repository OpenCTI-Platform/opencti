// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent, useMemo } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Group from './Group';
import { RootGroupsSubscription } from './__generated__/RootGroupsSubscription.graphql';
import { RootGroupQuery } from './__generated__/RootGroupQuery.graphql';
import Security from '../../../../utils/Security';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';

const subscription = graphql`
    subscription RootGroupsSubscription($id: ID!) {
        group(id: $id) {
            ...Group_group
            ...GroupEditionContainer_group
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
      ...Group_group
      @arguments(
        rolesOrderBy: $rolesOrderBy
        rolesOrderMode: $rolesOrderMode
      )
      ...GroupEditionContainer_group
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
  const data = usePreloadedQuery(groupQuery, queryRef);
  const { group } = data;

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      {group ? (
        <Switch>
          <Route
            exact
            path="/dashboard/settings/accesses/groups/:groupId"
            render={(routeProps) => (
              <Group {...routeProps} groupData={group} />
            )}
          />
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </Security>
  );
};

const RootGroup = () => {
  const { groupId } = useParams() as { groupId: string };
  const queryRef = useQueryLoading<RootGroupQuery>(groupQuery, { id: groupId, rolesOrderBy: 'name', rolesOrderMode: 'asc' });
  return (
    <div>
      <TopBar />
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
