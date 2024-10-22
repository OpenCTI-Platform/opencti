// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent, useMemo } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import AccessesMenu from '@components/settings/AccessesMenu';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Group from './Group';
import { RootGroupsSubscription } from './__generated__/RootGroupsSubscription.graphql';
import { RootGroupQuery } from './__generated__/RootGroupQuery.graphql';
import Security from '../../../../utils/Security';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';

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
  const data = usePreloadedQuery(groupQuery, queryRef);
  const { group } = data;
  const { t_i18n } = useFormatter();

  const { isSensitive } = useSensitiveModifications('groups', group?.standard_id);

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      {group ? (
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
          <Routes>
            <Route
              path="/"
              element={
                <Group groupData={group}/>
            }
            />
          </Routes>
        </>
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
