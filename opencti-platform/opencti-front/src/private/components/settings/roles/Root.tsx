// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Role from './Role';
import { groupsSearchQuery } from '../Groups';
import { RootRoleQuery } from './__generated__/RootRoleQuery.graphql';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const roleQuery = graphql`
    query RootRoleQuery($id: String!) {
        role(id: $id) {
            id
            name
            ...Role_role
            ...RoleEdition_role
        }
    }
`;

interface RootRoleComponentProps {
  queryRef: PreloadedQuery<RootRoleQuery>,
}

const RootRoleComponent: FunctionComponent<RootRoleComponentProps> = ({ queryRef }) => {
  const data = usePreloadedQuery(roleQuery, queryRef);
  const { role } = data;
  const groupsQueryRef = useQueryLoading<GroupsSearchQuery>(
    groupsSearchQuery,
    {
      count: 50,
      orderBy: 'name',
      orderMode: 'asc',
    },
  );

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      {role ? (
        <Switch>
          {groupsQueryRef ? (
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
              <Route
                exact
                path="/dashboard/settings/accesses/roles/:roleId"
                render={(routeProps) => (
                  <Role {...routeProps} roleData={role} groupsQueryRef={groupsQueryRef} />
                )}
              />
            </React.Suspense>
          ) : (
            <Loader variant={LoaderVariant.inElement} />
          )
          }
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </Security>
  );
};

const RootRole = () => {
  const { roleId } = useParams() as { roleId: string };
  const queryRef = useQueryLoading<RootRoleQuery>(roleQuery, { id: roleId });
  return (
    <div>
      <TopBar />
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <RootRoleComponent queryRef={queryRef} roleId={roleId} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </div>
  );
};

export default RootRole;
