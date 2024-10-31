// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Role from './Role';
import { groupsSearchQuery } from '../Groups';
import { RootRoleQuery } from './__generated__/RootRoleQuery.graphql';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';

const roleQuery = graphql`
  query RootRoleQuery($id: String!) {
    role(id: $id) {
      id
      standard_id
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
  const { t_i18n } = useFormatter();

  const { isSensitive } = useSensitiveModifications('roles', role?.standard_id);

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
        <>
          <Breadcrumbs
            isSensitive={isSensitive}
            elements={[
              { label: t_i18n('Settings') },
              { label: t_i18n('Security') },
              { label: t_i18n('Roles'), link: '/dashboard/settings/accesses/roles' },
              { label: role.name, current: true },
            ]}
          />
          <>
            {groupsQueryRef ? (
              <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                <Routes>
                  <Route
                    path="/"
                    element={(
                      <Role roleData={role} groupsQueryRef={groupsQueryRef} />
                    )}
                  />
                </Routes>
              </React.Suspense>
            ) : (
              <Loader variant={LoaderVariant.inElement} />
            )
            }
          </>
        </>
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
