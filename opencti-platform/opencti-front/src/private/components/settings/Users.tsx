import React, { useMemo } from 'react';
import { graphql } from 'react-relay';
import { UsersLinesPaginationQuery, UsersLinesPaginationQuery$variables } from '@components/settings/__generated__/UsersLinesPaginationQuery.graphql';
import { UsersLine_node$data } from '@components/settings/__generated__/UsersLine_node.graphql';
import { AccountCircleOutlined, ManageAccountsOutlined, PersonOutlined } from '@mui/icons-material';
import SettingsOrganizationUserCreation from './users/SettingsOrganizationUserCreation';
import EnterpriseEdition from '../common/entreprise_edition/EnterpriseEdition';
import UserCreation from './users/UserCreation';
import AccessesMenu from './AccessesMenu';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useGranted, { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { groupsQuery } from '../common/form/GroupField';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useAuth from '../../../utils/hooks/useAuth';

export const usersQuery = graphql`
  query UsersLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...UsersLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const usersFragment = graphql`
        fragment UsersLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "UsersOrdering", defaultValue: name }
          orderMode: { type: "OrderingMode", defaultValue: asc }
          filters: { type: "FilterGroup" }
        ) @refetchable(queryName: "UsersLinesRefetchQuery") {
          users(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
          ) @connection(key: "Pagination_users") {
            edges {
              node {
                id
                name
                firstname
                lastname
                ...UsersLine_node
              }
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }
      `;

const usersLineFragment = graphql`
    fragment UsersLine_node on User {
      id
      name
      user_email
      firstname
      external
      lastname
      entity_type
      user_service_account
      effective_confidence_level {
        max_confidence
      }
      otp_activated
      created_at
    }
  `;

const LOCAL_STORAGE_KEY = 'users';

const Users = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Users | Security | Settings'));
  const isSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const isAdminOrganization = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const isOnlyAdminOrganization = !isSetAccess && isAdminOrganization;
  const { me } = useAuth();
  const organization = me.administrated_organizations?.[0] ?? null;

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<UsersLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('User', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as UsersLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<UsersLinesPaginationQuery>(
    usersQuery,
    queryPaginationOptions,
  );

  const defaultAssignationFilter = {
    mode: 'and',
    filters: [{ key: 'default_assignation', values: [true] }],
    filterGroups: [],
  };
  const defaultGroupsQueryRef = useQueryLoading(
    groupsQuery,
    {
      orderBy: 'name',
      orderMode: 'asc',
      filters: defaultAssignationFilter,
    },
  );

  const userCreateButton = useMemo(() => {
    if (isSetAccess && defaultGroupsQueryRef) {
      return (
        <React.Suspense>
          <UserCreation paginationOptions={queryPaginationOptions} defaultGroupsQueryRef={defaultGroupsQueryRef} />
        </React.Suspense>
      );
    } if (isOnlyAdminOrganization && isEnterpriseEdition) {
      return (
        <SettingsOrganizationUserCreation
          paginationOptions={queryPaginationOptions}
          organization={organization}
          variant="controlledDial"
        />
      );
    }
    return null;
  }, [
    isSetAccess,
    defaultGroupsQueryRef,
    isAdminOrganization,
    isEnterpriseEdition,
    organization,
  ]);

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 25,
    },
    user_email: {
      percentWidth: 25,
    },
    firstname: {
      percentWidth: 12.5,
    },
    lastname: {
      percentWidth: 12.5,
    },
    effective_confidence_level: {
      percentWidth: 10,
    },
    otp: {
      percentWidth: 5,
    },
    created_at: {
      percentWidth: 10,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: usersQuery,
    linesFragment: usersFragment,
    queryRef,
    nodePath: ['users', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<UsersLinesPaginationQuery>;

  return (
    <div
      style={{
        margin: 0,
        padding: '0 200px 50px 0',
      }}
      data-testid="users-settings-page"
    >
      <AccessesMenu/>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Security') },
        { label: t_i18n('Users'), current: true }]}
      />
      {isSetAccess || isEnterpriseEdition ? (
        <>
          {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data) => data.users?.edges?.map(({ node }: { node: UsersLine_node$data }) => node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            contextFilters={contextFilters}
            lineFragment={usersLineFragment}
            preloadedPaginationProps={preloadedPaginationProps}
            createButton={userCreateButton}
            disableLineSelection={isOnlyAdminOrganization}
            icon={(user) => {
              const external = user.external === true;
              const userServiceAccount = user.user_service_account;
              if (userServiceAccount) {
                return <ManageAccountsOutlined color="primary" />;
              }
              if (external) {
                return <AccountCircleOutlined color="primary" />;
              }
              return <PersonOutlined color="primary" />;
            }}
            taskScope={'USER'}
            entityTypes={['User']}
          />
          )}
        </>
      ) : (
        <EnterpriseEdition feature="Organization sharing"/>
      )}
    </div>
  );
};

export default Users;
