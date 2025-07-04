import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { HorizontalRule, PersonOutlined, Security } from '@mui/icons-material';
import SettingsOrganizationUserCreation from '@components/settings/users/SettingsOrganizationUserCreation';
import { SettingsOrganization_organization$data } from '@components/settings/organizations/__generated__/SettingsOrganization_organization.graphql';
import { graphql } from 'react-relay';
import {
  SettingsOrganizationUsersPaginationQuery,
  SettingsOrganizationUsersPaginationQuery$variables,
} from '@components/settings/users/__generated__/SettingsOrganizationUsersPaginationQuery.graphql';
import { SettingsOrganizationUsersLine_node$data } from '@components/settings/users/__generated__/SettingsOrganizationUsersLine_node.graphql';
import { Link } from 'react-router-dom';
import { ListItemButton } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  paper: {
    margin: '28px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
}));

export const settingsOrganizationUsersQuery = graphql`
  query SettingsOrganizationUsersPaginationQuery(
    $id: String!
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SettingsOrganizationUsersLines_data
    @arguments(
      id: $id
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const settingsOrganizationUsersFragment = graphql`
  fragment SettingsOrganizationUsersLines_data on Query
  @argumentDefinitions(
    id: { type: "String!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "UsersOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SettingsOrganizationUsersLinesRefetchQuery") {
    organization(id: $id) {
      id
      name
      members(
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "Pagination_organization_members") {
        edges {
          node {
            id
            ...SettingsOrganizationUsersLine_node
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

const settingsOrganizationUsersLineFragment = graphql`
  fragment SettingsOrganizationUsersLine_node on User {
    id
    name
    user_email
    firstname
    external
    lastname
    otp_activated
    created_at
    administrated_organizations {
      id
      name
      authorized_authorities
    }
  }
`;

interface MembersListContainerProps {
  organization: SettingsOrganization_organization$data;
}

const SettingsOrganizationUsers: FunctionComponent<MembersListContainerProps> = ({ organization }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const LOCAL_STORAGE_KEY = `organization-${organization.id}-users`;

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<SettingsOrganizationUsersPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('Organization', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    id: organization.id,
  } as unknown as SettingsOrganizationUsersPaginationQuery$variables;

  const queryRef = useQueryLoading<SettingsOrganizationUsersPaginationQuery>(
    settingsOrganizationUsersQuery,
    { ...paginationOptions, id: organization.id },
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 25,
    },
    user_email: {
      percentWidth: 30,
    },
    firstname: {
      id: 'firstname',
      label: 'Firstname',
      percentWidth: 10,
      isSortable: true,
      render: (user) => user.firstname,
    },
    lastname: {
      id: 'lastname',
      label: 'Lastname',
      percentWidth: 10,
      isSortable: true,
      render: (user) => user.lastname,
    },
    effective_confidence_level: {
      id: 'effective_confidence_level',
      label: 'Max Confidence',
      percentWidth: 10,
      isSortable: false,
    },
    otp: {
      id: 'otp',
      label: '2FA',
      percentWidth: 5,
      isSortable: false,
      render: (user) => (
        <>
          {user.otp_activated ? (
            <Security fontSize="small" color="secondary" />
          ) : (
            <HorizontalRule fontSize="small" color="primary" />
          )}
        </>
      ),
    },
    created_at: {
      percentWidth: 10,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: settingsOrganizationUsersQuery,
    linesFragment: settingsOrganizationUsersFragment,
    queryRef,
    nodePath: ['organization', 'members', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SettingsOrganizationUsersPaginationQuery>;

  return (
    <Grid item xs={12} style={{ marginTop: 0 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Users')}
      </Typography>
      <SettingsOrganizationUserCreation
        paginationOptions={queryPaginationOptions}
        organization={organization}
        variant="standard"
      />
      <div style={{ float: 'right', marginTop: -12 }}>
        <SearchInput
          variant="thin"
          onSubmit={helpers.handleSearch}
          // keyword={searchTerm}
        />
      </div>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.organization?.members?.edges?.map(({ node }: { node: SettingsOrganizationUsersLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={settingsOrganizationUsersLineFragment}
          disableLineSelection
          disableNavigation
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(user) => <ListItemButton component={Link} to={`/dashboard/settings/accesses/users/${user.id}`}/>}
          icon={() => <PersonOutlined color="primary" />}
        />
        )}
      </Paper>
    </Grid>
  );
};

export default SettingsOrganizationUsers;
