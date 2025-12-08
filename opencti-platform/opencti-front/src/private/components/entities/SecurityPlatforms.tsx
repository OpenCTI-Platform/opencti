import React from 'react';
import { graphql } from 'react-relay';
import { SecurityPlatformsPaginationQuery, SecurityPlatformsPaginationQuery$variables } from '@components/entities/__generated__/SecurityPlatformsPaginationQuery.graphql';
import { securityPlatformFragment } from '@components/entities/securityPlatforms/SecurityPlatform';
import { SecurityPlatformsLines_data$data } from '@components/entities/__generated__/SecurityPlatformsLines_data.graphql';
import SecurityPlatformCreation from '@components/entities/securityPlatforms/SecurityPlatformCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';

const LOCAL_STORAGE_KEY = 'securityPlatform';

export const securityPlatformsQuery = graphql`
  query SecurityPlatformsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: SecurityPlatformOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SecurityPlatformsLines_data
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

export const securityPlatformsFragment = graphql`
  fragment SecurityPlatformsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "SecurityPlatformOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SecurityPlatformsLinesRefetchQuery") {
    securityPlatforms(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_securityPlatforms") {
      edges {
        node {
          id
          name
          description
          security_platform_type
          ...SecurityPlatform_securityPlatform
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

const SecurityPlatforms = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
  };
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security platform'));
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SecurityPlatformsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('SecurityPlatform', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as SecurityPlatformsPaginationQuery$variables;

  const queryRef = useQueryLoading<SecurityPlatformsPaginationQuery>(
    securityPlatformsQuery,
    queryPaginationOptions,
  );
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 20,
    },
    security_platform_type: {
      percentWidth: 20,
    },
    objectLabel: {
      percentWidth: 20,
    },
    modified: {
      percentWidth: 20,
    },
    created_at: {
      percentWidth: 20,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: securityPlatformsQuery,
    linesFragment: securityPlatformsFragment,
    queryRef,
    nodePath: ['securityPlatforms', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SecurityPlatformsPaginationQuery>;

  return (
    <div data-testid="security-platform-page">
      <Breadcrumbs elements={[{ label: t_i18n('Entities') }, { label: t_i18n('Security platforms'), current: true }]} />
      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: SecurityPlatformsLines_data$data) => data.securityPlatforms?.edges?.map((n) => n?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        contextFilters={contextFilters}
        preloadedPaginationProps={preloadedPaginationProps}
        lineFragment={securityPlatformFragment}
        exportContext={{ entity_type: 'SecurityPlatform' }}
        createButton={<SecurityPlatformCreation
          paginationOptions={queryPaginationOptions}
                      />}
      />
      )}
    </div>
  );
};

export default SecurityPlatforms;
