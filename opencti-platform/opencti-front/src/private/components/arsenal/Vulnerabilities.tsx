import React from 'react';
import { graphql } from 'react-relay';
import { VulnerabilitiesLinesPaginationQuery, VulnerabilitiesLinesPaginationQuery$variables } from '@components/arsenal/__generated__/VulnerabilitiesLinesPaginationQuery.graphql';
import { VulnerabilitiesLines_data$data } from '@components/arsenal/__generated__/VulnerabilitiesLines_data.graphql';
import VulnerabilityCreation from './vulnerabilities/VulnerabilityCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'vulnerabilities';

const vulnerabilityLineFragment = graphql`
  fragment VulnerabilitiesLine_node on Vulnerability {
    id
    name
    x_opencti_cvss_base_severity
    created
    modified
    confidence
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
  }
`;

const vulnerabilitiesLinesQuery = graphql`
  query VulnerabilitiesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: VulnerabilitiesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...VulnerabilitiesLines_data
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

const vulnerabilitiesLinesFragment = graphql`
  fragment VulnerabilitiesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "VulnerabilitiesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "VulnerabilitiesLinesRefetchQuery") {
    vulnerabilities(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_vulnerabilities") {
      edges {
        node {
          id
          name
          description
          ...VulnerabilitiesLine_node
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

const Vulnerabilities = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<VulnerabilitiesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Vulnerability', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as VulnerabilitiesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<VulnerabilitiesLinesPaginationQuery>(
    vulnerabilitiesLinesQuery,
    queryPaginationOptions,
  );

  const dataColumns = {
    name: { percentWidth: 28 },
    x_opencti_cvss_base_severity: {},
    objectLabel: {},
    created: {},
    modified: {},
    creator: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationOptions = {
    linesQuery: vulnerabilitiesLinesQuery,
    linesFragment: vulnerabilitiesLinesFragment,
    queryRef,
    nodePath: ['vulnerabilities', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<VulnerabilitiesLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Arsenal') }, { label: t_i18n('Vulnerabilities'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: VulnerabilitiesLines_data$data) => (data?.vulnerabilities?.edges || []).map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationOptions}
          lineFragment={vulnerabilityLineFragment}
          exportContext={{ entity_type: 'Vulnerability' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
              <VulnerabilityCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <VulnerabilityCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default Vulnerabilities;
