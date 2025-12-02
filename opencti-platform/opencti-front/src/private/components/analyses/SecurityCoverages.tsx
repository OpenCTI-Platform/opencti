import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import type { SecurityCoveragesLinesPaginationQuery, SecurityCoveragesLinesPaginationQuery$variables } from './__generated__/SecurityCoveragesLinesPaginationQuery.graphql';
import type { SecurityCoveragesLines_data$data } from './__generated__/SecurityCoveragesLines_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import SecurityCoverageCreation from './security_coverages/SecurityCoverageCreation';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useAuth from '../../../utils/hooks/useAuth';

const LOCAL_STORAGE_KEY = 'securityCoverages';

const securityCoverageFragment = graphql`
  fragment SecurityCoveragesLine_node on SecurityCoverage {
    id
    name
    description
    entity_type
    coverage_last_result
    coverage_valid_from
    coverage_valid_to
    auto_enrichment_disable
    coverage_information {
      coverage_name
      coverage_score
    }
    objectCovered {
      ... on Report {
        id
        name
        entity_type
      }
      ... on Malware {
        id
        name
        entity_type
      }
    }
    draftVersion {
      draft_id
      draft_operation
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    creators {
      id
      name
    }
    created
    modified
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
  }
`;

const securityCoveragesLinesQuery = graphql`
  query SecurityCoveragesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: SecurityCoverageOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SecurityCoveragesLines_data
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

const securityCoveragesLinesFragment = graphql`
  fragment SecurityCoveragesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "SecurityCoverageOrdering" }
    orderMode: { type: "OrderingMode" }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "SecurityCoveragesLinesRefetchQuery") {
    securityCoverages(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination__securityCoverages") {
      edges {
        node {
          id
          ...SecurityCoveragesLine_node
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

const SecurityCoverages: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { platformModuleHelpers: { isRuntimeFieldEnable } } = useAuth();
  setTitle(t_i18n('Security coverages'));
  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<SecurityCoveragesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Security-Coverage', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as SecurityCoveragesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<SecurityCoveragesLinesPaginationQuery>(
    securityCoveragesLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: securityCoveragesLinesQuery,
    linesFragment: securityCoveragesLinesFragment,
    queryRef,
    nodePath: ['securityCoverages', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SecurityCoveragesLinesPaginationQuery>;

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 35,
      isSortable: true,
    },
    coverage_last_result: { percentWidth: 15 },
    coverage_information: { percentWidth: 15 },
    creator: {
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    objectLabel: { percentWidth: 15 },
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 8,
    },
  };

  return (
    <ExportContextProvider>
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Security coverages'), current: true }]} />
      {queryRef && (
      <div data-testid='security-coverages-page'>
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: SecurityCoveragesLines_data$data) => data.securityCoverages?.edges?.map((n) => n.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={securityCoverageFragment}
          exportContext={{ entity_type: 'Security-Coverage' }}
          redirectionModeEnabled
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <SecurityCoverageCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      </div>
      )}
    </ExportContextProvider>
  );
};

export default SecurityCoverages;
