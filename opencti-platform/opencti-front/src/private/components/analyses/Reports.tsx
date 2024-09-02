import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { ReportsLinesPaginationQuery, ReportsLinesPaginationQuery$variables } from '@components/analyses/__generated__/ReportsLinesPaginationQuery.graphql';
import { ReportsLines_data$data } from '@components/analyses/__generated__/ReportsLines_data.graphql';
import ReportCreation from './reports/ReportCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const reportLineFragment = graphql`
  fragment ReportsLine_node on Report {
    id
    entity_type
    name
    description
    published
    report_types
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
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
    status {
      id
      order
      template {
        id
        name
        color
      }
    }
    workflowEnabled
    created_at
  }
`;

const reportsLinesQuery = graphql`
  query ReportsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ReportsLines_data
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

const reportsLineFragment = graphql`
  fragment ReportsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ReportsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ReportsLinesRefetchQuery") {
    reports(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_reports") {
      edges {
        node {
          id
          name
          published
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...ReportsLine_node
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

const LOCAL_STORAGE_KEY = 'reports';

const Reports: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Reports | Analyses'));
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'published',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ReportsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Report', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ReportsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ReportsLinesPaginationQuery>(
    reportsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: reportsLinesQuery,
    linesFragment: reportsLineFragment,
    queryRef,
    nodePath: ['reports', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ReportsLinesPaginationQuery>;

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      label: 'Title',
      percentWidth: 25,
      isSortable: true,
    },
    report_types: {},
    createdBy: {
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    objectLabel: { percentWidth: 15 },
    published: {},
    x_opencti_workflow_id: { percentWidth: 8 },
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 8,
    },
  };
  return (
    <span data-testid="report-page">
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Reports'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ReportsLines_data$data) => data.reports?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={reportLineFragment}
          exportContext={{ entity_type: 'Report' }}
          redirectionModeEnabled
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ReportCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ReportCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </span>
  );
};

export default Reports;
