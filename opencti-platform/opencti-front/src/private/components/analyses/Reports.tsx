import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { ReportsLinesPaginationQuery, ReportsLinesPaginationQuery$variables } from '@components/analyses/__generated__/ReportsLinesPaginationQuery.graphql';
import { ReportsLines_data$data } from '@components/analyses/__generated__/ReportsLines_data.graphql';
import ReportCreation from './reports/ReportCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

// TODO JRI Make this configurable through UI
// Its the only source of truth for query and display
// Table is now able to support result coming from stixCoreObjectsRepresentatives
// stixCoreObjectsRepresentatives $orderBy CHANGED to string instead of enum
// --> Backend is not throwing an error in this mode if attribute doesnt exist
// Be careful to use the real schema definition and NOT the filtering schema.
// - Remaining jobs
// -- /!\ Add line after creation, broken for now because of fragment change
// -- Standard chip display must be change to use the append + tooltip instead of limit 3
// -- Not sure whats going on with table sizing
// -- Looks like sort by author is not working but no idea why
const COLUMNS_DEFINITION: DataTableProps['dataColumns'] = {
  'Report name': {
    mappings: [{ entity_type: 'Report', attribute: 'name' }, { entity_type: 'Case-Incident', attribute: 'name' }],
  },
  type: {
    mappings: [{ entity_type: 'Report', attribute: 'report_types' }],
  },
  Author: {
    mappings: [{ entity_type: 'Report', attribute: 'createdBy' }],
  },
  Creators: {
    mappings: [{ entity_type: 'Report', attribute: 'creator_id' }],
  },
  Labels: {
    mappings: [{ entity_type: 'Report', attribute: 'objectLabel' }],
  },
  Published: {
    mappings: [
      { entity_type: 'Report', attribute: 'published' },
      { entity_type: 'Case-Incident', attribute: 'created' },
    ],
  },
  Status: {
    mappings: [
      { entity_type: 'Report', attribute: 'x_opencti_workflow_id' },
      { entity_type: 'Case-Incident', attribute: 'x_opencti_workflow_id' },
    ],
  },
  Markings: {
    mappings: [
      { entity_type: 'Report', attribute: 'objectMarking' },
      { entity_type: 'Case-Incident', attribute: 'objectMarking' },
    ],
  },
};

const reportLineFragment = graphql`
  fragment ReportsLine_node on StixCoreObjectRepresentative {
      id
      entity_type
      columns {
        attribute
        type
        representatives {
           id
           color
           value
        }
      }
  }
`;

const reportsLinesQuery = graphql`
  query ReportsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: String
    $orderMode: OrderingMode
    $filters: FilterGroup
    $attributes: [CoreColumnDefinition!]!
  ) {
    ...ReportsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      attributes: $attributes
    )
  }
`;
const reportsLineFragment = graphql`
  fragment ReportsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "String", defaultValue: "name" }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
    attributes: { type: "[CoreColumnDefinition!]!" }
  )
  @refetchable(queryName: "ReportsLinesRefetchQuery") {
    stixCoreObjectsRepresentatives(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      attributes:$attributes
    ) @connection(key: "Pagination_stixCoreObjectsRepresentatives") {
      edges {
        node {
          id
          entity_type
          columns {
            attribute
            representatives {
              id
              color
              value
            }
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
  const attributes = Object.entries(COLUMNS_DEFINITION)
    .map(([k, v]) => ({ column: k, definition: v.mappings })).flat();
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
    attributes,
  } as unknown as ReportsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ReportsLinesPaginationQuery>(
    reportsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: reportsLinesQuery,
    linesFragment: reportsLineFragment,
    queryRef,
    nodePath: ['stixCoreObjectsRepresentatives', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ReportsLinesPaginationQuery>;

  // const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  return (
    <span data-testid="report-page">
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Reports'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={COLUMNS_DEFINITION}
          resolvePath={(data: ReportsLines_data$data) => data.stixCoreObjectsRepresentatives?.edges?.map((n) => n?.node)}
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
