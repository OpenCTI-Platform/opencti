import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { DataSourcesLines_data$data } from '@components/techniques/__generated__/DataSourcesLines_data.graphql';
import { DataSourcesLinesPaginationQuery, DataSourcesLinesPaginationQuery$variables } from '@components/techniques/__generated__/DataSourcesLinesPaginationQuery.graphql';
import useHelper from 'src/utils/hooks/useHelper';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DataSourceCreation from './data_sources/DataSourceCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

export const LOCAL_STORAGE_KEY_DATA_SOURCES = 'dataSources';

const dataSourceLineFragment = graphql`
  fragment DataSourcesLine_node on DataSource {
    id
    name
    entity_type
    description
    created
    modified
    x_mitre_platforms
    collection_layers
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
  }
`;

const dataSourcesLinesQuery = graphql`
  query DataSourcesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DataSourcesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DataSourcesLines_data
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

const dataSourcesLinesFragment = graphql`
  fragment DataSourcesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DataSourcesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DataSourcesLinesRefetchQuery") {
    dataSources(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_dataSources") {
      edges {
        node {
          id
          name
          description
          ...DataSourcesLine_node
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

const DataSources: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACED');

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage: { filters }, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<DataSourcesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_DATA_SOURCES,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Data-Source', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DataSourcesLinesPaginationQuery$variables;

  const dataColumns = {
    name: { percentWidth: 45 },
    objectLabel: { percentWidth: 25 },
    created: {},
    modified: {},
  };
  const queryRef = useQueryLoading<DataSourcesLinesPaginationQuery>(
    dataSourcesLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationOptions = {
    linesQuery: dataSourcesLinesQuery,
    linesFragment: dataSourcesLinesFragment,
    queryRef,
    nodePath: ['dataSources', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DataSourcesLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Data sources'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: DataSourcesLines_data$data) => data.dataSources?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY_DATA_SOURCES}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationOptions}
          lineFragment={dataSourceLineFragment}
          exportContext={{ entity_type: 'Data-Source' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <DataSourceCreation paginationOptions={paginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <DataSourceCreation paginationOptions={paginationOptions} />
        </Security>
      )}
    </>
  );
};

export default DataSources;
