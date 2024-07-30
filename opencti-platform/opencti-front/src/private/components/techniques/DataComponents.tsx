import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { DataComponentsLinesPaginationQuery, DataComponentsLinesPaginationQuery$variables } from '@components/techniques/__generated__/DataComponentsLinesPaginationQuery.graphql';
import { DataComponentsLines_data$data } from '@components/techniques/__generated__/DataComponentsLines_data.graphql';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import DataComponentCreation from './data_components/DataComponentCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY_DATA_COMPONENTS = 'dataComponents';

const dataComponentFragment = graphql`
  fragment DataComponentsLine_node on DataComponent {
    id
    entity_type
    name
    description
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
  }
`;

const dataComponentsLinesQuery = graphql`
  query DataComponentsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DataComponentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DataComponentsLines_data
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

const dataComponentsLinesFragment = graphql`
  fragment DataComponentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DataComponentsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DataComponentsLinesRefetchQuery") {
    dataComponents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_dataComponents") {
      edges {
        node {
          ...DataComponentsLine_node
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

const DataComponents: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACED');

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
  };
  const { viewStorage: { filters }, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<DataComponentsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_DATA_COMPONENTS,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Data-Component', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DataComponentsLinesPaginationQuery$variables;

  const dataColumns = {
    name: { percentWidth: 45 },
    objectLabel: { percentWidth: 25 },
    created: {},
    modified: {},
  };
  const queryRef = useQueryLoading<DataComponentsLinesPaginationQuery>(
    dataComponentsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationOptions = {
    linesQuery: dataComponentsLinesQuery,
    linesFragment: dataComponentsLinesFragment,
    queryRef,
    nodePath: ['dataComponents', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DataComponentsLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Data components'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          preloadedPaginationProps={preloadedPaginationOptions}
          initialValues={initialValues}
          storageKey={LOCAL_STORAGE_KEY_DATA_COMPONENTS}
          toolbarFilters={contextFilters}
          resolvePath={(data: DataComponentsLines_data$data) => data.dataComponents?.edges?.map((n) => n?.node)}
          lineFragment={dataComponentFragment}
          exportContext={{ entity_type: 'Data-Component' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <DataComponentCreation paginationOptions={paginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <DataComponentCreation paginationOptions={paginationOptions} />
        </Security>
      )}
    </>
  );
};

export default DataComponents;
