import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { ObservedDatasLinesPaginationQuery, ObservedDatasLinesPaginationQuery$variables } from '@components/events/__generated__/ObservedDatasLinesPaginationQuery.graphql';
import { ObservedDatasLines_data$data } from '@components/events/__generated__/ObservedDatasLines_data.graphql';
import ObservedDataCreation from './observed_data/ObservedDataCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'observedDatas';

const observedDataFragment = graphql`
  fragment ObservedDatasLine_node on ObservedData {
    id
    created
    name
    entity_type
    first_observed
    last_observed
    number_observed
    confidence
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
  }
`;

const observedDatasLinesQuery = graphql`
  query ObservedDatasLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ObservedDatasOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ObservedDatasLines_data
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

const observedDatasLinesFragment = graphql`
  fragment ObservedDatasLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ObservedDatasOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "ObservedDatasLinesRefetchQuery") {
    observedDatas(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_observedDatas") {
      edges {
        node {
          id
          created
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
          ...ObservedDatasLine_node
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

const ObservedDatas: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const initialValues = {
    searchTerm: '',
    sortBy: 'last_observed',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const {
    viewStorage,
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<ObservedDatasLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Observed-Data', filters);
  const queryPaginationOptions = {
    ...paginationOptions, filters: contextFilters,
  } as unknown as ObservedDatasLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<ObservedDatasLinesPaginationQuery>(
    observedDatasLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable();
  const dataColumns = {
    name: { percentWidth: 29 },
    number_observed: {},
    first_observed: {},
    last_observed: {},
    createdBy: { isSortable: isRuntimeSort },
    objectLabel: {},
    objectMarking: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationProps = {
    linesQuery: observedDatasLinesQuery,
    linesFragment: observedDatasLinesFragment,
    queryRef,
    nodePath: ['observedDatas', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ObservedDatasLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Events') }, { label: t_i18n('Observed datas'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ObservedDatasLines_data$data) => data.observedDatas?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={observedDataFragment}
          exportContext={{ entity_type: 'Observed-Data' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ObservedDataCreation paginationOptions={queryPaginationOptions}/>
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ObservedDataCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default ObservedDatas;
