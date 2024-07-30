import React from 'react';
import { graphql } from 'react-relay';
import { InfrastructuresLines_data$data } from '@components/observations/__generated__/InfrastructuresLines_data.graphql';
import {
  InfrastructuresLinesPaginationQuery,
  InfrastructuresLinesPaginationQuery$variables,
} from '@components/observations/__generated__/InfrastructuresLinesPaginationQuery.graphql';
import useHelper from 'src/utils/hooks/useHelper';
import useAuth from '../../../utils/hooks/useAuth';
import InfrastructureCreation from './infrastructures/InfrastructureCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

export const LOCAL_STORAGE_KEY_INFRASTRUCTURES = 'infrastructures';

const infrastructureFragment = graphql`
  fragment InfrastructuresLine_node on Infrastructure {
    id
    name
    entity_type
    created
    modified
    confidence
    infrastructure_types
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
  }
`;

const infrastructuresLinesQuery = graphql`
  query InfrastructuresLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: InfrastructuresOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...InfrastructuresLines_data
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

const infrastructuresLinesFragment = graphql`
  fragment InfrastructuresLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "InfrastructuresOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "InfrastructuresLinesRefetchQuery") {
    infrastructures(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_infrastructures") {
      edges {
        node {
          id
          ...InfrastructuresLine_node
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

const Infrastructures = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage: { filters }, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<InfrastructuresLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_INFRASTRUCTURES,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Infrastructure', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as InfrastructuresLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<InfrastructuresLinesPaginationQuery>(
    infrastructuresLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    name: { percentWidth: 35 },
    infrastructure_types: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: {},
    created: { percentWidth: 10 },
    objectMarking: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationOptions = {
    linesQuery: infrastructuresLinesQuery,
    linesFragment: infrastructuresLinesFragment,
    queryRef,
    nodePath: ['infrastructures', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<InfrastructuresLinesPaginationQuery>;

  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Observations') }, { label: t_i18n('Infrastructures'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: InfrastructuresLines_data$data) => data.infrastructures?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY_INFRASTRUCTURES}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={infrastructureFragment}
          preloadedPaginationProps={preloadedPaginationOptions}
          exportContext={{ entity_type: 'Infrastructure' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <InfrastructureCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <InfrastructureCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </ExportContextProvider>
  );
};

export default Infrastructures;
