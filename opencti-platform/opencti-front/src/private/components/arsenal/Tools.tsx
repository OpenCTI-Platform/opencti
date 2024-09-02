import React from 'react';
import { graphql } from 'react-relay';
import { ToolsLines_data$data } from '@components/arsenal/__generated__/ToolsLines_data.graphql';
import { ToolsLinesPaginationQuery, ToolsLinesPaginationQuery$variables } from '@components/arsenal/__generated__/ToolsLinesPaginationQuery.graphql';
import ToolCreation from './tools/ToolCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'tools';

const toolLineFragment = graphql`
  fragment ToolsLine_node on Tool {
    id
    entity_type
    name
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

const toolsLinesQuery = graphql`
  query ToolsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ToolsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ToolsLines_data
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

const toolsLinesFragment = graphql`
  fragment ToolsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ToolsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ToolsLinesRefetchQuery") {
    tools(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_tools") {
      edges {
        node {
          id
          name
          description
          ...ToolsLine_node
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

const Tools = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<ToolsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Tool', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ToolsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<ToolsLinesPaginationQuery>(
    toolsLinesQuery,
    queryPaginationOptions,
  );

  const dataColumns = {
    name: { percentWidth: 35 },
    objectLabel: { percentWidth: 25 },
    created: { percentWidth: 20 },
    modified: { percentWidth: 20 },
  };

  const preloadedPaginationOptions = {
    linesQuery: toolsLinesQuery,
    linesFragment: toolsLinesFragment,
    queryRef,
    nodePath: ['tools', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ToolsLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Arsenal') }, { label: t_i18n('Tools'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ToolsLines_data$data) => data.tools?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationOptions}
          lineFragment={toolLineFragment}
          exportContext={{ entity_type: 'Tool' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
              <ToolCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ToolCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default Tools;
